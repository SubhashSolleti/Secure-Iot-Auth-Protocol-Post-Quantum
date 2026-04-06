import asyncio, time
import sqlite3
import logging
import secrets
from pathlib import Path
from collections import defaultdict

from kem_adapter import kem_generate_keypair, kem_decaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256, b32, Timer,
    pack, unpack, send_msg, recv_msg, derive_stable_pseudonym
)
from identity import IdentityManager

HOST = "127.0.0.1"
PORT = 8765
TIME_DELTA_SEC = 5
CONN_TIMEOUT = 30          # seconds — max wait per message recv
RATE_LIMIT_MAX = 20        # max connections per IP within window
RATE_LIMIT_WINDOW = 60     # seconds
DB_FILE = "server_pseudonyms.db"
SERVER_DATA_DIR = Path("./server_data")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# ── Long-term server identity (persistent ML-DSA-65 key) ──
identity = IdentityManager("server", SERVER_DATA_DIR / "identity")

# ── SQLite with asyncio lock for coroutine safety ──
db_lock = asyncio.Lock()
conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Schema: psi_stable is the persistent FK; psi_session varies per session
cursor.execute("""
CREATE TABLE IF NOT EXISTS pseudonyms (
    psi_stable BLOB PRIMARY KEY,
    z_i        BLOB,
    w_i        BLOB,
    sig_pk     BLOB
)
""")
conn.commit()

# Migration: rename psi → psi_stable for existing databases
try:
    cursor.execute("SELECT psi_stable FROM pseudonyms LIMIT 1")
except sqlite3.OperationalError:
    # Old schema had 'psi' column — rebuild table
    try:
        cursor.execute("ALTER TABLE pseudonyms RENAME COLUMN psi TO psi_stable")
        conn.commit()
        logging.info("[server] Migrated DB: renamed psi → psi_stable")
    except sqlite3.OperationalError:
        pass  # Column already correct or table empty

# Migration: add sig_pk column to existing databases (legacy compat)
try:
    cursor.execute("SELECT sig_pk FROM pseudonyms LIMIT 1")
except sqlite3.OperationalError:
    try:
        cursor.execute("ALTER TABLE pseudonyms ADD COLUMN sig_pk BLOB")
        conn.commit()
        logging.info("[server] Migrated DB: added sig_pk column")
    except sqlite3.OperationalError:
        pass


# ── Rate limiter ──
_conn_log: dict[str, list[float]] = defaultdict(list)


def _rate_limit_ok(ip: str) -> bool:
    """Sliding-window rate limiter per IP address."""
    now = time.time()
    timestamps = _conn_log[ip]
    _conn_log[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_conn_log[ip]) >= RATE_LIMIT_MAX:
        return False
    _conn_log[ip].append(now)
    return True


async def _recv(reader: asyncio.StreamReader) -> dict:
    """recv_msg wrapped with a connection timeout."""
    return await asyncio.wait_for(recv_msg(reader), timeout=CONN_TIMEOUT)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    ip = addr[0] if addr else "unknown"

    # ── Rate limit check ──
    if not _rate_limit_ok(ip):
        logging.warning(f"[server] Rate limit exceeded for {ip} — dropping")
        writer.close()
        await writer.wait_closed()
        return

    logging.info(f"[server] connection from {addr}  (KEM={kem_name()})")

    serv_pub, serv_priv = kem_generate_keypair()

    await send_msg(writer, {"type": "hello", "serv_pub": serv_pub})

    t = Timer(); t.start()

    try:
        # ─────────────────────── m1 (receive) ───────────────────────
        msg = await _recv(reader)
        if msg.get("type") != "m1":
            logging.error("[server] Invalid m1")
            await send_msg(writer, {"type": "err", "reason": "invalid-msg"})
            return

        m1_payload = msg["payload"]
        m1_sig     = msg["sig"]
        m1_sig_pk  = msg["sig_pk"]

        # Signature verification (proves possession of signing key)
        if not IdentityManager.verify_signature(m1_sig_pk, m1_payload, m1_sig):
            logging.error("[server] Invalid m1 signature")
            await send_msg(writer, {"type": "err", "reason": "invalid-sig"})
            return

        # Decrypt m1 payload
        m1_unpacked = unpack(m1_payload)
        ct    = m1_unpacked["ct"]
        ad    = m1_unpacked["ad"]
        nonce = m1_unpacked["nonce"]
        ctext = m1_unpacked["ciphertext"]

        ss = kem_decaps(serv_priv, ct)
        pt = aead_decrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad=ad, nonce=nonce, ciphertext=ctext)
        # Tiered Pseudonym Architecture:
        #   PSi (session) = pt[0:32]   — unique per-session (unlinkable)
        #   PSi_stable    = pt[104:136] — fixed per-device (for screening / DB lookup)
        PSi = pt[0:32]; NEV = pt[32:64]; t1 = pt[64:72]; zi = pt[72:104]
        PSi_stable = pt[104:136] if len(pt) >= 136 else PSi  # backward compat

        logging.info(f"[server] PSi_session: {PSi.hex()[:12]}... (per-session)")
        logging.info(f"[server] PSi_stable:  {PSi_stable.hex()[:12]}... (for screening)")

        # Replay detection via timestamp
        t1_time = int.from_bytes(t1, "big")
        current_time = int(time.time())
        if abs(t1_time - current_time) > TIME_DELTA_SEC:
            logging.error("[server] Replay detected: t1 timestamp skew too large")
            await send_msg(writer, {"type": "err", "reason": "replay"})
            return

        # ─── TOFU identity binding + pseudonym lookup (under lock) ───
        # DB lookup uses PSi_stable (persistent) not PSi_session (ephemeral)
        is_new_client = False
        async with db_lock:
            cursor.execute(
                "SELECT z_i, w_i, sig_pk FROM pseudonyms WHERE psi_stable = ?", (PSi_stable,)
            )
            row = cursor.fetchone()

            if row is None:
                # First encounter: auto-provision with TOFU
                w_i = b32()
                cursor.execute(
                    "INSERT INTO pseudonyms (psi_stable, z_i, w_i, sig_pk) VALUES (?, ?, ?, ?)",
                    (PSi_stable, zi, w_i, bytes(m1_sig_pk))
                )
                conn.commit()
                is_new_client = True
                z_i = zi
                logging.info("[server] Auto-provisioned PSi_stable with TOFU identity binding")
            else:
                z_i, w_i = row["z_i"], row["w_i"]
                stored_sig_pk = row["sig_pk"]

                # TOFU identity check: reject if key changed
                if stored_sig_pk and not secrets.compare_digest(
                    bytes(m1_sig_pk), bytes(stored_sig_pk)
                ):
                    logging.error(
                        "[server] Client identity key mismatch — possible impersonation"
                    )
                    await send_msg(writer, {"type": "err", "reason": "identity-mismatch"})
                    return
                logging.info("[server] Client identity verified (TOFU)")

                # Verify z_i secret
                if not secrets.compare_digest(bytes(zi), bytes(z_i)):
                    logging.error("[server] Invalid zi")
                    await send_msg(writer, {"type": "err", "reason": "invalid-zi"})
                    return

        # ─────────────────────── m2 (send) ───────────────────────
        T  = b32()
        NS = b32()
        t2 = int(time.time()).to_bytes(8, "big")
        zi_plus_wi = sha256(bytes(z_i) + bytes(w_i))
        env = T + NS + t2 + zi_plus_wi
        ad2 = PSi
        nonce2, ctext2 = aead_encrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad2, env)

        m2_inner   = {"ad": ad2, "nonce": nonce2, "ciphertext": ctext2}
        m2_payload = pack(m2_inner)
        m2_sig     = identity.sign_message(m2_payload)   # ← long-term key

        await send_msg(writer, {
            "type":   "m2",
            "payload": m2_payload,
            "sig":     m2_sig,
            "sig_pk":  identity.pk                       # ← long-term public key
        })

        # ─── Transcript-bound directional session keys ───
        #
        # Binds K_sess to the full handshake transcript (serv_pub ‖ m1 ‖ m2)
        # and derives separate client→server / server→client keys to prevent
        # reflection attacks and unknown-key-share attacks.
        transcript_hash = sha256(bytes(serv_pub) + bytes(m1_payload) + bytes(m2_payload))

        K_c2s = hkdf_sha256(
            ss + NEV + NS + transcript_hash, info=b"kdf-sess-c2s", length=32
        )
        K_s2c = hkdf_sha256(
            ss + NEV + NS + transcript_hash, info=b"kdf-sess-s2c", length=32
        )

        # ─────────────────────── m4 (receive) ───────────────────────
        msg = await _recv(reader)
        if msg.get("type") == "err":
            logging.error(f"[server] Client error: {msg.get('reason')}")
            return
        if msg.get("type") != "m4":
            logging.error("[server] Invalid m4")
            return

        ad4 = msg["ad"]; nonce4 = msg["nonce"]; ctext4 = msg["ciphertext"]
        pt4 = aead_decrypt(K_c2s, ad4, nonce4, ctext4)    # ← client→server key
        N_edge = pt4[32:64]

        # ─────────────────────── m5 (send — liveness) ───────────────
        Np1   = (int.from_bytes(N_edge, "big") + 1) % (1 << (8 * len(N_edge)))
        Np1_b = Np1.to_bytes(len(N_edge), "big")
        nonce5, ctext5 = aead_encrypt(K_s2c, ad4, Np1_b)  # ← server→client key
        await send_msg(writer, {
            "type": "m5", "ad": ad4, "nonce": nonce5, "ciphertext": ctext5
        })

        # ─────────────── w_i provisioning / rotation ─────────────
        #
        # New clients:      receive freshly generated w_i
        # Returning clients: receive rotated w_i = SHA256(old_w_i ‖ T)
        #                    for forward secrecy of the auth chain
        if is_new_client:
            prov_wi = w_i
        else:
            prov_wi = sha256(bytes(w_i) + T)
            async with db_lock:
                cursor.execute(
                    "UPDATE pseudonyms SET w_i = ? WHERE psi_stable = ?", (prov_wi, PSi_stable)
                )
                conn.commit()
            logging.info("[server] Rotated w_i for returning client")

        nonce_prov, ctext_prov = aead_encrypt(K_s2c, PSi, prov_wi)
        await send_msg(writer, {
            "type": "provision", "nonce": nonce_prov, "ciphertext": ctext_prov
        })

        # ───────── Hash chain (client-generated, server verifies) ────
        msg = await _recv(reader)
        if msg.get("type") != "hash_commit":
            logging.error("[server] Expected hash_commit")
            return

        head = msg["head"]
        n    = msg["n"]
        logging.info(f"[server] Received hash-chain commitment (n={n})")

        # Challenge client to reveal pre-image
        await send_msg(writer, {"type": "hash_challenge"})

        msg = await _recv(reader)
        if msg.get("type") != "hash_reveal":
            logging.error("[server] Expected hash_reveal")
            return

        pre_recv = msg["pre"]
        ok = secrets.compare_digest(sha256(pre_recv), head)
        await send_msg(writer, {"type": "hash_ok", "ok": ok})
        logging.info(f"[server] Hash-chain verification: {ok}")

        t.mark("first-hop-complete")
        logging.info(f"[server] first-hop ~{t.marks['first-hop-complete']:.2f} ms")

    except asyncio.TimeoutError:
        logging.warning(f"[server] Connection timeout for {addr}")
    except (ConnectionResetError, asyncio.IncompleteReadError):
        logging.warning(f"[server] Connection lost: {addr}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logging.info(f"[server] listening on {server.sockets[0].getsockname()}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())