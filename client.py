import asyncio, os, time, json
import logging
import secrets
from pathlib import Path

from kem_adapter import kem_encaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256,
    derive_pseudonym, b32, Timer, pack, unpack,
    send_msg, recv_msg
)
from identity import IdentityManager

HOST = "127.0.0.1"
PORT = 8765
TIME_DELTA_SEC = 5
CONN_TIMEOUT = 30          # seconds — max wait per message recv
CLIENT_DATA_DIR = Path("./client_data")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# ──────────────── Persistent device secrets ────────────────

def load_or_create_device_secrets() -> dict:
    """Generate device identity secrets on first run, persist for reuse."""
    CLIENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    secrets_path = CLIENT_DATA_DIR / "device_secrets.json"

    if secrets_path.exists():
        with open(secrets_path) as f:
            data = json.load(f)
        logging.info("[client] Loaded existing device secrets")
        return {k: bytes.fromhex(v) for k, v in data.items()}

    device = {
        "id_real": os.urandom(32).hex(),
        "sd":      os.urandom(32).hex(),
        "a_i":     os.urandom(32).hex(),
        "z_i":     os.urandom(32).hex(),
    }
    with open(secrets_path, "w") as f:
        json.dump(device, f, indent=2)
    # Restrict permissions on secrets file (owner read/write only)
    os.chmod(secrets_path, 0o600)
    logging.info("[client] Generated and persisted new device secrets")
    return {k: bytes.fromhex(v) for k, v in device.items()}


# ──────────────── W_I persistence ────────────────

def load_wi() -> bytes | None:
    """Load previously provisioned w_i from disk."""
    path = CLIENT_DATA_DIR / "w_i.bin"
    if path.exists():
        return path.read_bytes()
    return None


def save_wi(w_i: bytes):
    """Persist w_i received from server for future session authentication."""
    CLIENT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = CLIENT_DATA_DIR / "w_i.bin"
    path.write_bytes(w_i)
    os.chmod(path, 0o600)   # owner-only access
    logging.info("[client] Saved w_i for future sessions")


async def _recv(reader: asyncio.StreamReader) -> dict:
    """recv_msg wrapped with a connection timeout."""
    return await asyncio.wait_for(recv_msg(reader), timeout=CONN_TIMEOUT)


# ──────────────── Main protocol ────────────────

async def run_client():
    device   = load_or_create_device_secrets()
    identity = IdentityManager("client", CLIENT_DATA_DIR / "identity")
    W_I      = load_wi()

    reader, writer = await asyncio.open_connection(HOST, PORT)

    try:
        # Receive server hello (KEM public key)
        hello = await _recv(reader)
        serv_pub = hello.get("serv_pub")
        if not serv_pub:
            logging.error("[client] Invalid hello")
            return
        logging.info(f"[client] using KEM: {kem_name()}")

        t = Timer(); t.start()

        # ─────────────────────── m1 (send) ───────────────────────
        PSi = derive_pseudonym(device["id_real"], device["sd"], device["a_i"])
        NEV = b32()
        t1  = int(time.time()).to_bytes(8, "big")
        zi  = device["z_i"]

        ct, ss = kem_encaps(serv_pub)

        ad  = PSi
        env = PSi + NEV + t1 + zi
        nonce, ctext = aead_encrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad, env)

        m1_inner   = {"ct": ct, "ad": ad, "nonce": nonce, "ciphertext": ctext}
        m1_payload = pack(m1_inner)
        m1_sig     = identity.sign_message(m1_payload)   # ← long-term key

        await send_msg(writer, {
            "type":    "m1",
            "payload": m1_payload,
            "sig":     m1_sig,
            "sig_pk":  identity.pk                       # ← long-term public key
        })

        # ─────────────────────── m2 (receive) ───────────────────────
        msg = await _recv(reader)
        if msg.get("type") == "err":
            logging.error(f"[client] Server error: {msg.get('reason')}")
            return
        if msg.get("type") != "m2":
            logging.error(f"[client] bad response: {msg}")
            return

        m2_payload = msg["payload"]
        m2_sig     = msg["sig"]
        m2_sig_pk  = msg["sig_pk"]

        # Verify server signature
        if not IdentityManager.verify_signature(m2_sig_pk, m2_payload, m2_sig):
            logging.error("[client] Invalid m2 signature")
            await send_msg(writer, {"type": "err", "reason": "invalid-sig"})
            return

        # TOFU: verify or pin server identity
        server_id = f"{HOST}_{PORT}"
        is_trusted, is_new = identity.verify_peer_identity(server_id, m2_sig_pk)
        if not is_trusted:
            logging.error(
                "[client] Server identity key mismatch — possible MITM attack!"
            )
            await send_msg(writer, {"type": "err", "reason": "identity-mismatch"})
            return
        if is_new:
            logging.info("[client] First connection: pinned server identity (TOFU)")
        else:
            logging.info("[client] Server identity verified against pinned key")

        # Decrypt m2 payload
        m2_unpacked = unpack(m2_payload)
        ad2    = m2_unpacked["ad"]
        nonce2 = m2_unpacked["nonce"]
        ctext2 = m2_unpacked["ciphertext"]
        pt2 = aead_decrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad2, nonce2, ctext2)
        T  = pt2[0:32]; NS = pt2[32:64]; t2 = pt2[64:72]; ziw_received = pt2[72:104]

        # Replay detection via timestamp
        t2_time = int.from_bytes(t2, "big")
        current_time = int(time.time())
        if abs(t2_time - current_time) > TIME_DELTA_SEC:
            logging.error("[client] Replay detected: t2 timestamp skew too large")
            await send_msg(writer, {"type": "err", "reason": "replay"})
            return

        # Verify zi⊕wi (mutual auth — only if W_I known from previous session)
        if W_I is not None:
            expected_ziw = sha256(zi + W_I)
            if not secrets.compare_digest(ziw_received, expected_ziw):
                logging.error("[client] Invalid zi⊕wi — server authentication failed")
                await send_msg(writer, {"type": "err", "reason": "invalid-ziw"})
                return
            logging.info("[client] Server zi⊕wi verified successfully")
        else:
            logging.info("[client] First session: zi⊕wi verification deferred")

        # ─── Transcript-bound directional session keys ───
        #
        # Binds K_sess to the full handshake transcript (serv_pub ‖ m1 ‖ m2)
        # and derives separate client→server / server→client keys to prevent
        # reflection attacks and unknown-key-share attacks.
        transcript_hash = sha256(
            bytes(serv_pub) + bytes(m1_payload) + bytes(m2_payload)
        )

        K_c2s = hkdf_sha256(
            ss + NEV + NS + transcript_hash, info=b"kdf-sess-c2s", length=32
        )
        K_s2c = hkdf_sha256(
            ss + NEV + NS + transcript_hash, info=b"kdf-sess-s2c", length=32
        )

        # ─────────────────────── m4 (send) ───────────────────────
        N_edge = b32()
        t4  = int(time.time()).to_bytes(8, "big")
        pt4 = PSi + N_edge + t4
        nonce4, ctext4 = aead_encrypt(K_c2s, ad2, pt4)    # ← client→server key
        await send_msg(writer, {
            "type": "m4", "ad": ad2, "nonce": nonce4, "ciphertext": ctext4
        })

        # ─────────────────────── m5 (receive — liveness) ─────────
        msg = await _recv(reader)
        if msg.get("type") != "m5":
            logging.error("[client] missing m5")
            return

        n5 = msg["nonce"]; c5 = msg["ciphertext"]
        back = aead_decrypt(K_s2c, ad2, n5, c5)           # ← server→client key
        expected_np1 = (
            (int.from_bytes(N_edge, "big") + 1) % (1 << (8 * len(N_edge)))
        )
        ok = int.from_bytes(back, "big") == expected_np1
        logging.info(f"[client] liveness ack: {ok}")
        if not ok:
            logging.error("[client] Liveness check failed")
            return

        # ─────────────── w_i provisioning / rotation ──────────────
        msg = await _recv(reader)
        if msg.get("type") != "provision":
            logging.error("[client] Expected provision message")
            return

        n_prov = msg["nonce"]; c_prov = msg["ciphertext"]
        w_i_received = aead_decrypt(K_s2c, PSi, n_prov, c_prov)
        save_wi(w_i_received)

        if W_I is None:
            logging.info("[client] Received initial w_i from server")
        else:
            logging.info("[client] Received rotated w_i from server")

        # ───────── Hash chain (client-generated, commits head) ────
        seed  = b32()
        n     = 20
        chain = [seed]
        for _ in range(n):
            chain.append(sha256(chain[-1]))
        head = chain[n]       # commitment: h_n
        pre  = chain[n - 1]   # pre-image:  h_{n-1}

        # Send commitment
        await send_msg(writer, {"type": "hash_commit", "head": head, "n": n})

        # Wait for server challenge
        msg = await _recv(reader)
        if msg.get("type") != "hash_challenge":
            logging.error("[client] Expected hash_challenge")
            return

        # Reveal pre-image
        await send_msg(writer, {"type": "hash_reveal", "pre": pre})

        # Receive verification result
        msg = await _recv(reader)
        if msg.get("type") == "hash_ok":
            logging.info(f"[client] Hash-chain verification: {msg.get('ok')}")

        t.mark("first-hop-complete")
        logging.info(f"[client] first-hop ~{t.marks['first-hop-complete']:.2f} ms")

    except asyncio.TimeoutError:
        logging.warning("[client] Connection timeout")
    except (ConnectionResetError, asyncio.IncompleteReadError):
        logging.warning("[client] Connection lost")
    finally:
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(run_client())