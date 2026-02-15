"""
Server – Post-Quantum Pseudonym-Based Authentication + Encrypted Streaming.

Listens for IoT client connections, performs the PQ handshake (m1–m5),
verifies hash-chain integrity, then receives encrypted sensor data
over the established session key.
"""

import asyncio
import json
import logging
import secrets
import sqlite3
import struct
import time
from typing import Dict, Tuple

import msgpack
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate, sign, verify

from config import (
    HOST, PORT, TIME_DELTA_SEC, DB_FILE, HASH_CHAIN_LENGTH,
    LOG_FORMAT, PSI_LEN, NONCE_LEN, TS_LEN, ZI_LEN,
    STREAM_PACKET_COUNT,
)
from kem_adapter import kem_generate_keypair, kem_decaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256, b32,
    Timer, pack, unpack,
)

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# ── Database ─────────────────────────────────────────────────────────────
conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS pseudonyms (
        psi  BLOB PRIMARY KEY,
        z_i  BLOB NOT NULL,
        w_i  BLOB NOT NULL
    )
""")
conn.commit()


# ── Helpers ──────────────────────────────────────────────────────────────
async def send_msg(writer: asyncio.StreamWriter, obj: dict) -> None:
    """Length-prefix and send a MsgPack-encoded message."""
    data = msgpack.packb(obj, use_bin_type=True)
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict:
    """Read a length-prefixed MsgPack message."""
    hdr = await reader.readexactly(4)
    (length,) = struct.unpack("!I", hdr)
    data = await reader.readexactly(length)
    return msgpack.unpackb(data, raw=False)


def _close(writer: asyncio.StreamWriter):
    """Schedule a graceful close."""
    writer.close()


# ── Client handler ───────────────────────────────────────────────────────
async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    addr = writer.get_extra_info("peername")
    logging.info(f"[server] connection from {addr}  (KEM={kem_name()})")

    serv_pub, serv_priv = kem_generate_keypair()
    await send_msg(writer, {"type": "hello", "serv_pub": serv_pub})

    t = Timer()
    t.start()

    # ── m1: Client → Server ──────────────────────────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") != "m1":
        logging.error("[server] Expected m1, got %s", msg.get("type"))
        await send_msg(writer, {"type": "err", "reason": "invalid-msg"})
        _close(writer)
        await writer.wait_closed()
        return

    m1_payload = msg["payload"]
    m1_sig     = msg["sig"]
    m1_sig_pk  = msg["sig_pk"]

    if not verify(m1_sig_pk, m1_payload, m1_sig):
        logging.error("[server] Invalid m1 signature")
        await send_msg(writer, {"type": "err", "reason": "invalid-sig"})
        _close(writer)
        await writer.wait_closed()
        return

    m1 = unpack(m1_payload)
    ct, ad, nonce, ctext = m1["ct"], m1["ad"], m1["nonce"], m1["ciphertext"]

    ss = kem_decaps(serv_priv, ct)
    kdf_key = hkdf_sha256(ss, info=b"kdf-ss")
    pt = aead_decrypt(kdf_key, ad=ad, nonce=nonce, ciphertext=ctext)

    # Parse fixed-length fields from plaintext
    off = 0
    PSi  = pt[off : off + PSI_LEN];   off += PSI_LEN
    NEV  = pt[off : off + NONCE_LEN]; off += NONCE_LEN
    t1   = pt[off : off + TS_LEN];    off += TS_LEN
    zi   = pt[off : off + ZI_LEN]

    # Replay check
    t1_time = int.from_bytes(t1, "big")
    if abs(t1_time - int(time.time())) > TIME_DELTA_SEC:
        logging.error("[server] Replay detected: t1 skew too large")
        await send_msg(writer, {"type": "err", "reason": "replay"})
        _close(writer)
        await writer.wait_closed()
        return

    # Pseudonym lookup / auto-provision
    cursor.execute("SELECT z_i, w_i FROM pseudonyms WHERE psi = ?", (PSi,))
    row = cursor.fetchone()
    if row is None:
        w_i = b32()
        cursor.execute(
            "INSERT INTO pseudonyms (psi, z_i, w_i) VALUES (?, ?, ?)",
            (PSi, zi, w_i),
        )
        conn.commit()
        logging.info("[server] Auto-provisioned new pseudonym")
        z_i = zi
    else:
        z_i, w_i = row["z_i"], row["w_i"]
        if not secrets.compare_digest(zi, z_i):
            logging.error("[server] Invalid z_i — authentication failed")
            await send_msg(writer, {"type": "err", "reason": "invalid-zi"})
            _close(writer)
            await writer.wait_closed()
            return

    # ── m2: Server → Client ──────────────────────────────────────────────
    sig_pk, sig_sk = sig_generate()

    T  = b32()
    NS = b32()
    t2 = int(time.time()).to_bytes(TS_LEN, "big")
    zi_plus_wi = sha256(z_i + w_i)
    envelope = T + NS + t2 + zi_plus_wi

    ad2 = PSi
    nonce2, ctext2 = aead_encrypt(kdf_key, ad2, envelope)
    m2_inner  = {"ad": ad2, "nonce": nonce2, "ciphertext": ctext2}
    m2_payload = pack(m2_inner)
    m2_sig = sign(sig_sk, m2_payload)
    await send_msg(writer, {
        "type": "m2",
        "payload": m2_payload,
        "sig": m2_sig,
        "sig_pk": sig_pk,
    })

    K_sess = hkdf_sha256(ss + NEV + NS, info=b"kdf-sess", length=32)

    # ── m4: Client → Server (liveness challenge) ─────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") == "err":
        logging.error("[server] Client error: %s", msg.get("reason"))
        _close(writer)
        await writer.wait_closed()
        return
    if msg.get("type") != "m4":
        logging.error("[server] Expected m4, got %s", msg.get("type"))
        _close(writer)
        await writer.wait_closed()
        return

    pt4 = aead_decrypt(K_sess, msg["ad"], msg["nonce"], msg["ciphertext"])
    N_edge = pt4[PSI_LEN : PSI_LEN + NONCE_LEN]

    # ── m5: Server → Client (liveness response) ─────────────────────────
    Np1 = (int.from_bytes(N_edge, "big") + 1) % (1 << (8 * len(N_edge)))
    Np1_b = Np1.to_bytes(len(N_edge), "big")
    nonce5, ctext5 = aead_encrypt(K_sess, msg["ad"], Np1_b)
    await send_msg(writer, {
        "type": "m5",
        "ad": msg["ad"],
        "nonce": nonce5,
        "ciphertext": ctext5,
    })

    # ── Hash-chain verification ──────────────────────────────────────────
    n = HASH_CHAIN_LENGTH
    M_client = b32()
    seed = sha256(T) + sha256(M_client)
    head = seed
    for _ in range(n):
        head = sha256(head)
    pre = seed
    for _ in range(n - 1):
        pre = sha256(pre)

    await send_msg(writer, {"type": "hash_head", "head": head, "n": n, "pre": pre})

    msg = await recv_msg(reader)
    if msg.get("type") == "hash_use":
        ok = secrets.compare_digest(sha256(msg["pre"]), head)
        await send_msg(writer, {"type": "hash_ok", "ok": ok})
        logging.info(f"[server] hash-chain check: {ok}")

    t.mark("handshake-complete")
    logging.info(f"[server] handshake ~{t.marks['handshake-complete']:.2f} ms")

    # ── Encrypted Data Streaming ─────────────────────────────────────────
    logging.info("[server] Waiting for encrypted sensor data...")
    for i in range(STREAM_PACKET_COUNT):
        try:
            msg = await asyncio.wait_for(recv_msg(reader), timeout=10.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            logging.warning("[server] Stream ended (timeout or disconnect)")
            break

        if msg.get("type") != "stream_data":
            logging.warning("[server] Unexpected message type: %s", msg.get("type"))
            break

        plaintext = aead_decrypt(
            K_sess, msg["ad"], msg["nonce"], msg["ciphertext"],
        )
        payload = json.loads(plaintext.decode())
        logging.info(
            "[server] 📡 Sensor packet #%d: %s",
            payload.get("seq", i),
            payload,
        )

    logging.info("[server] Session complete.")
    _close(writer)
    await writer.wait_closed()


# ── Entry point ──────────────────────────────────────────────────────────
async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logging.info(f"[server] listening on {server.sockets[0].getsockname()}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())