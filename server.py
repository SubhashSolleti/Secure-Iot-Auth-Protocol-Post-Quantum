"""
Server – Post-Quantum Pseudonym-Based Authentication + Encrypted Streaming.

Features:
  • Hybrid ML-KEM-768 + X25519 key exchange
  • ML-DSA-65 signatures with persistent (pinned) server identity
  • Session resumption via encrypted session tickets
  • Per-IP token-bucket rate limiting
  • TLS 1.3 transport (configurable)
  • Hash-chain verification + encrypted sensor-data streaming
  • Structured JSON logging for SIEM integration
"""

import asyncio
import json
import secrets
import sqlite3
import struct
import time
from typing import Dict, Tuple

import msgpack
from pqcrypto.sign.ml_dsa_65 import sign, verify

from config import (
    HOST, PORT, TIME_DELTA_SEC, DB_FILE, HASH_CHAIN_LENGTH,
    PSI_LEN, NONCE_LEN, TS_LEN, ZI_LEN,
    STREAM_PACKET_COUNT, TLS_ENABLED,
)
from kem_adapter import kem_generate_keypair, kem_decaps, kem_name
from log_setup import get_logger
from pinned_keys import load_server_identity
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256, b32,
    Timer, pack, unpack,
)
from rate_limiter import RateLimiter
from session_store import SessionStore

logger = get_logger("server")

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

# ── Singletons ───────────────────────────────────────────────────────────
rate_limiter = RateLimiter()
session_store = SessionStore()

# ── Load persistent server signing identity ──────────────────────────────
_server_sig_pk, _server_sig_sk = load_server_identity()
logger.info("server_identity_loaded", kem=kem_name())


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


# ── Resumed session handler ──────────────────────────────────────────────
async def _handle_resumed_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    psi: bytes,
    k_sess: bytes,
) -> None:
    """Handle a resumed session — skip handshake, go straight to streaming."""
    logger.info("session_resumed", psi=psi.hex()[:16])

    # Receive streaming data
    for i in range(STREAM_PACKET_COUNT):
        try:
            msg = await asyncio.wait_for(recv_msg(reader), timeout=10.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            logger.warning("stream_ended", reason="timeout_or_disconnect")
            break

        if msg.get("type") != "stream_data":
            logger.warning("unexpected_msg", msg_type=msg.get("type"))
            break

        plaintext = aead_decrypt(
            k_sess, msg["ad"], msg["nonce"], msg["ciphertext"],
        )
        payload = json.loads(plaintext.decode())
        logger.info("sensor_data_received", seq=payload.get("seq", i), data=payload)

    # Issue a fresh ticket for next resumption
    new_ticket = session_store.issue(psi, k_sess)
    await send_msg(writer, {"type": "new_ticket", "ticket": new_ticket})

    logger.info("resumed_session_complete")
    _close(writer)
    await writer.wait_closed()


# ── Client handler ───────────────────────────────────────────────────────
async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    addr = writer.get_extra_info("peername")
    ip = addr[0] if addr else "unknown"

    # ── Rate limiting ────────────────────────────────────────────────────
    if not rate_limiter.allow(ip):
        logger.warning("rate_limited", ip=ip)
        await send_msg(writer, {"type": "err", "reason": "rate-limited"})
        _close(writer)
        await writer.wait_closed()
        return

    logger.info("connection_accepted", peer=addr, kem=kem_name())

    serv_pub, serv_priv = kem_generate_keypair()
    await send_msg(writer, {
        "type": "hello",
        "serv_pub": serv_pub,
        "sig_pk": _server_sig_pk,
    })

    t = Timer()
    t.start()

    # ── Check for session resumption ─────────────────────────────────────
    msg = await recv_msg(reader)

    if msg.get("type") == "resume":
        ticket_id = msg.get("ticket")
        result = session_store.resume(ticket_id) if ticket_id else None
        if result is not None:
            psi, k_sess = result
            await send_msg(writer, {"type": "resume_ok"})
            await _handle_resumed_session(reader, writer, psi, k_sess)
            return
        else:
            logger.info("resume_rejected", reason="invalid_or_expired_ticket")
            await send_msg(writer, {"type": "resume_fail"})
            msg = await recv_msg(reader)  # client will retry with m1

    # ── m1: Client → Server ──────────────────────────────────────────────
    if msg.get("type") != "m1":
        logger.error("invalid_message", expected="m1", got=msg.get("type"))
        await send_msg(writer, {"type": "err", "reason": "invalid-msg"})
        _close(writer)
        await writer.wait_closed()
        return

    m1_payload = msg["payload"]
    m1_sig     = msg["sig"]
    m1_sig_pk  = msg["sig_pk"]

    if not verify(m1_sig_pk, m1_payload, m1_sig):
        logger.error("invalid_m1_signature")
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
        logger.error("replay_detected", field="t1", skew=abs(t1_time - int(time.time())))
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
        logger.info("pseudonym_provisioned", psi=PSi.hex()[:16])
        z_i = zi
    else:
        z_i, w_i = row["z_i"], row["w_i"]
        if not secrets.compare_digest(zi, z_i):
            logger.error("invalid_zi", psi=PSi.hex()[:16])
            await send_msg(writer, {"type": "err", "reason": "invalid-zi"})
            _close(writer)
            await writer.wait_closed()
            return

    # ── m2: Server → Client (signed with persistent identity) ────────────
    T  = b32()
    NS = b32()
    t2 = int(time.time()).to_bytes(TS_LEN, "big")
    zi_plus_wi = sha256(z_i + w_i)
    envelope = T + NS + t2 + zi_plus_wi

    ad2 = PSi
    nonce2, ctext2 = aead_encrypt(kdf_key, ad2, envelope)
    m2_inner  = {"ad": ad2, "nonce": nonce2, "ciphertext": ctext2}
    m2_payload = pack(m2_inner)
    m2_sig = sign(_server_sig_sk, m2_payload)
    await send_msg(writer, {
        "type": "m2",
        "payload": m2_payload,
        "sig": m2_sig,
        "sig_pk": _server_sig_pk,
    })

    K_sess = hkdf_sha256(ss + NEV + NS, info=b"kdf-sess", length=32)

    # ── m4: Client → Server (liveness challenge) ─────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") == "err":
        logger.error("client_error", reason=msg.get("reason"))
        _close(writer)
        await writer.wait_closed()
        return
    if msg.get("type") != "m4":
        logger.error("invalid_message", expected="m4", got=msg.get("type"))
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
        logger.info("hash_chain_verified", ok=ok)

    t.mark("handshake-complete")
    logger.info("handshake_complete", latency_ms=round(t.marks["handshake-complete"], 2))

    # ── Encrypted Data Streaming ─────────────────────────────────────────
    logger.info("waiting_for_sensor_data")
    for i in range(STREAM_PACKET_COUNT):
        try:
            msg = await asyncio.wait_for(recv_msg(reader), timeout=10.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            logger.warning("stream_ended", reason="timeout_or_disconnect")
            break

        if msg.get("type") != "stream_data":
            logger.warning("unexpected_msg", msg_type=msg.get("type"))
            break

        plaintext = aead_decrypt(
            K_sess, msg["ad"], msg["nonce"], msg["ciphertext"],
        )
        payload = json.loads(plaintext.decode())
        logger.info("sensor_data_received", seq=payload.get("seq", i), data=payload)

    # ── Issue session ticket for future resumption ───────────────────────
    ticket_id = session_store.issue(PSi, K_sess)
    await send_msg(writer, {"type": "session_ticket", "ticket": ticket_id})
    logger.info("session_ticket_issued", psi=PSi.hex()[:16])

    logger.info("session_complete")
    _close(writer)
    await writer.wait_closed()


# ── Entry point ──────────────────────────────────────────────────────────
async def main():
    ssl_ctx = None
    if TLS_ENABLED:
        from tls_utils import get_server_ssl_context
        ssl_ctx = get_server_ssl_context()
        logger.info("tls_enabled", version="TLS 1.3")

    server = await asyncio.start_server(handle_client, HOST, PORT, ssl=ssl_ctx)
    logger.info("server_listening", address=server.sockets[0].getsockname())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())