"""
Client – Post-Quantum Pseudonym-Based Authentication + Encrypted Streaming.

Features:
  • Hybrid ML-KEM-768 + X25519 key exchange
  • ML-DSA-65 signature verification with server key pinning
  • Session resumption via server-issued tickets
  • TLS 1.3 transport (configurable)
  • Automatic pseudonym rotation after N sessions
  • Encrypted sensor-data streaming
  • Structured JSON logging for SIEM integration
"""

import asyncio
import json
import os
import secrets
import struct
import time
from typing import Optional

import msgpack
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate, sign, verify

from config import (
    HOST, PORT, TIME_DELTA_SEC,
    PSI_LEN, NONCE_LEN, TS_LEN, ZI_LEN,
    STREAM_INTERVAL_SEC, STREAM_PACKET_COUNT,
    TLS_ENABLED, PINNED_KEY_FILE,
)
from kem_adapter import kem_encaps, kem_name
from log_setup import get_logger
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256,
    derive_pseudonym, b32, Timer, pack, unpack,
)
from secrets_config import ID_REAL, SD, A_I, Z_I, rotate_epoch

logger = get_logger("client")

# ── Persistent state (would be persisted to flash / secure storage) ──────
W_I: Optional[bytes] = None            # Set after first successful session
_session_ticket: Optional[bytes] = None  # Server-issued session ticket

# ── Pinned server key ────────────────────────────────────────────────────
_pinned_server_pk: Optional[bytes] = None


def _load_pinned_key() -> Optional[bytes]:
    """Load the pinned server public key if available."""
    if os.path.isfile(PINNED_KEY_FILE):
        with open(PINNED_KEY_FILE, "rb") as f:
            return f.read()
    return None


_pinned_server_pk = _load_pinned_key()


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


# ── Simulated sensor data ───────────────────────────────────────────────
def _generate_sensor_reading(seq: int) -> dict:
    """Produce a fake but realistic IoT telemetry payload."""
    import random
    return {
        "seq": seq,
        "ts": time.time(),
        "temperature_c": round(20.0 + random.uniform(-5, 15), 2),
        "humidity_pct": round(40.0 + random.uniform(0, 40), 1),
        "battery_v": round(3.3 + random.uniform(-0.3, 0.1), 2),
        "status": "ok",
    }


async def _send_stream(writer, reader, K_sess, PSi):
    """Send encrypted sensor data and handle session ticket."""
    logger.info("streaming_start")
    for seq in range(1, STREAM_PACKET_COUNT + 1):
        reading = _generate_sensor_reading(seq)
        plaintext = json.dumps(reading).encode()
        ad_stream = PSi
        nonce_s, ctext_s = aead_encrypt(K_sess, ad_stream, plaintext)
        await send_msg(writer, {
            "type": "stream_data",
            "ad": ad_stream,
            "nonce": nonce_s,
            "ciphertext": ctext_s,
        })
        logger.info("sensor_packet_sent", seq=seq)
        await asyncio.sleep(STREAM_INTERVAL_SEC)

    # Receive session ticket for future resumption
    global _session_ticket
    try:
        msg = await asyncio.wait_for(recv_msg(reader), timeout=5.0)
        if msg.get("type") in ("session_ticket", "new_ticket"):
            _session_ticket = msg.get("ticket")
            logger.info("session_ticket_received")
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        logger.warning("no_session_ticket_received")


# ── Main protocol ───────────────────────────────────────────────────────
async def run_client() -> None:
    global _pinned_server_pk, _session_ticket

    ssl_ctx = None
    if TLS_ENABLED:
        from tls_utils import get_client_ssl_context
        ssl_ctx = get_client_ssl_context()

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=ssl_ctx)

    # ── Hello ────────────────────────────────────────────────────────────
    hello = await recv_msg(reader)
    serv_pub = hello.get("serv_pub")
    server_sig_pk = hello.get("sig_pk")
    if not serv_pub:
        logger.error("invalid_hello")
        return
    logger.info("connected", kem=kem_name(), tls=TLS_ENABLED)

    # ── Pin server key on first contact ──────────────────────────────────
    if _pinned_server_pk is None and server_sig_pk is not None:
        _pinned_server_pk = server_sig_pk
        with open(PINNED_KEY_FILE, "wb") as f:
            f.write(server_sig_pk)
        logger.info("server_key_pinned", path=PINNED_KEY_FILE)
    elif _pinned_server_pk is not None and server_sig_pk is not None:
        if not secrets.compare_digest(_pinned_server_pk, server_sig_pk):
            logger.error("pinned_key_mismatch", msg="Server identity changed! Possible MITM attack.")
            writer.close()
            await writer.wait_closed()
            raise RuntimeError("Server key does not match pinned key — aborting")

    t = Timer()
    t.start()

    # ── Try session resumption ───────────────────────────────────────────
    if _session_ticket is not None:
        logger.info("attempting_resume")
        await send_msg(writer, {"type": "resume", "ticket": _session_ticket})
        _session_ticket = None  # one-time use
        msg = await recv_msg(reader)
        if msg.get("type") == "resume_ok":
            logger.info("session_resumed")
            PSi = derive_pseudonym(ID_REAL, SD, A_I)
            # We don't have K_sess locally — the server does the lookup.
            # Send streaming data with the LAST known K_sess.
            # NOTE: In a real implementation, K_sess would be cached locally.
            t.mark("resume-complete")
            logger.info("resume_complete", latency_ms=round(t.marks["resume-complete"], 2))
            # For demo, streaming handled by a separate flow
            rotate_epoch()
            logger.info("session_complete")
            writer.close()
            await writer.wait_closed()
            return
        else:
            logger.info("resume_rejected", reason="ticket_expired_or_invalid")
            # Fall through to full handshake

    # ── m1: Client → Server ──────────────────────────────────────────────
    sig_pk, sig_sk = sig_generate()

    PSi = derive_pseudonym(ID_REAL, SD, A_I)
    NEV = b32()
    t1  = int(time.time()).to_bytes(TS_LEN, "big")
    zi  = Z_I

    ct, ss = kem_encaps(serv_pub)

    ad = PSi
    envelope = PSi + NEV + t1 + zi
    nonce, ctext = aead_encrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad, envelope)
    m1_inner   = {"ct": ct, "ad": ad, "nonce": nonce, "ciphertext": ctext}
    m1_payload = pack(m1_inner)
    m1_sig     = sign(sig_sk, m1_payload)
    await send_msg(writer, {
        "type": "m1",
        "payload": m1_payload,
        "sig": m1_sig,
        "sig_pk": sig_pk,
    })

    # ── m2: Server → Client ──────────────────────────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") == "err":
        logger.error("server_error", reason=msg.get("reason"))
        return
    if msg.get("type") != "m2":
        logger.error("unexpected_response", msg=msg)
        return

    m2_payload = msg["payload"]
    m2_sig     = msg["sig"]
    m2_sig_pk  = msg["sig_pk"]

    # ── Certificate pinning check ────────────────────────────────────────
    if _pinned_server_pk is not None:
        if not secrets.compare_digest(m2_sig_pk, _pinned_server_pk):
            logger.error("m2_key_mismatch", msg="m2 signed with unknown key — rejecting")
            await send_msg(writer, {"type": "err", "reason": "pinned-key-mismatch"})
            return

    if not verify(m2_sig_pk, m2_payload, m2_sig):
        logger.error("invalid_m2_signature")
        await send_msg(writer, {"type": "err", "reason": "invalid-sig"})
        return

    m2 = unpack(m2_payload)
    pt2 = aead_decrypt(
        hkdf_sha256(ss, info=b"kdf-ss"),
        m2["ad"], m2["nonce"], m2["ciphertext"],
    )

    # Parse fixed-length fields
    off = 0
    T             = pt2[off : off + PSI_LEN];   off += PSI_LEN
    NS            = pt2[off : off + NONCE_LEN];  off += NONCE_LEN
    t2            = pt2[off : off + TS_LEN];     off += TS_LEN
    ziw_received  = pt2[off : off + ZI_LEN]

    # Replay check
    t2_time = int.from_bytes(t2, "big")
    if abs(t2_time - int(time.time())) > TIME_DELTA_SEC:
        logger.error("replay_detected", field="t2", skew=abs(t2_time - int(time.time())))
        await send_msg(writer, {"type": "err", "reason": "replay"})
        return

    # Mutual authentication via z_i ⊕ w_i
    if W_I is not None:
        expected_ziw = sha256(Z_I + W_I)
        if not secrets.compare_digest(ziw_received, expected_ziw):
            logger.error("ziw_mismatch")
            await send_msg(writer, {"type": "err", "reason": "invalid-ziw"})
            return
    else:
        logger.info("first_session_provisional_trust")

    K_sess = hkdf_sha256(ss + NEV + NS, info=b"kdf-sess", length=32)

    # ── m4: Client → Server (liveness challenge) ─────────────────────────
    N_edge = b32()
    t4     = int(time.time()).to_bytes(TS_LEN, "big")
    pt4    = PSi + N_edge + t4
    nonce4, ctext4 = aead_encrypt(K_sess, m2["ad"], pt4)
    await send_msg(writer, {
        "type": "m4",
        "ad": m2["ad"],
        "nonce": nonce4,
        "ciphertext": ctext4,
    })

    # ── m5: Server → Client (liveness response) ─────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") != "m5":
        logger.error("missing_m5")
        return
    back = aead_decrypt(K_sess, m2["ad"], msg["nonce"], msg["ciphertext"])
    expected = (int.from_bytes(N_edge, "big") + 1) % (1 << (8 * len(N_edge)))
    ok = int.from_bytes(back, "big") == expected
    logger.info("liveness_ack", ok=ok)

    # ── Hash-chain verification ──────────────────────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") != "hash_head":
        logger.error("missing_hash_head")
        return
    head, n, pre = msg["head"], msg["n"], msg["pre"]

    t.mark("handshake-complete")
    logger.info("handshake_complete", latency_ms=round(t.marks["handshake-complete"], 2))

    await send_msg(writer, {"type": "hash_use", "pre": pre})
    msg = await recv_msg(reader)
    logger.info("hash_chain_verified", result=msg)

    # ── Encrypted Data Streaming ─────────────────────────────────────────
    await _send_stream(writer, reader, K_sess, PSi)

    # ── Pseudonym rotation ───────────────────────────────────────────────
    new_a_i = rotate_epoch()
    logger.info("epoch_check", a_i=new_a_i.hex()[:16])

    logger.info("session_complete")
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(run_client())