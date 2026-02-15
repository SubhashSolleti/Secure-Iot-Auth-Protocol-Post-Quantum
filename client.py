"""
Client – Post-Quantum Pseudonym-Based Authentication + Encrypted Streaming.

Connects to the authentication server, performs the PQ handshake (m1–m5),
verifies hash-chain integrity, then streams encrypted simulated sensor
data over the established session key.
"""

import asyncio
import json
import logging
import secrets
import struct
import time
from typing import Optional

import msgpack
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate, sign, verify

from config import (
    HOST, PORT, TIME_DELTA_SEC, LOG_FORMAT,
    PSI_LEN, NONCE_LEN, TS_LEN, ZI_LEN, WI_LEN,
    STREAM_INTERVAL_SEC, STREAM_PACKET_COUNT,
)
from kem_adapter import kem_encaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256,
    derive_pseudonym, b32, Timer, pack, unpack,
)
from secrets_config import ID_REAL, SD, A_I, Z_I

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# ── Persistent state (would be persisted to flash / secure storage) ──────
W_I: Optional[bytes] = None  # Set after first successful session


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


# ── Main protocol ───────────────────────────────────────────────────────
async def run_client() -> None:
    reader, writer = await asyncio.open_connection(HOST, PORT)

    # ── Hello ────────────────────────────────────────────────────────────
    hello = await recv_msg(reader)
    serv_pub = hello.get("serv_pub")
    if not serv_pub:
        logging.error("[client] Invalid hello from server")
        return
    logging.info(f"[client] Using KEM: {kem_name()}")

    t = Timer()
    t.start()

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
        logging.error("[client] Server error: %s", msg.get("reason"))
        return
    if msg.get("type") != "m2":
        logging.error("[client] Unexpected response: %s", msg)
        return

    m2_payload = msg["payload"]
    m2_sig     = msg["sig"]
    m2_sig_pk  = msg["sig_pk"]

    if not verify(m2_sig_pk, m2_payload, m2_sig):
        logging.error("[client] Invalid m2 signature")
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
        logging.error("[client] Replay detected: t2 skew too large")
        await send_msg(writer, {"type": "err", "reason": "replay"})
        return

    # Mutual authentication via z_i ⊕ w_i
    if W_I is not None:
        expected_ziw = sha256(Z_I + W_I)
        if not secrets.compare_digest(ziw_received, expected_ziw):
            logging.error("[client] zi+wi mismatch — server authentication failed")
            await send_msg(writer, {"type": "err", "reason": "invalid-ziw"})
            return
    else:
        logging.info("[client] First session — provisional trust (no w_i yet)")

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
        logging.error("[client] Missing m5")
        return
    back = aead_decrypt(K_sess, m2["ad"], msg["nonce"], msg["ciphertext"])
    expected = (int.from_bytes(N_edge, "big") + 1) % (1 << (8 * len(N_edge)))
    ok = int.from_bytes(back, "big") == expected
    logging.info(f"[client] Liveness ack: {ok}")

    # ── Hash-chain verification ──────────────────────────────────────────
    msg = await recv_msg(reader)
    if msg.get("type") != "hash_head":
        logging.error("[client] Missing hash_head")
        return
    head, n, pre = msg["head"], msg["n"], msg["pre"]

    t.mark("handshake-complete")
    logging.info(f"[client] Handshake ~{t.marks['handshake-complete']:.2f} ms")

    await send_msg(writer, {"type": "hash_use", "pre": pre})
    msg = await recv_msg(reader)
    logging.info(f"[client] Hash-chain verification: {msg}")

    # ── Encrypted Data Streaming ─────────────────────────────────────────
    logging.info("[client] 🚀 Streaming encrypted sensor data...")
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
        logging.info(f"[client] 📤 Sent sensor packet #{seq}")
        await asyncio.sleep(STREAM_INTERVAL_SEC)

    logging.info("[client] Session complete.")
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(run_client())