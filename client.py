import asyncio, time, struct
import msgpack
import logging
import secrets

from kem_adapter import kem_encaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256,
    derive_pseudonym, b32, Timer, pack, unpack
)
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate, sign, verify

HOST = "127.0.0.1"
PORT = 8765
W_I = None
TIME_DELTA_SEC = 5


logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

async def send_msg(writer, obj: dict):
    data = msgpack.packb(obj, use_bin_type=True)
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()

async def recv_msg(reader):
    hdr = await reader.readexactly(4)
    (length,) = struct.unpack("!I", hdr)
    data = await reader.readexactly(length)
    return msgpack.unpackb(data, raw=False)

ID_REAL = b"demo-user-id-1234567890".ljust(32, b'\x00')
SD = b'\x01' * 32
A_I = b'\x02' * 32
Z_I = b'\x03' * 32

async def run_client():
    reader, writer = await asyncio.open_connection(HOST, PORT)

    hello = await recv_msg(reader)
    serv_pub = hello.get("serv_pub")
    if not serv_pub:
        logging.error("[client] Invalid hello")
        return
    logging.info(f"[client] using KEM: {kem_name()}")

    t = Timer(); t.start()

    # Generating ephemeral signing key for m1
    sig_pk, sig_sk = sig_generate()

    # --- m1 ---
    PSi = derive_pseudonym(ID_REAL, SD, A_I)
    NEV = b32()
    t1 = int(time.time()).to_bytes(8, "big")
    zi = Z_I

    ct, ss = kem_encaps(serv_pub)

    ad = PSi
    env = PSi + NEV + t1 + zi
    nonce, ctext = aead_encrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad, env)
    m1_inner = {"ct": ct, "ad": ad, "nonce": nonce, "ciphertext": ctext}
    m1_payload = pack(m1_inner)
    m1_sig = sign(sig_sk, m1_payload)
    await send_msg(writer, {"type":"m1", "payload": m1_payload, "sig": m1_sig, "sig_pk": sig_pk})

    # --- m2 ---
    msg = await recv_msg(reader)
    if msg.get("type") == "err":
        logging.error(f"[client] Server error: {msg.get('reason')}")
        return
    if msg.get("type") != "m2":
        logging.error(f"[client] bad response: {msg}")
        return
    m2_payload = msg["payload"]
    m2_sig = msg["sig"]
    m2_sig_pk = msg["sig_pk"]
    if not verify(m2_sig_pk, m2_payload, m2_sig):
        logging.error("[client] Invalid m2 signature")
        await send_msg(writer, {"type":"err","reason":"invalid-sig"})
        return
    m2_unpacked = unpack(m2_payload)
    ad2 = m2_unpacked["ad"]; nonce2 = m2_unpacked["nonce"]; ctext2 = m2_unpacked["ciphertext"]
    pt2 = aead_decrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad2, nonce2, ctext2)
    T = pt2[0:32]; NS = pt2[32:64]; t2 = pt2[64:72]; ziw_received = pt2[72:104]

    t2_time = int.from_bytes(t2, "big")
    current_time = int(time.time())
    if abs(t2_time - current_time) > TIME_DELTA_SEC:
        logging.error("[client] Replay detected: t2 timestamp skew too large")
        await send_msg(writer, {"type":"err","reason":"replay"})
        return

    if W_I:
        expected_ziw = sha256(Z_I + W_I)
        if not secrets.compare_digest(ziw_received, expected_ziw):
            logging.error("[client] Invalid zi_plus_wi: Authentication failed")
            await send_msg(writer, {"type":"err","reason":"invalid-ziw"})
            return
    else:
        logging.info("[client] First session: Provisional trust")

    K_sess = hkdf_sha256(ss + NEV + NS, info=b"kdf-sess", length=32)

    # --- m4 ---
    N_edge = b32()
    t4 = int(time.time()).to_bytes(8, "big")
    pt4 = PSi + N_edge + t4
    nonce4, ctext4 = aead_encrypt(K_sess, ad2, pt4)
    await send_msg(writer, {"type":"m4","ad":ad2,"nonce":nonce4,"ciphertext":ctext4})

    # --- m5 ---
    msg = await recv_msg(reader)
    if msg.get("type") != "m5":
        logging.error("[client] missing m5")
        return
    n5 = msg["nonce"]; c5 = msg["ciphertext"]
    back = aead_decrypt(K_sess, ad2, n5, c5)
    ok = (int.from_bytes(back, "big") == (int.from_bytes(N_edge, "big")+1) % (1 << (8*len(N_edge))))
    logging.info(f"[client] liveness ack: {ok}")

    # --- hash head + preimage ---
    msg = await recv_msg(reader)
    if msg.get("type") != "hash_head":
        logging.error("[client] missing hash head")
        return
    head = msg["head"]; n = msg["n"]; pre = msg["pre"]

    t.mark("first-hop-complete")
    logging.info(f"[client] first-hop ~{t.marks['first-hop-complete']:.2f} ms")

    await send_msg(writer, {"type": "hash_use", "pre": pre})

    msg = await recv_msg(reader)
    logging.info(f"[client] hash-chain check from server: {msg}")

    writer.close(); await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(run_client())