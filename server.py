import asyncio, time, struct
from typing import Dict, Tuple
import msgpack
import sqlite3
import logging
import secrets

from kem_adapter import kem_generate_keypair, kem_decaps, kem_name
from pq_commons import (
    aead_encrypt, aead_decrypt, hkdf_sha256, sha256, b32, Timer, pack, unpack  # Added pack, unpack
)
from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate, sign, verify

HOST = "127.0.0.1"
PORT = 8765
TIME_DELTA_SEC = 5
DB_FILE = "server_pseudonyms.db"

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS pseudonyms (
    psi BLOB PRIMARY KEY,
    z_i BLOB,
    w_i BLOB
)
""")
conn.commit()

async def send_msg(writer, obj: dict):
    data = msgpack.packb(obj, use_bin_type=True)
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()

async def recv_msg(reader):
    hdr = await reader.readexactly(4)
    (length,) = struct.unpack("!I", hdr)
    data = await reader.readexactly(length)
    return msgpack.unpackb(data, raw=False)

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    logging.info(f"[server] connection from {addr}  (KEM={kem_name()})")

    serv_pub, serv_priv = kem_generate_keypair()

    await send_msg(writer, {"type": "hello", "serv_pub": serv_pub})

    t = Timer(); t.start()

    # --- m1 ---
    msg = await recv_msg(reader)
    if msg.get("type") != "m1":
        logging.error("[server] Invalid m1")
        await send_msg(writer, {"type":"err","reason":"invalid-msg"})
        writer.close(); await writer.wait_closed(); return
    m1_payload = msg["payload"]
    m1_sig = msg["sig"]
    m1_sig_pk = msg["sig_pk"]
    if not verify(m1_sig_pk, m1_payload, m1_sig):
        logging.error("[server] Invalid m1 signature")
        await send_msg(writer, {"type":"err","reason":"invalid-sig"})
        writer.close(); await writer.wait_closed(); return
    m1_unpacked = unpack(m1_payload)
    ct = m1_unpacked["ct"]; ad = m1_unpacked["ad"]; nonce = m1_unpacked["nonce"]; ctext = m1_unpacked["ciphertext"]

    ss = kem_decaps(serv_priv, ct)
    pt = aead_decrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad=ad, nonce=nonce, ciphertext=ctext)
    PSi = pt[0:32]; NEV = pt[32:64]; t1 = pt[64:72]; zi = pt[72:104]

    t1_time = int.from_bytes(t1, "big")
    current_time = int(time.time())
    if abs(t1_time - current_time) > TIME_DELTA_SEC:
        logging.error("[server] Replay detected: t1 timestamp skew too large")
        await send_msg(writer, {"type":"err","reason":"replay"})
        writer.close(); await writer.wait_closed(); return

    cursor.execute("SELECT z_i, w_i FROM pseudonyms WHERE psi = ?", (PSi,))
    row = cursor.fetchone()
    if row is None:
        w_i = b32()
        cursor.execute("INSERT INTO pseudonyms (psi, z_i, w_i) VALUES (?, ?, ?)", (PSi, zi, w_i))
        conn.commit()
        logging.info("[server] auto-provisioned PSi with client's zi")
        z_i, w_i = zi, w_i
    else:
        z_i, w_i = row['z_i'], row['w_i']
        if not secrets.compare_digest(zi, z_i):
            logging.error("[server] Invalid zi")
            await send_msg(writer, {"type":"err","reason":"invalid-zi"})
            writer.close(); await writer.wait_closed(); return

    # Generate ephemeral signing key for m2
    sig_pk, sig_sk = sig_generate()

    # --- m2 ---
    T  = b32()
    NS = b32()
    t2 = int(time.time()).to_bytes(8, "big")
    zi_plus_wi = sha256(z_i + w_i)
    env = T + NS + t2 + zi_plus_wi
    ad2 = PSi
    nonce2, ctext2 = aead_encrypt(hkdf_sha256(ss, info=b"kdf-ss"), ad2, env)
    m2_inner = {"ad":ad2,"nonce":nonce2,"ciphertext":ctext2}
    m2_payload = pack(m2_inner)
    m2_sig = sign(sig_sk, m2_payload)
    await send_msg(writer, {"type":"m2", "payload": m2_payload, "sig": m2_sig, "sig_pk": sig_pk})

    K_sess = hkdf_sha256(ss + NEV + NS, info=b"kdf-sess", length=32)

    # --- m4 ---
    msg = await recv_msg(reader)
    if msg.get("type") == "err":
        logging.error(f"[server] Client error: {msg.get('reason')}")
        writer.close(); await writer.wait_closed(); return
    if msg.get("type") != "m4":
        logging.error("[server] Invalid m4")
        writer.close(); await writer.wait_closed(); return
    ad4 = msg["ad"]; nonce4 = msg["nonce"]; ctext4 = msg["ciphertext"]
    pt4 = aead_decrypt(K_sess, ad4, nonce4, ctext4)
    N_edge = pt4[32:64]

    # --- m5 ---
    Np1 = (int.from_bytes(N_edge, "big") + 1) % (1 << (8*len(N_edge)))
    Np1_b = Np1.to_bytes(len(N_edge), "big")
    nonce5, ctext5 = aead_encrypt(K_sess, ad4, Np1_b)
    await send_msg(writer, {"type":"m5","ad":ad4,"nonce":nonce5,"ciphertext":ctext5})

    # --- Hash-chain ---
    M_client = b32()
    n = 20
    seed = sha256(T) + sha256(M_client)
    head = seed
    for _ in range(n):
        head = sha256(head)
    pre = seed
    for _ in range(n - 1):
        pre = sha256(pre)

    await send_msg(writer, {"type":"hash_head","head": head, "n": n, "pre": pre})

    t.mark("first-hop-complete")
    logging.info(f"[server] first-hop ~{t.marks['first-hop-complete']:.2f} ms")

    msg = await recv_msg(reader)
    if msg.get("type") == "hash_use":
        pre_recv = msg["pre"]
        ok = secrets.compare_digest(sha256(pre_recv), head)
        await send_msg(writer, {"type":"hash_ok","ok": ok})
        logging.info(f"[server] hash-chain check: {ok}")

    writer.close(); await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logging.info(f"[server] listening on {server.sockets[0].getsockname()}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())