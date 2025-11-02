# Secure IoT Auth Protocol: Post-Quantum

A post-quantum, pseudonym-based authentication protocol for privacy-preserving IoT.

## 🚀 Overview

This project implements a secure, quantum-resistant authentication system. It leverages NIST-standardized post-quantum cryptography (ML-KEM-768, ML-DSA-65) with optional hybrid X25519 for efficiency, ensuring protection against future quantum attacks.

### Key Features
- **Quantum-Resistant Security**: Uses ML-KEM-768 + X25519 for forward secrecy.
- **Pseudonym-Based Privacy**: Derives unlinkable pseudonyms (PSi) to hide real identities (e.g., device IDs).
- **Continuous Sessions**: Supports resumable connections for real-time data streaming.
- **Replay Protection**: Timestamps, nonces, and liveness checks prevent attacks.
- **Lightweight & Scalable**: Built with asyncio and MsgPack for IoT efficiency.

## 📖 Quick Start

### Prerequisites
- Python 3.11.14
- Dependencies: `msgpack`, `cryptography`, `pqcrypto` (see `requirements.txt`)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Secure-Iot-Auth-Protocol-Post-Quantum](https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum).git
   cd Secure-Iot-Auth-Protocol-Post-Quantum
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
   python src/server.py
   ```
4. Run the client (in another terminal):
   ```bash
   python src/client.py
   ```

## 🛠️ Architecture

| Component | Description | Technology |
|-----------|-------------|------------|
| Client | IoT device or mobile app (e.g., telematics sensor) | Python asyncio, pqcrypto |
| Server | Backend for authentication and data storage | SQLite (prod: PostgreSQL) |
| Crypto | Key exchange, signatures, encryption | ML-KEM-768, ML-DSA-65, AES-GCM |
| Protocol | Async handshake + streaming | MsgPack, TCP/WebSocket |

## 🔬 Algorithms

| Algorithm     | Category      | Purpose                          | Security Notes                               |
|---------------|--------------|----------------------------------|-----------------------------------------------|
| **ML-KEM-768** | PQ KEM        | Key exchange (shared secret)     | NIST FIPS 203; Quantum-resistant              |
| **X25519**     | Classical ECDH | Hybrid KEM (optional)            | Fast; ~128-bit classical security             |
| **ML-DSA-65**  | PQ Signature   | Message signing (m₁/m₂ auth)     | NIST FIPS 204; EUF-CMA secure                 |
| **AES-GCM**    | Symmetric AEAD | Encrypt + authenticate data      | 256-bit keys; Provides integrity + confidentiality |
| **HKDF-SHA256**| KDF           | Derive K_sess + AEAD subkeys     | Domain-separated; cryptographically strong    |
| **SHA-256**    | Hash Function | Pseudonyms, proofs, chain links  | Collision-resistant; Widely standardized      |


### Protocol Flow
1. **Handshake**: Client/server exchange ephemeral keys (m1/m2), establish K_sess.
2. **Pseudonym Provisioning**: Auto-register PSi with z_i/w_i for anonymity.
3. **Streaming**: Real-time telemetry (e.g., sensor data) encrypted with K_sess.
4. **Resumption**: Handles network drops for continuous sessions.
5. **Verification**: Hash chains ensure integrity; liveness checks prevent replays.

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m 'Add your feature'`.
4. Push: `git push origin feature/your-feature`.
5. Open a pull request.


## 🙏 Acknowledgments

- [pqcrypto](https://github.com/pqclean/pqclean) for post-quantum primitives.

---

⭐ **Star this repo if you find it useful!**  
Questions or issues? Open an [issue](https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum) or reach out on [Linkedin](https://www.linkedin.com/in/solletikrishnachaitanyasubhash).
