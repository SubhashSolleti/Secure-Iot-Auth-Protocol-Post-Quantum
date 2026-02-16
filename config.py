"""
Shared configuration for the Secure IoT Auth Protocol.
All tuneable protocol constants live here.
"""

# ── Network ────────────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8765

# ── Protocol timing ───────────────────────────────────────────────────────
TIME_DELTA_SEC = 5          # Maximum acceptable clock skew (seconds)
HASH_CHAIN_LENGTH = 20      # Number of links in the verification hash chain

# ── Storage ───────────────────────────────────────────────────────────────
DB_FILE = "server_pseudonyms.db"

# ── KEM fallback policy ──────────────────────────────────────────────────
# "strict"  → abort if hybrid ML-KEM+X25519 is unavailable
# "relaxed" → silently fall back to pure ML-KEM-768
KEM_FALLBACK_POLICY = "strict"

# ── Byte-field sizes (avoids magic numbers in protocol code) ─────────────
PSI_LEN   = 32   # pseudonym length
NONCE_LEN = 32   # nonce / random bytes length
TS_LEN    = 8    # timestamp (int64)
ZI_LEN    = 32   # z_i commitment length
WI_LEN    = 32   # w_i witness length

# ── Streaming ────────────────────────────────────────────────────────────
STREAM_INTERVAL_SEC = 1.0    # seconds between simulated sensor packets
STREAM_PACKET_COUNT = 5      # number of sensor packets to send in demo

# ── Session Resumption ───────────────────────────────────────────────────
SESSION_TICKET_TTL_SEC = 300  # session ticket validity (5 minutes)

# ── Rate Limiting (token-bucket) ─────────────────────────────────────────
RATE_LIMIT_PER_SEC = 10       # token refill rate per second
RATE_LIMIT_BURST   = 20       # maximum burst size

# ── TLS Transport ────────────────────────────────────────────────────────
TLS_ENABLED = True            # wrap TCP in TLS 1.3
CERTS_DIR   = "certs"         # directory for cert/key files

# ── Pseudonym Rotation ───────────────────────────────────────────────────
PSEUDONYM_ROTATE_EVERY = 5    # rotate A_I every N sessions

# ── Logging ──────────────────────────────────────────────────────────────
LOG_MODE   = "json"           # "json" for SIEM, "text" for human-readable
LOG_FORMAT = "[%(levelname)s] %(message)s"  # fallback format if structlog unavailable

# ── Certificate Pinning ──────────────────────────────────────────────────
SERVER_IDENTITY_DIR = "server_identity"   # persistent ML-DSA signing key
PINNED_KEY_FILE     = "pinned_server.pk"  # client-side pinned public key
