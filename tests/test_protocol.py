"""
Integration test – full handshake + streaming round-trip.

Spins up the server in-process, connects a client, completes the
entire m1→m5 handshake + hash-chain + streaming, and asserts that
the session completes without errors.
"""

import asyncio
import os
import sys
import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Override config to use a temp DB and minimal streaming for speed
import config
config.DB_FILE = ":memory:"
config.STREAM_PACKET_COUNT = 2
config.STREAM_INTERVAL_SEC = 0.05

from server import handle_client  # noqa: E402  (after config patch)
from client import run_client     # noqa: E402


@pytest.mark.asyncio
async def test_full_handshake_and_streaming():
    """
    End-to-end: start server, run client, assert clean completion.

    Both sides share the same event loop so we can await them together.
    """
    # Use a random port to avoid conflicts
    port = 0
    server = await asyncio.start_server(
        handle_client, "127.0.0.1", port,
    )
    actual_port = server.sockets[0].getsockname()[1]

    # Patch the client to connect to the ephemeral port
    import client as client_mod
    original_port = client_mod.PORT
    client_mod.PORT = actual_port

    try:
        # Run the client against the live server
        await asyncio.wait_for(run_client(), timeout=30.0)
    finally:
        client_mod.PORT = original_port
        server.close()
        await server.wait_closed()
