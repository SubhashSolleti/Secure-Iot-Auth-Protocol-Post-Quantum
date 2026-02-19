"""
Tests for tls_utils – TLS 1.3 certificate generation and context creation.
"""

import os
import sys
import shutil
import ssl
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tls_utils import ensure_certs, get_server_ssl_context, get_client_ssl_context


class TestTLSUtils:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_ensure_certs_creates_files(self):
        ensure_certs(self.tmpdir)
        assert os.path.isfile(os.path.join(self.tmpdir, "ca.pem"))
        assert os.path.isfile(os.path.join(self.tmpdir, "ca.key"))
        assert os.path.isfile(os.path.join(self.tmpdir, "server.pem"))
        assert os.path.isfile(os.path.join(self.tmpdir, "server.key"))

    def test_ensure_certs_idempotent(self):
        ensure_certs(self.tmpdir)
        mtime1 = os.path.getmtime(os.path.join(self.tmpdir, "ca.pem"))
        ensure_certs(self.tmpdir)  # should not regenerate
        mtime2 = os.path.getmtime(os.path.join(self.tmpdir, "ca.pem"))
        assert mtime1 == mtime2

    def test_server_ssl_context(self):
        ctx = get_server_ssl_context(self.tmpdir)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_client_ssl_context(self):
        ctx = get_client_ssl_context(self.tmpdir)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
