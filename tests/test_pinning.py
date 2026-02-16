"""
Tests for pinned_keys – ML-DSA-65 server identity persistence and client pinning.
"""

import os
import sys
import shutil
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pinned_keys import (
    generate_and_save_server_identity,
    load_server_identity,
    export_pinned_pk,
    load_pinned_pk,
)
from pqcrypto.sign.ml_dsa_65 import sign, verify


class TestPinnedKeys:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.identity_dir = os.path.join(self.tmpdir, "identity")
        self.pinned_path = os.path.join(self.tmpdir, "pinned.pk")

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generate_and_load(self):
        pk1, sk1 = generate_and_save_server_identity(self.identity_dir)
        pk2, sk2 = load_server_identity(self.identity_dir)
        assert pk1 == pk2
        assert sk1 == sk2

    def test_auto_generate_on_first_load(self):
        pk, sk = load_server_identity(self.identity_dir)
        assert pk is not None and sk is not None
        # Second load returns same key
        pk2, sk2 = load_server_identity(self.identity_dir)
        assert pk == pk2

    def test_sign_verify_with_loaded_key(self):
        pk, sk = load_server_identity(self.identity_dir)
        msg = b"hello world"
        sig = sign(sk, msg)
        assert verify(pk, msg, sig)

    def test_export_and_load_pinned(self):
        generate_and_save_server_identity(self.identity_dir)
        exported_pk = export_pinned_pk(self.identity_dir, self.pinned_path)
        loaded_pk = load_pinned_pk(self.pinned_path)
        assert exported_pk == loaded_pk

    def test_load_pinned_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_pinned_pk(os.path.join(self.tmpdir, "nonexistent"))
