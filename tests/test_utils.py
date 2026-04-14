"""Tests for red_agent utility modules: crypto, entropy, serialization."""

from __future__ import annotations

import hashlib
import json

import pytest

from red_agent.utils.crypto import (
    _zero_via_ctypes,
    compute_hmac,
    hmac_sha256,
    secure_zero,
    sha256,
    verify_hmac,
)
from red_agent.utils.entropy import EntropyInsufficientError, generate_seed
from red_agent.utils.serialization import transform


# ---------------------------------------------------------------------------
# crypto.py
# ---------------------------------------------------------------------------


class TestSha256:
    def test_returns_hex_string(self):
        result = sha256(b"hello")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_correct_hash(self):
        expected = hashlib.sha256(b"hello").hexdigest()
        assert sha256(b"hello") == expected

    def test_empty_bytes(self):
        result = sha256(b"")
        assert len(result) == 64

    def test_deterministic(self):
        assert sha256(b"abc") == sha256(b"abc")

    def test_different_inputs_differ(self):
        assert sha256(b"a") != sha256(b"b")


class TestHmacSha256:
    def test_returns_hex_string(self):
        result = hmac_sha256(b"key", b"msg")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_deterministic(self):
        assert hmac_sha256(b"k", b"m") == hmac_sha256(b"k", b"m")

    def test_different_keys_differ(self):
        assert hmac_sha256(b"key1", b"msg") != hmac_sha256(b"key2", b"msg")

    def test_different_msgs_differ(self):
        assert hmac_sha256(b"key", b"msg1") != hmac_sha256(b"key", b"msg2")


class TestComputeHmac:
    def test_returns_bytes(self):
        result = compute_hmac(b"key", b"msg")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_matches_hmac_sha256_hex(self):
        raw = compute_hmac(b"key", b"msg")
        hex_result = hmac_sha256(b"key", b"msg")
        assert raw.hex() == hex_result


class TestVerifyHmac:
    def test_correct_tag_returns_true(self):
        key = b"secret-key-32bytes-padddddddddddd"
        msg = b"payload"
        tag = compute_hmac(key, msg)
        assert verify_hmac(key, msg, tag) is True

    def test_wrong_tag_returns_false(self):
        key = b"secret-key-32bytes-padddddddddddd"
        msg = b"payload"
        assert verify_hmac(key, msg, b"\x00" * 32) is False

    def test_wrong_key_returns_false(self):
        key1 = b"key1" * 8
        key2 = b"key2" * 8
        msg = b"payload"
        tag = compute_hmac(key1, msg)
        assert verify_hmac(key2, msg, tag) is False


class TestSecureZero:
    def test_zeros_buffer(self):
        buf = bytearray(b"secret_data_here")
        result = secure_zero(buf)
        assert result is True
        assert all(b == 0 for b in buf)

    def test_empty_buffer(self):
        buf = bytearray(b"")
        result = secure_zero(buf)
        assert result is True

    def test_zero_via_ctypes_returns_true(self):
        buf = bytearray(b"data")
        assert _zero_via_ctypes(buf) is True
        assert all(b == 0 for b in buf)

    def test_zero_via_ctypes_empty_buffer(self):
        buf = bytearray()
        assert _zero_via_ctypes(buf) is True


# ---------------------------------------------------------------------------
# entropy.py
# ---------------------------------------------------------------------------


class TestGenerateSeed:
    def test_returns_32_bytes(self):
        seed = generate_seed()
        assert isinstance(seed, bytes)
        assert len(seed) == 32

    def test_seeds_are_unique(self):
        seed1 = generate_seed()
        seed2 = generate_seed()
        assert seed1 != seed2

    def test_with_task_queue_depth(self):
        seed = generate_seed(task_queue_depth=5)
        assert len(seed) == 32

    def test_with_zero_task_queue_depth(self):
        seed = generate_seed(task_queue_depth=0)
        assert len(seed) == 32

    def test_entropy_insufficient_error_is_runtime_error(self):
        assert issubclass(EntropyInsufficientError, RuntimeError)


# ---------------------------------------------------------------------------
# serialization.py
# ---------------------------------------------------------------------------


class TestTransform:
    def test_without_key_returns_json_bytes(self):
        payload = {"key": "value", "num": 42}
        result = transform(payload)
        assert isinstance(result, bytes)
        parsed = json.loads(result)
        assert parsed["key"] == "value"
        assert parsed["num"] == 42

    def test_without_key_is_sorted_json(self):
        payload = {"b": 2, "a": 1}
        result = transform(payload)
        # sort_keys=True means 'a' comes before 'b'
        text = result.decode()
        assert text.index('"a"') < text.index('"b"')

    def test_with_key_returns_envelope(self):
        key = b"test-key-32bytes-paddddddddddddd"
        payload = {"data": "test"}
        result = transform(payload, transform_key=key)
        assert isinstance(result, bytes)
        envelope = json.loads(result)
        assert "data" in envelope
        assert "mac" in envelope

    def test_with_key_envelope_has_hex_data(self):
        key = b"test-key-32bytes-paddddddddddddd"
        payload = {"val": 1}
        result = transform(payload, transform_key=key)
        envelope = json.loads(result)
        # data field is hex-encoded
        decoded = bytes.fromhex(envelope["data"])
        original = json.loads(decoded)
        assert original["val"] == 1

    def test_with_key_mac_verifies(self):
        key = b"test-key-32bytes-paddddddddddddd"
        payload = {"secure": True}
        result = transform(payload, transform_key=key)
        envelope = json.loads(result)
        raw = bytes.fromhex(envelope["data"])
        expected_mac = hmac_sha256(key, raw)
        assert envelope["mac"] == expected_mac

    def test_none_key_returns_plain_json(self):
        result = transform({"x": 1}, transform_key=None)
        assert json.loads(result) == {"x": 1}

    def test_non_serializable_uses_str_fallback(self):
        import datetime
        payload = {"ts": datetime.date(2024, 1, 1)}
        result = transform(payload)
        assert isinstance(result, bytes)
        assert b"2024" in result
