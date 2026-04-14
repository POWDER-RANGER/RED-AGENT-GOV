"""Wire-format serialization for task output.

The ``transform`` function encodes a result payload into bytes for emission.
When a *transform_key* is supplied the payload is HMAC-signed and the
resulting envelope carries both the ciphertext and the MAC tag.
Without a key the payload is plain JSON-encoded bytes.
"""

from __future__ import annotations

import json
from typing import Any

from .crypto import hmac_sha256


def transform(
    payload: Any,
    transform_key: bytes | None = None,
) -> bytes:
    """Serialize *payload* to wire bytes.

    Args:
        payload: JSON-serializable value.
        transform_key: Optional 32-byte key. When present the output is an
            envelope ``{"data": <hex>, "mac": <hex>}``.

    Returns:
        UTF-8-encoded bytes ready for emission.
    """
    raw = json.dumps(payload, default=str, sort_keys=True).encode()
    if transform_key is None:
        return raw
    mac = hmac_sha256(transform_key, raw)
    envelope = json.dumps({"data": raw.hex(), "mac": mac})
    return envelope.encode()
