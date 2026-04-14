"""
Serialization Boundary Protocol (Section 3.2).
- Randomize field ordering within each object.
- Stochastic padding on string fields (stripped by receiver).
- Variation driven by session entropy seed — not deterministic.
"""
from __future__ import annotations
import json, random, secrets
from typing import Any


_PAD_CHAR = "\x00"    # stripped by receiver on deserialise


def _make_rng(seed: bytes) -> random.Random:
    rng = random.Random()
    rng.seed(seed)
    return rng


def _pad_string(value: str, rng: random.Random, max_pad: int = 32) -> str:
    n = rng.randint(0, max_pad)
    return value + (_PAD_CHAR * n)


def _shuffle_dict(d: dict, rng: random.Random) -> dict:
    keys = list(d.keys())
    rng.shuffle(keys)
    return {k: d[k] for k in keys}


def transform(payload: dict, seed: bytes) -> bytes:
    """
    Apply serialization boundary transformation driven by *seed*.
    Returns wire-format bytes.
    """
    rng = _make_rng(seed)

    def _transform_value(v: Any) -> Any:
        if isinstance(v, str):
            return _pad_string(v, rng)
        if isinstance(v, dict):
            return _shuffle_dict({k: _transform_value(vv) for k, vv in v.items()}, rng)
        if isinstance(v, list):
            return [_transform_value(i) for i in v]
        return v

    transformed = _transform_value(payload)
    if isinstance(transformed, dict):
        transformed = _shuffle_dict(transformed, rng)

    return json.dumps(transformed, separators=(",", ":")).encode()


def detransform(data: bytes) -> dict:
    """
    Strip padding and return canonical dict (field order is restored by receiver).
    """
    raw = json.loads(data.decode())

    def _strip(v: Any) -> Any:
        if isinstance(v, str):
            return v.rstrip(_PAD_CHAR)
        if isinstance(v, dict):
            return {k: _strip(vv) for k, vv in v.items()}
        if isinstance(v, list):
            return [_strip(i) for i in v]
        return v

    return _strip(raw)
