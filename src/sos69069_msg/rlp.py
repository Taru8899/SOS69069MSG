"""Minimal RLP (encode for transactions, decode for tests)."""

from typing import Any, Union

Item = Union[bytes, int, list, tuple]


def _len_prefix(n: int, offset: int) -> bytes:
    if n < 56:
        return bytes([offset + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(nb)]) + nb


def encode(x: Item) -> bytes:
    if isinstance(x, int):
        if x < 0:
            raise ValueError("negative int")
        x = x.to_bytes((x.bit_length() + 7) // 8, "big")  # 0 -> b""
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _len_prefix(len(x), 0x80) + x
    payload = b"".join(encode(i) for i in x)
    return _len_prefix(len(payload), 0xC0) + payload


def decode(data: bytes) -> Any:
    item, rest = _decode(data)
    if rest:
        raise ValueError("trailing bytes")
    return item


def _decode(d: bytes):
    b = d[0]
    if b < 0x80:
        return d[:1], d[1:]
    if b < 0xB8:
        n = b - 0x80
        return d[1:1 + n], d[1 + n:]
    if b < 0xC0:
        ll = b - 0xB7
        n = int.from_bytes(d[1:1 + ll], "big")
        return d[1 + ll:1 + ll + n], d[1 + ll + n:]
    if b < 0xF8:
        n, start = b - 0xC0, 1
    else:
        ll = b - 0xF7
        n, start = int.from_bytes(d[1:1 + ll], "big"), 1 + ll
    body, rest = d[start:start + n], d[start + n:]
    items = []
    while body:
        it, body = _decode(body)
        items.append(it)
    return items, rest
