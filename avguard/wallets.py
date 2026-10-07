"""Whether a piece of text is one cryptocurrency address, and of which family.

Pure and tkinter-free, for the paste guard's swap check (docs/next-6.md item
6): a clipper replaces an address the user copied with one of its own, of
the same family, so the check needs to know that both texts are addresses
and that they are of one family. A checksum is verified wherever the format
has one, so a mistyped or truncated string is not an address:

- Bitcoin, Litecoin, Dogecoin and Tron legacy addresses: Base58Check (a
  version byte, a 20-byte hash, four bytes of double SHA-256).
- Bitcoin and Litecoin segwit addresses: bech32 (BIP-173) for witness
  version 0, bech32m (BIP-350) for versions 1 to 16.
- Ethereum: 0x and forty hex digits; a mixed-case address carries the EIP-55
  checksum (Keccak-256 of the lowercase hex, implemented here because the
  standard library's sha3_256 is the NIST variant, not Keccak). An address
  written all in one case carries no checksum and is accepted as written.

Nothing here keeps, logs or sends an address.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {c: i for i, c in enumerate(_BECH32)}
_BECH32_CONST, _BECH32M_CONST = 1, 0x2BC830A3

# Base58Check version bytes, mainnet only: what a user copies to pay someone.
_VERSIONS = {
    0x00: ("Bitcoin", "legacy"), 0x05: ("Bitcoin", "script"),
    0x30: ("Litecoin", "legacy"), 0x32: ("Litecoin", "script"),
    0x1E: ("Dogecoin", "legacy"), 0x16: ("Dogecoin", "script"),
    0x41: ("Tron", "account"),
}
_SEGWIT_HRP = {"bc": "Bitcoin", "ltc": "Litecoin"}
_BASE58_SHAPE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{25,35}$")
_ETH_SHAPE = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class Address:
    family: str           # Bitcoin, Litecoin, Dogecoin, Tron, Ethereum
    kind: str             # legacy, script, segwit, account
    checksummed: bool     # False only for an Ethereum address written in one case


def family(text: str) -> Address | None:
    """The address `text` is, if it is exactly one (surrounding whitespace
    ignored), else None."""
    candidate = (text or "").strip()
    if not candidate or len(candidate) > 100 or any(c.isspace() for c in candidate):
        return None
    if _ETH_SHAPE.match(candidate):
        return _ethereum(candidate)
    found = _segwit(candidate)
    if found is not None:
        return found
    if _BASE58_SHAPE.match(candidate):
        return _base58check(candidate)
    return None


# ----------------------------------------------------------------- Base58Check

def _b58decode(text: str) -> bytes | None:
    number = 0
    for char in text:
        value = _B58_INDEX.get(char)
        if value is None:
            return None
        number = number * 58 + value
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(text) - len(text.lstrip("1"))
    return b"\0" * leading + body


def b58check_encode(version: int, payload: bytes) -> str:
    """Encode `payload` under `version` (used by the tests to build addresses)."""
    raw = bytes([version]) + payload
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58[rest] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _base58check(text: str) -> Address | None:
    raw = _b58decode(text)
    if raw is None or len(raw) != 25:
        return None
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        return None
    known = _VERSIONS.get(body[0])
    if known is None:
        return None
    return Address(known[0], known[1], True)


# ------------------------------------------------------------ bech32, bech32m

def _polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            check ^= generator[i] if (top >> i) & 1 else 0
    return check


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def _segwit(text: str) -> Address | None:
    if text.lower() != text and text.upper() != text:
        return None                                   # mixed case is invalid bech32
    lowered = text.lower()
    if "1" not in lowered or len(lowered) > 90:
        return None
    hrp, _, data_part = lowered.rpartition("1")
    if hrp not in _SEGWIT_HRP or len(data_part) < 6:
        return None
    data = [_BECH32_INDEX.get(c, -1) for c in data_part]
    if -1 in data:
        return None
    const = _polymod(_hrp_expand(hrp) + data)
    if const not in (_BECH32_CONST, _BECH32M_CONST):
        return None
    version, program = data[0], _convertbits(data[1:-6], 5, 8)
    if program is None or version > 16 or not 2 <= len(program) <= 40:
        return None
    if version == 0 and (const != _BECH32_CONST or len(program) not in (20, 32)):
        return None
    if version != 0 and const != _BECH32M_CONST:
        return None
    return Address(_SEGWIT_HRP[hrp], "segwit", True)


# ----------------------------------------------------------- Ethereum, EIP-55

_KECCAK_ROUNDS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state: list[list[int]]) -> None:
    for round_constant in _KECCAK_ROUNDS:
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _KECCAK_ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y])
        state[0][0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as Ethereum uses it (padding 0x01, not SHA-3's 0x06)."""
    rate = 136
    padded = bytearray(data) + b"\x01" + b"\0" * ((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(rate // 8))
    return out[:32]


def eip55(hex40: str) -> str:
    """The EIP-55 mixed-case form of forty hex digits."""
    lowered = hex40.lower()
    digest = keccak256(lowered.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
                          for i, c in enumerate(lowered))


def _ethereum(text: str) -> Address | None:
    body = text[2:]
    if body == body.lower() or body == body.upper():
        return Address("Ethereum", "account", False)
    if eip55(body) != "0x" + body:
        return None
    return Address("Ethereum", "account", True)


# ------------------------------------------------- comparing two addresses

_PREFIX = {"Bitcoin": ("bc1", "1", "3"), "Litecoin": ("ltc1", "L", "M", "3"), "Dogecoin": ("D", "9", "A"),
           "Tron": ("T",), "Ethereum": ("0x",)}
_SHAPES = (
    ("Ethereum", re.compile(r"^0x[0-9a-fA-F]{40}$")),
    ("Bitcoin", re.compile(r"^(?:bc1[02-9ac-hj-np-z]{8,87}|BC1[02-9AC-HJ-NP-Z]{8,87}|[13][1-9A-HJ-NP-Za-km-z]{24,34})$")),
    ("Litecoin", re.compile(r"^(?:ltc1[02-9ac-hj-np-z]{8,86}|LTC1[02-9AC-HJ-NP-Z]{8,86}|[LM][1-9A-HJ-NP-Za-km-z]{24,34})$")),
    ("Dogecoin", re.compile(r"^[D9A][1-9A-HJ-NP-Za-km-z]{24,34}$")),
    ("Tron", re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")),
)


def canonical(text: str) -> str:
    """The form two copies of one address share: bech32 and Ethereum compare
    without case (an all-caps bech32 address is the same address; EIP-55 case
    is a checksum, not a different account), Base58 exactly."""
    candidate = (text or "").strip()
    if candidate[:3].lower() in ("bc1", "ltc", "0x0") or candidate[:2].lower() == "0x":
        return candidate.lower()
    return candidate


def shaped_like(text: str) -> str | None:
    """The family an address-shaped string would belong to, checksum NOT
    verified: for telling that a string which fails its checksum was made to
    look like an address of a family."""
    candidate = (text or "").strip()
    for name, shape in _SHAPES:
        if shape.match(candidate):
            return name
    return None


def lookalike(first: str, second: str, family_name: str) -> bool:
    """Whether `second` was made to look like `first`: the same leading and
    trailing characters after the family's fixed prefix, which is how the
    lookalike clippers reported so far choose their replacement. Two random
    addresses share two characters at both ends about once in eleven million."""
    a, b = canonical(first), canonical(second)
    for prefix in _PREFIX.get(family_name, ()):
        if a.startswith(prefix.lower() if a == a.lower() else prefix) and b[:len(prefix)].lower() == prefix.lower():
            a, b = a[len(prefix):], b[len(prefix):]
            break
    head = len(_common(a, b))
    tail = len(_common(a[::-1], b[::-1]))
    return (head >= 2 and tail >= 2) or head >= 4 or tail >= 4


def differing_characters(first: str, second: str) -> int | None:
    """How many positions differ between two strings of one length, or None
    when the lengths differ."""
    a, b = canonical(first), canonical(second)
    if len(a) != len(b):
        return None
    return sum(1 for x, y in zip(a, b) if x != y)


def _common(a: str, b: str) -> str:
    out = []
    for x, y in zip(a, b):
        if x != y:
            break
        out.append(x)
    return "".join(out)
