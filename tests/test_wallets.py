"""The address recogniser behind the paste guard's swap check
(avguard/wallets.py): each family recognised with its checksum verified, so
a one-character change is not an address; Keccak-256 against its published
vectors; nothing that is not exactly one address is called one.

The addresses are test vectors from the specifications and the projects'
own test files (BIP-173, BIP-350, EIP-55, Bitcoin Core's and Litecoin
Core's key_io_valid.json, Dogecoin's base58_keys_valid.json, TronWeb's
isAddress test) or built here from a fixed payload; none is anyone's wallet.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import wallets
from avguard.wallets import Address, family

PAYLOAD = hashlib.sha256(b"avguard test payload").digest()[:20]
FIXTURES = Path(__file__).resolve().parent / "clipboard"


def changed(text: str, index: int) -> str:
    """`text` with one character replaced by another of the same alphabet."""
    char = text[index]
    swap = {"q": "p", "p": "q", "a": "b", "b": "a", "1": "2", "2": "1", "A": "B", "B": "A"}
    other = swap.get(char) or ("x" if char != "x" else "y")
    return text[:index] + other + text[index + 1:]


class TestKeccak(unittest.TestCase):
    def test_the_published_vectors(self):
        self.assertEqual(wallets.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(wallets.keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_it_is_not_the_nist_variant(self):
        self.assertNotEqual(wallets.keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_the_permutation_and_absorption_against_hashlib(self):
        # The same sponge with NIST's padding byte is SHA3-256, which hashlib
        # has: this checks every round and the multi-block path, at sizes
        # either side of the 136-byte rate.
        data = bytes(range(256)) * 4
        for size in (0, 1, 135, 136, 137, 272, 1000):
            with self.subTest(size=size):
                self.assertEqual(wallets.keccak256(data[:size], pad=0x06), hashlib.sha3_256(data[:size]).digest())


class TestEthereum(unittest.TestCase):
    EIP55 = ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
             "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")

    def test_the_eip55_vectors(self):
        for address in self.EIP55:
            with self.subTest(address=address):
                self.assertEqual(family(address), Address("Ethereum", "account", True))
                self.assertEqual(wallets.eip55(address[2:].lower()), address)

    def test_one_flipped_case_breaks_the_checksum(self):
        for address in self.EIP55:
            body = address[2:]
            index = next(i for i, c in enumerate(body) if c.isalpha())
            flipped = "0x" + body[:index] + body[index].swapcase() + body[index + 1:]
            self.assertIsNone(family(flipped), flipped)

    def test_the_one_case_vectors(self):
        for address in ("0x52908400098527886E0F7030069857D2E4169EE7", "0xde709f2102306220921060314715629080e2fb77"):
            self.assertEqual(family(address), Address("Ethereum", "account", False), address)
        self.assertIsNone(family("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"), "the last letter's case is wrong")

    def test_one_case_throughout_carries_no_checksum(self):
        lower = self.EIP55[0].lower()
        self.assertEqual(family(lower), Address("Ethereum", "account", False))
        self.assertEqual(family("0x" + lower[2:].upper()), Address("Ethereum", "account", False))
        self.assertIsNone(family(lower[:-1]), "thirty-nine digits")
        self.assertIsNone(family(lower + "0"), "forty-one digits")


class TestBitcoinFamilies(unittest.TestCase):
    SEGWIT = ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                                  # BIP-173
              "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",                                  # BIP-173
              "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",              # BIP-173
              "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",              # BIP-350
              "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",  # BIP-350
              "BC1SW50QGDZ25J",                                                              # BIP-350
              "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")                                        # BIP-350
    BASE58 = (("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo", "Bitcoin", "legacy"),       # Bitcoin Core key_io_valid.json
              ("1FjL87pn8ky6Vbavd1ZHeChRXtoxwRGCRd", "Bitcoin", "legacy"),
              ("36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm", "Bitcoin", "script"),
              ("3BZECeAH8gSKkjrTx8PwMrNQBLG18yHpvf", "Bitcoin", "script"),
              ("LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA", "Litecoin", "legacy"),     # Litecoin Core key_io_valid.json
              ("LbfVMz974gbbGFqXF7FZUpSBWSbwBHDwR5", "Litecoin", "legacy"),
              ("MHrYRxAiMNBTku3eoDHwhA1LQGDjUStZW2", "Litecoin", "script"),
              ("M9dw1FAoWpHC6PcMzoCHhqQ9McvTyG5Ywj", "Litecoin", "script"),
              ("DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE", "Dogecoin", "legacy"),     # Dogecoin base58_keys_valid.json
              ("DBjW6kna7rUPE4Mj9j4B3oK3xVA1SDHrdt", "Dogecoin", "legacy"),
              ("A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs", "Dogecoin", "script"),
              ("9zYnVRaekPtdKBYuPw5QiBtv3NNrzD2LLW", "Dogecoin", "script"),
              ("TYPG8VeuoVAh2hP7Vfw6ww7vK98nvXXXUG", "Tron", "account"))        # TronWeb isAddress test
    LITECOIN_SEGWIT = ("ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4w",           # Litecoin Core key_io_valid.json
                       "ltc1ppu2gv0tujus0f6eggrk7eqmaf0567x6zer4fcuhz4z7ztzq9u9yseqxltc")
    INVALID = (("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", "Bitcoin Core: the shape, a wrong checksum"),
               ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "BIP-173: checksum"),
               ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", "BIP-173: mixed case"),
               ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "BIP-173: version 0 program length"),
               ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
                "BIP-173's version 1 example, bech32 where BIP-350 wants bech32m"),
               ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "BIP-350: bech32 on version 1"),
               ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "BIP-350: bech32m on version 0"),
               ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", "BIP-350: unknown prefix"),
               ("TYPG8VeuoVAh2hP7Vfw6ww7vK98nvXXXUs", "Tron: last character changed"))

    def test_segwit_vectors(self):
        for address in self.SEGWIT:
            with self.subTest(address=address):
                self.assertEqual(family(address), Address("Bitcoin", "segwit", True))

    def test_a_changed_character_or_the_wrong_checksum_constant_is_not_an_address(self):
        for address in self.SEGWIT:
            for index in (5, len(address) // 2, len(address) - 1):
                self.assertIsNone(family(changed(address, index)), (address, index))
        self.assertIsNone(family("bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "mixed case")
        self.assertIsNone(family("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), "testnet is not a payment address here")

    def test_base58check_versions_round_trip(self):
        for version, (name, kind) in wallets._VERSIONS.items():
            address = wallets.b58check_encode(version, PAYLOAD)
            with self.subTest(family=name, kind=kind, address=address):
                self.assertEqual(family(address), Address(name, kind, True))
                for index in (1, len(address) // 2, len(address) - 1):
                    self.assertIsNone(family(changed(address, index)), (address, index))

    def test_the_projects_base58_vectors(self):
        for address, name, kind in self.BASE58:
            with self.subTest(address=address):
                self.assertEqual(family(address), Address(name, kind, True))
                for index in (1, len(address) // 2, len(address) - 1):
                    self.assertIsNone(family(changed(address, index)), (address, index))

    def test_the_invalid_vectors(self):
        for address, why in self.INVALID:
            with self.subTest(why=why):
                self.assertIsNone(family(address), address)

    def test_tron_from_the_hex_in_its_documentation(self):
        # Tron publishes hex, not Base58 vectors: encoded here, then read back.
        for hex21 in ("41dd791d6b49e190062d650e6a23c575510d35f2f9", "4165cfbd57fa4f20687b2c33f84c4f9017e5895d49"):
            raw = bytes.fromhex(hex21)
            address = wallets.b58check_encode(raw[0], raw[1:])
            self.assertTrue(address.startswith("T"), address)
            self.assertEqual(family(address), Address("Tron", "account", True))
            self.assertEqual(wallets.canonical(address), "b58:" + hex21)

    def test_an_unknown_version_byte_is_not_an_address(self):
        self.assertIsNone(family(wallets.b58check_encode(0x6F, PAYLOAD)), "testnet P2PKH")
        self.assertIsNone(family(wallets.b58check_encode(0x00, PAYLOAD + b"\0")), "21-byte payload")

    def test_litecoin_segwit(self):
        for address in self.LITECOIN_SEGWIT:
            with self.subTest(address=address):
                self.assertEqual(family(address), Address("Litecoin", "segwit", True))
                self.assertEqual(family(address.upper()), Address("Litecoin", "segwit", True))
                self.assertIsNone(family(changed(address, len(address) - 1)))


class TestComparing(unittest.TestCase):
    """shaped_like and differing_characters, which the near-copy test uses on
    a string that fails its checksum."""

    def test_shaped_like_names_the_family_without_the_checksum(self):
        for text, name in (("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "Bitcoin"),
                           ("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", "Bitcoin"),
                           ("ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4x", "Litecoin"),
                           ("TYPG8VeuoVAh2hP7Vfw6ww7vK98nvXXXUs", "Tron"),
                           ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", "Ethereum"),
                           ("hello", None), ("bc1qb", None), ("", None)):
            with self.subTest(text=text):
                self.assertEqual(wallets.shaped_like(text), name)

    def test_differing_characters(self):
        a = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        self.assertEqual(wallets.differing_characters(a, a), 0)
        self.assertEqual(wallets.differing_characters(a, a[:-1] + "5"), 1)
        self.assertEqual(wallets.differing_characters(a, a.upper()), 0, "bech32 ignores case")
        self.assertIsNone(wallets.differing_characters(a, a + "q"), "lengths differ")
        legacy = TestBitcoinFamilies.BASE58[0][0]
        self.assertEqual(wallets.differing_characters(legacy, legacy.swapcase()),
                         sum(c.isalpha() for c in legacy), "Base58 keeps case")

    def test_a_base58_address_beginning_ltc1_keeps_its_case(self):
        # Base58 has L, T, C and 1, so a Litecoin legacy address can begin
        # "LTC1"; a case-flipped copy of one is a different string.
        for second in "abcdef":
            address = "LTC1" + second + "VaAy1ppRuxRgrS5RNU3vBsy7Ri"
            flipped = address[:5] + address[5:].swapcase()
            self.assertGreater(wallets.differing_characters(address, flipped), 0, address)


class TestCanonical(unittest.TestCase):
    def test_two_spellings_of_one_address_share_one_key(self):
        pairs = (("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"),
                 (TestEthereum.EIP55[0], TestEthereum.EIP55[0].lower()),
                 (TestEthereum.EIP55[0], "0x" + TestEthereum.EIP55[0][2:].upper()),
                 (TestBitcoinFamilies.LITECOIN_SEGWIT[0], TestBitcoinFamilies.LITECOIN_SEGWIT[0].upper()))
        for first, second in pairs:
            with self.subTest(first=first):
                self.assertEqual(wallets.canonical(first), wallets.canonical(second))

    def test_different_addresses_have_different_keys(self):
        keys = [wallets.canonical(a) for a, _, _ in TestBitcoinFamilies.BASE58]
        keys += [wallets.canonical(a) for a in TestBitcoinFamilies.SEGWIT if a != a.upper()]
        keys += [wallets.canonical(a) for a in TestEthereum.EIP55]
        self.assertEqual(len(keys), len(set(keys)))

    def test_the_same_program_under_two_witness_versions_is_two_addresses(self):
        v0 = wallets.canonical("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        v1 = wallets.canonical("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")
        self.assertNotEqual(v0, v1)
        self.assertNotEqual(wallets.canonical("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"), v0)


class TestOnlyExactlyOneAddress(unittest.TestCase):
    def test_surrounding_whitespace_is_ignored_and_anything_else_is_not_an_address(self):
        vector = TestBitcoinFamilies.SEGWIT[0]
        self.assertIsNotNone(family(f"  {vector}\r\n"))
        for text in ("", " ", "hello", f"{vector} {vector}", f"send to {vector}", f"bitcoin:{vector}",
                     "0x" + "g" * 40, "1" * 30, "bc1", "x" * 200, None):
            with self.subTest(text=text):
                self.assertIsNone(family(text))

    def test_ordinary_text_of_the_same_shape_is_not_an_address(self):
        for text in ("1234567890123456789012345678", "abcdefghijkmnopqrstuvwxyzABCDEFGH",
                     "0x0000000000000000000000000000000000000000z", "deadbeef" * 5):
            self.assertIsNone(family(text), text)

    def test_formats_outside_the_check_are_not_addresses(self):
        monero_shaped = "4" + "".join(wallets._B58[(7 * i) % 58] for i in range(94))   # 95 Base58 characters
        for text, why in (("rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN", "XRP, its own Base58 alphabet"),
                          ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "Bitcoin Cash cashaddr"),
                          (monero_shaped, "Monero-shaped")):
            with self.subTest(why=why):
                self.assertIsNone(family(text), text)

    def test_a_lookalike_letter_from_outside_ascii_is_not_an_address(self):
        # KELVIN SIGN (U+212A) is its own upper case and lowers to "k".
        kelvin = "\u212a"
        for text in ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7" + kelvin + "V8F3T4",
                     "LT2" + kelvin + "VaAy1ppRuxRgrS5RNU3vBsy7RibPeA"):
            with self.subTest(text=ascii(text)):
                self.assertIsNone(family(text))
                self.assertIsNone(wallets.shaped_like(text))

    def test_random_base58_is_never_an_address(self):
        # A four-byte checksum: about one string in 4.3 billion passes by
        # chance, and the version byte must also be one of seven.
        rng = random.Random(20261007)
        letters = wallets._B58[1:]
        for _ in range(20000):
            text = rng.choice("13LMDA9T") + "".join(rng.choice(letters) for _ in range(33))
            self.assertIsNone(family(text), text)

    def test_no_clipboard_fixture_is_an_address(self):
        files = sorted(FIXTURES.rglob("*.txt"))
        self.assertGreater(len(files), 50)
        for path in files:
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(family(text), path.name)
            for line in text.splitlines():
                self.assertIsNone(family(line), (path.name, line[:40]))


if __name__ == "__main__":
    unittest.main()
