"""The address recogniser behind the paste guard's swap check
(avguard/wallets.py): each family recognised with its checksum verified, so
a one-character change is not an address; Keccak-256 against its published
vectors; nothing that is not exactly one address is called one.

The addresses are test vectors from the specifications (BIP-173, BIP-350,
EIP-55) or built here from a fixed payload; none is anyone's wallet.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from avguard import wallets
from avguard.wallets import Address, family

PAYLOAD = hashlib.sha256(b"avguard test payload").digest()[:20]


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

    def test_inputs_across_the_block_boundary(self):
        for size in (0, 1, 135, 136, 137, 272, 1000):
            data = bytes(range(256)) * 4
            self.assertEqual(len(wallets.keccak256(data[:size])), 32, size)


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
              "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")              # BIP-350

    def test_segwit_vectors(self):
        for address in self.SEGWIT:
            with self.subTest(address=address):
                self.assertEqual(family(address), Address("Bitcoin", "segwit", True))

    def test_a_changed_character_or_the_wrong_checksum_constant_is_not_an_address(self):
        for address in self.SEGWIT:
            for index in (5, len(address) // 2, len(address) - 1):
                self.assertIsNone(family(changed(address, index)), (address, index))
        self.assertIsNone(family("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"),
                          "witness version 0 under the bech32m constant (BIP-350)")
        self.assertIsNone(family("bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "mixed case")
        self.assertIsNone(family("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), "testnet is not a payment address here")

    def test_base58check_versions_round_trip(self):
        for version, (name, kind) in wallets._VERSIONS.items():
            address = wallets.b58check_encode(version, PAYLOAD)
            with self.subTest(family=name, kind=kind, address=address):
                self.assertEqual(family(address), Address(name, kind, True))
                for index in (1, len(address) // 2, len(address) - 1):
                    self.assertIsNone(family(changed(address, index)), (address, index))

    def test_known_legacy_addresses(self):
        self.assertEqual(family("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Address("Bitcoin", "legacy", True))
        self.assertEqual(family("3P14159f73E4gFr7JterCCQh9QjiTjiZrG"), Address("Bitcoin", "script", True))

    def test_an_unknown_version_byte_is_not_an_address(self):
        self.assertIsNone(family(wallets.b58check_encode(0x6F, PAYLOAD)), "testnet P2PKH")
        self.assertIsNone(family(wallets.b58check_encode(0x00, PAYLOAD + b"\0")), "21-byte payload")

    def test_litecoin_segwit(self):
        self.assertEqual(family("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"), Address("Litecoin", "segwit", True))


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


if __name__ == "__main__":
    unittest.main()
