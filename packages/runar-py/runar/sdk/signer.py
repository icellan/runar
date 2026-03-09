"""Signer interface and implementations."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Callable


class Signer(ABC):
    """Abstracts private key operations for signing transactions."""

    @abstractmethod
    def get_public_key(self) -> str:
        """Return the hex-encoded compressed public key (66 hex chars)."""
        ...

    @abstractmethod
    def get_address(self) -> str:
        """Return the BSV address."""
        ...

    @abstractmethod
    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        """Sign a transaction input.

        Returns the DER-encoded signature with sighash byte appended, hex-encoded.
        """
        ...


class MockSigner(Signer):
    """Deterministic signer for testing. Does not perform real crypto."""

    def __init__(self, pub_key_hex: str = '', address: str = ''):
        self._pub_key = pub_key_hex or ('02' + '00' * 32)
        self._address = address or ('00' * 20)

    def get_public_key(self) -> str:
        return self._pub_key

    def get_address(self) -> str:
        return self._address

    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        # Return a deterministic 72-byte mock signature: DER prefix 0x30 + 70 zero bytes + sighash 0x41
        return '30' + '00' * 70 + '41'


class ExternalSigner(Signer):
    """Callback-based signer that delegates to an external signing function."""

    def __init__(
        self,
        pub_key_hex: str,
        address: str,
        sign_fn: Callable[[str, int, str, int, int | None], str],
    ):
        self._pub_key = pub_key_hex
        self._address = address
        self._sign_fn = sign_fn

    def get_public_key(self) -> str:
        return self._pub_key

    def get_address(self) -> str:
        return self._address

    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        return self._sign_fn(tx_hex, input_index, subscript, satoshis, sighash_type)
