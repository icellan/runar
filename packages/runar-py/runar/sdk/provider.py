"""Provider interface and MockProvider for testing."""

from __future__ import annotations
from abc import ABC, abstractmethod
from runar.sdk.types import Transaction, Utxo


class Provider(ABC):
    """Abstracts blockchain access for UTXO lookup and broadcast."""

    @abstractmethod
    def get_transaction(self, txid: str) -> Transaction:
        """Fetch a transaction by its txid."""
        ...

    @abstractmethod
    def broadcast(self, raw_tx: str) -> str:
        """Send a raw transaction hex to the network. Returns the txid."""
        ...

    @abstractmethod
    def get_utxos(self, address: str) -> list[Utxo]:
        """Return all UTXOs for a given address."""
        ...

    @abstractmethod
    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        """Find a UTXO by its script hash (for stateful contract lookup)."""
        ...

    @abstractmethod
    def get_network(self) -> str:
        """Return the network this provider is connected to."""
        ...

    @abstractmethod
    def get_fee_rate(self) -> int:
        """Return the current fee rate in satoshis per byte."""
        ...

    @abstractmethod
    def get_raw_transaction(self, txid: str) -> str:
        """Fetch the raw transaction hex by its txid."""
        ...


class MockProvider(Provider):
    """In-memory provider for unit tests and local development."""

    def __init__(self, network: str = 'testnet'):
        self._transactions: dict[str, Transaction] = {}
        self._utxos: dict[str, list[Utxo]] = {}
        self._contract_utxos: dict[str, Utxo] = {}
        self._broadcasted_txs: list[str] = []
        self._network = network
        self._broadcast_count = 0
        self._fee_rate = 1

    def add_transaction(self, tx: Transaction) -> None:
        self._transactions[tx.txid] = tx

    def add_utxo(self, address: str, utxo: Utxo) -> None:
        if address not in self._utxos:
            self._utxos[address] = []
        self._utxos[address].append(utxo)

    def add_contract_utxo(self, script_hash: str, utxo: Utxo) -> None:
        self._contract_utxos[script_hash] = utxo

    def get_broadcasted_txs(self) -> list[str]:
        return list(self._broadcasted_txs)

    def set_fee_rate(self, rate: int) -> None:
        self._fee_rate = rate

    # -- Provider interface --

    def get_transaction(self, txid: str) -> Transaction:
        tx = self._transactions.get(txid)
        if tx is None:
            raise RuntimeError(f"MockProvider: transaction {txid} not found")
        return tx

    def broadcast(self, raw_tx: str) -> str:
        self._broadcasted_txs.append(raw_tx)
        self._broadcast_count += 1
        fake_txid = _mock_hash64(
            f"mock-broadcast-{self._broadcast_count}-{raw_tx[:16]}"
        )
        return fake_txid

    def get_utxos(self, address: str) -> list[Utxo]:
        return list(self._utxos.get(address, []))

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        return self._contract_utxos.get(script_hash)

    def get_network(self) -> str:
        return self._network

    def get_fee_rate(self) -> int:
        return self._fee_rate

    def get_raw_transaction(self, txid: str) -> str:
        tx = self._transactions.get(txid)
        if tx is None:
            raise RuntimeError(f"MockProvider: transaction {txid} not found")
        if not tx.raw:
            raise RuntimeError(f"MockProvider: transaction {txid} has no raw hex")
        return tx.raw


def _mock_hash64(input_str: str) -> str:
    """Deterministic mock hash producing a 64-char hex string (like a txid)."""
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    h3 = 0xA54FF53A

    mask32 = 0xFFFFFFFF

    for ch in input_str:
        c = ord(ch)
        h0 = ((h0 ^ c) * 0x01000193) & mask32
        h1 = ((h1 ^ c) * 0x01000193) & mask32
        h2 = ((h2 ^ c) * 0x01000193) & mask32
        h3 = ((h3 ^ c) * 0x01000193) & mask32

    parts = [h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3]
    return ''.join(f'{p:08x}' for p in parts)
