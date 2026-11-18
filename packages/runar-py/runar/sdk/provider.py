"""Provider interface and MockProvider for testing."""

from __future__ import annotations
from abc import ABC, abstractmethod
from runar.sdk.types import TransactionData, Utxo
from runar.sdk.errors import (
    BroadcastRejected,
    BroadcastValidationUnavailable,
    assert_script_hex_under_limit,
)
from runar.sdk.input_limits import MAX_SCRIPT_BYTES

_BSV_SDK_HINT = (
    "MockProvider's SCRIPT-EXECUTION layer needs the upstream bsv-sdk "
    "interpreter (bsv.script.spend.Spend), which is not installed.\n"
    "  Install it:  pip install 'bsv-sdk>=2.5.0'   (or: pip install 'runar[dev]')\n"
    "runar itself stays zero-dependency at RUNTIME; bsv-sdk is a TEST "
    "dependency, and CI installs it for the packages/runar-py job "
    "(.github/workflows/ci.yml: `pip install pytest slh-dsa bsv-sdk`).\n"
    "In CI ($CI set) its absence is a hard error, because CI must never lose "
    "the script layer silently. Outside CI the structural / non-vacuity / "
    "value-conservation layer still runs and the degradation is recorded as "
    "`script_vm_available: False` in last_validation_report — it is never "
    "silently reported as validated."
)


def _bsv_sdk_available() -> bool:
    try:
        import bsv.script.spend  # noqa: F401
        import bsv.transaction  # noqa: F401
    except ImportError:
        return False
    return True


class Provider(ABC):
    """Abstracts blockchain access for UTXO lookup and broadcast."""

    @abstractmethod
    def get_transaction(self, txid: str) -> TransactionData:
        """Fetch a transaction by its txid."""
        ...

    @abstractmethod
    def broadcast(self, tx) -> str:
        """Send a transaction to the network. Returns the txid.

        Accepts either a bsv-sdk Transaction object (calls tx.hex()) or a raw
        hex string for backward compatibility.
        """
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
        """Return the current fee rate in satoshis per KB (1000 bytes)."""
        ...

    @abstractmethod
    def get_raw_transaction(self, txid: str) -> str:
        """Fetch the raw transaction hex by its txid."""
        ...


_EMPTY_VALIDATION_REPORT = {
    'validated': 0,
    'unknown': 0,
    'unvalidatable': 0,
    'total': 0,
    'value_conserved': False,
    'script_vm_available': False,
}

# bsv-sdk releases before 2.5.0 sighash the wrong scriptCode for any script
# carrying a top-level ``OP_RETURN <data>`` (bsv-blockchain/py-sdk#247:
# ``Script.from_chunks`` dropped the 0x6a, and Spend builds the BIP-143
# scriptCode with it), so they reject every stateful Rúnar covenant input.
# MockProvider used to tolerate that as "unvalidatable"; it now validates
# covenant inputs like any other and refuses to run under an older bsv-sdk.
# Pinned by tests/test_gk_gap_008_covenant_carveout.py.
_MIN_BSV_SDK = (2, 5, 0)


def _bsv_sdk_version() -> str | None:
    """The installed bsv-sdk distribution version, or None if unreadable."""
    try:
        from importlib.metadata import version
        return version('bsv-sdk')
    except Exception:
        return None


def _require_fixed_bsv_sdk() -> None:
    """Raise unless the installed bsv-sdk is >= 2.5.0 (py-sdk#247 fixed)."""
    import re

    v = _bsv_sdk_version()
    m = re.match(r'(\d+)\.(\d+)\.(\d+)', v or '')
    if m is None or tuple(int(x) for x in m.groups()) < _MIN_BSV_SDK:
        raise BroadcastValidationUnavailable(
            f'MockProvider needs bsv-sdk >= 2.5.0 to validate broadcasts; found '
            f'{v or "an unreadable version"}. Older releases sighash the wrong '
            'scriptCode after OP_RETURN (bsv-blockchain/py-sdk#247) and reject '
            "every stateful Rúnar covenant input. Run: pip install -U 'bsv-sdk>=2.5.0'"
        )


class MockProvider(Provider):
    """In-memory provider for unit tests and local development.

    Broadcast validation is DEFAULT-ON (testing-gap remediation Phase A5) — see
    :meth:`broadcast` and README "How fund-path tests fail closed in the Python
    tier".
    """

    def __init__(self, network: str = 'testnet', validate_broadcasts: bool = True):
        self._transactions: dict[str, TransactionData] = {}
        self._raw_transactions: dict[str, str] = {}
        self._utxos: dict[str, list[Utxo]] = {}
        self._contract_utxos: dict[str, Utxo] = {}
        self._broadcasted_txs: list[str] = []
        self._network = network
        self._broadcast_count = 0
        self._fee_rate = 100
        self._validate_broadcasts = validate_broadcasts
        # "txid:vout" -> {'script': hex, 'satoshis': int}
        self._known_outpoints: dict[str, dict] = {}
        self._last_report = dict(_EMPTY_VALIDATION_REPORT)

    @classmethod
    def always_ack(cls, network: str = 'testnet') -> 'MockProvider':
        """A MockProvider whose :meth:`broadcast` never validates — the
        pre-Phase-A5 behaviour.

        FOR ALLOWLISTED TESTS ONLY: every test file that calls this (or the
        other opt-outs) must carry a matching entry in
        ``always_ack_allowlist.json``, enforced by
        ``tests/test_always_ack_allowlist.py``. Fund-path deploy/call tests
        must not use it.
        """
        return cls(network, validate_broadcasts=False)

    def enable_broadcast_validation(self, enabled: bool = True) -> None:
        """Turn the fail-closed :meth:`broadcast` check on or off. Passing
        ``False`` is an allowlisted opt-out — see :meth:`always_ack`."""
        self._validate_broadcasts = enabled

    def disable_broadcast_validation(self) -> None:
        """Restore the legacy always-ack :meth:`broadcast`. Allowlisted opt-out."""
        self._validate_broadcasts = False

    @property
    def last_validation_report(self) -> dict:
        """Report from the most recent validating :meth:`broadcast`. Exposed so
        a test can assert its gate is NOT vacuous."""
        return dict(self._last_report)

    @property
    def last_validated_input_count(self) -> int:
        """Number of inputs the most recent validating broadcast actually ran
        through the script interpreter."""
        return self._last_report['validated']

    def _remember_outpoint(self, txid, vout, script, satoshis) -> None:
        if not txid or not script:
            return
        self._known_outpoints[f'{txid}:{vout}'] = {
            'script': script,
            'satoshis': int(satoshis or 0),
        }

    def add_transaction(self, tx: TransactionData) -> None:
        self._transactions[tx.txid] = tx
        for i, out in enumerate(tx.outputs or []):
            self._remember_outpoint(tx.txid, i, out.script, out.satoshis)

    def add_utxo(self, address: str, utxo: Utxo) -> None:
        if address not in self._utxos:
            self._utxos[address] = []
        self._utxos[address].append(utxo)
        self._remember_outpoint(utxo.txid, utxo.output_index, utxo.script, utxo.satoshis)

    def add_contract_utxo(self, script_hash: str, utxo: Utxo) -> None:
        self._contract_utxos[script_hash] = utxo
        self._remember_outpoint(utxo.txid, utxo.output_index, utxo.script, utxo.satoshis)

    def get_broadcasted_txs(self) -> list[str]:
        return list(self._broadcasted_txs)

    def set_fee_rate(self, rate: int) -> None:
        self._fee_rate = rate

    # -- Provider interface --

    def get_transaction(self, txid: str) -> TransactionData:
        tx = self._transactions.get(txid)
        if tx is None:
            raise RuntimeError(f"MockProvider: transaction {txid} not found")
        return tx

    def broadcast(self, tx) -> str:
        """Validate the transaction (unless validation has been opted out of)
        and then record it, returning a deterministic fake txid.

        Fail-closed by default (testing-gap remediation Phase A5): every input
        whose outpoint this provider knows is executed by the upstream
        ``bsv-sdk`` ``Spend`` interpreter with full transaction context, outputs
        may not exceed known inputs, and a transaction none of whose inputs
        could be executed is REJECTED rather than waved through — a gate that
        validates nothing is worse than no gate.

        If ``bsv-sdk`` is missing, this raises
        :class:`~runar.sdk.errors.BroadcastValidationUnavailable` rather than
        skipping validation. See ``_BSV_SDK_HINT``.
        """
        # Accept either a bsv-sdk Transaction object or a raw hex string
        if isinstance(tx, str):
            raw_tx = tx
        else:
            raw_tx = tx.hex()

        parsed = None
        if self._validate_broadcasts:
            parsed = self._validate_broadcast(raw_tx)

        self._broadcasted_txs.append(raw_tx)
        # Auto-store raw hex for subsequent get_raw_transaction lookups
        self._broadcast_count += 1
        fake_txid = _mock_hash64(
            f"mock-broadcast-{self._broadcast_count}-{raw_tx[:16]}"
        )
        self._raw_transactions[fake_txid] = raw_tx
        # Register this tx's own outputs as known outpoints so a chained call
        # (spending the continuation this broadcast just created) is checkable.
        if parsed is not None:
            for i, out in enumerate(parsed['outputs']):
                self._remember_outpoint(fake_txid, i, out['script'].hex(), out['satoshis'] or 0)
        return fake_txid

    def _validate_broadcast(self, raw_tx: str):
        """Fail-closed broadcast validation. Returns the parsed transaction.

        TWO LAYERS, so the gate can never silently fail open:

        1. **Always on, stdlib only.** The payload must parse as a Bitcoin
           transaction (:func:`runar.sdk.oppushtx._parse_raw_tx`), at least one
           spent outpoint must be known here (non-vacuity), and — when every
           input is known — the outputs must not exceed the inputs.
        2. **Script execution via the upstream bsv-sdk ``Spend``**, when that
           optional dependency is installed. Its absence is NEVER a silent
           skip: it is recorded as ``script_vm_available: False`` in
           :attr:`last_validation_report`, and in CI (``$CI`` set) it is a hard
           :class:`BroadcastValidationUnavailable` error, because CI must never
           lose the script layer. See ``_BSV_SDK_HINT``.

        :raises BroadcastValidationUnavailable: bsv-sdk missing while in CI.
        :raises BroadcastRejected: the transaction is not parseable, an input's
            script fails, outputs exceed known inputs, or NOTHING could be
            checked at all (vacuous validation).
        """
        import os

        from runar.sdk.oppushtx import _parse_raw_tx

        script_vm = _bsv_sdk_available()
        if not script_vm and os.environ.get('CI'):
            raise BroadcastValidationUnavailable(_BSV_SDK_HINT)

        # --- layer 1: structural (stdlib only, always runs) ------------------
        try:
            raw_bytes = bytes.fromhex(raw_tx)
            structural = _parse_raw_tx(raw_bytes)
            if not structural['inputs'] or not structural['outputs']:
                raise ValueError('no inputs/outputs')
        except Exception as exc:
            raise BroadcastRejected(
                'MockProvider: refusing to broadcast — payload is not a parseable '
                f'Bitcoin transaction ({len(raw_tx) // 2} byte(s)): {exc}. '
                'A real node would reject it outright.'
            ) from exc

        unknown = 0
        all_inputs_known = True
        total_known_in = 0
        known_keys: list[str | None] = []

        for inp in structural['inputs']:
            key = f"{inp['prev_txid_bytes'][::-1].hex()}:{inp['prev_output_index']}"
            known = self._known_outpoints.get(key)
            if known is None:
                all_inputs_known = False
                unknown += 1
                known_keys.append(None)
            else:
                total_known_in += known['satoshis']
                known_keys.append(key)

        known_inputs = sum(1 for k in known_keys if k is not None)

        # --- layer 2: script execution (needs bsv-sdk) -----------------------
        parsed = None
        validated = 0
        if script_vm:
            _require_fixed_bsv_sdk()
            from bsv.script.script import Script as _BsvScript
            from bsv.script.spend import Spend as _BsvSpend
            from bsv.transaction import Transaction as _BsvTransaction

            parsed = _BsvTransaction.from_hex(raw_tx)
            for i, inp in enumerate(parsed.inputs):
                key = known_keys[i] if i < len(known_keys) else None
                if key is None:
                    continue
                known = self._known_outpoints[key]
                other_inputs = [v for j, v in enumerate(parsed.inputs) if j != i]
                locking = _BsvScript(known['script'])
                try:
                    spend = _BsvSpend({
                        'sourceTXID': inp.source_txid,
                        'sourceOutputIndex': inp.source_output_index,
                        'sourceSatoshis': known['satoshis'],
                        'lockingScript': locking,
                        'transactionVersion': parsed.version,
                        'otherInputs': other_inputs,
                        'outputs': parsed.outputs,
                        'inputIndex': i,
                        'unlockingScript': inp.unlocking_script,
                        'inputSequence': inp.sequence,
                        'lockTime': parsed.locktime,
                    })
                    ok = spend.validate()
                except Exception as exc:
                    raise BroadcastRejected(
                        f'MockProvider: refusing to broadcast invalid transaction: '
                        f'input {i}: script REJECTED by bsv-sdk Spend: {exc}'
                    ) from exc
                if not ok:
                    raise BroadcastRejected(
                        'MockProvider: refusing to broadcast invalid transaction: '
                        f'input {i}: script evaluated to false'
                    )
                validated += 1

        self._last_report = {
            'validated': validated,
            'unknown': unknown,
            # Always 0 since bsv-sdk 2.5.0: kept so the report keeps its shape.
            'unvalidatable': 0,
            'total': len(structural['inputs']),
            'value_conserved': all_inputs_known,
            'script_vm_available': script_vm,
        }

        # Non-vacuity: at least ONE real check must have run — a script really
        # executed, or (when every input's outpoint is known) the
        # value-conservation check below. If neither did, nothing was verified
        # and the ack would be a lie.
        if known_inputs == 0:
            raise BroadcastRejected(
                f'MockProvider: refusing to broadcast — NOTHING was checked '
                f"(0 of {len(structural['inputs'])} inputs recognised; unknown "
                f'outpoints: {unknown}), so validation would pass vacuously. Seed '
                'the spent outpoints via add_utxo/add_contract_utxo/add_transaction, '
                'or use MockProvider.always_ack() (allowlisted) if this test '
                'genuinely needs always-ack'
            )

        if all_inputs_known:
            total_out = sum(int(o['satoshis'] or 0) for o in structural['outputs'])
            if total_out > total_known_in:
                raise BroadcastRejected(
                    'MockProvider: refusing to broadcast invalid transaction: '
                    f'underfunded: outputs ({total_out} sats) exceed known inputs '
                    f'({total_known_in} sats)'
                )

        return structural

    def get_utxos(self, address: str) -> list[Utxo]:
        utxos = list(self._utxos.get(address, []))
        # DoS-bound: reject pathological scripts at the provider boundary.
        for u in utxos:
            if not u.script:
                continue
            assert_script_hex_under_limit(
                u.script, MAX_SCRIPT_BYTES,
                f"MockProvider.get_utxos({address})",
            )
        return utxos

    def get_contract_utxo(self, script_hash: str) -> Utxo | None:
        utxo = self._contract_utxos.get(script_hash)
        if utxo is not None and utxo.script:
            assert_script_hex_under_limit(
                utxo.script, MAX_SCRIPT_BYTES,
                f"MockProvider.get_contract_utxo({script_hash})",
            )
        return utxo

    def get_network(self) -> str:
        return self._network

    def get_fee_rate(self) -> int:
        return self._fee_rate

    def get_raw_transaction(self, txid: str) -> str:
        # Check auto-stored raw hex from broadcasts first
        if txid in self._raw_transactions:
            return self._raw_transactions[txid]
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
