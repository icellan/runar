"""Tests for runar.sdk.calling — transaction construction for method invocation.

Mirrors TestBuildCallTransaction_* tests from packages/runar-go/sdk_test.go.
"""

import struct
import pytest
from runar.sdk.calling import build_call_transaction, insert_unlocking_script
from runar.sdk.types import Utxo


def _make_utxo(satoshis: int, index: int = 0) -> Utxo:
    txid = f'{index:02x}' * 32
    return Utxo(txid=txid, output_index=0, satoshis=satoshis, script='76a914' + '00' * 20 + '88ac')


# ---------------------------------------------------------------------------
# Minimal raw-tx parser used by tests that need to inspect tx structure
# ---------------------------------------------------------------------------

def _parse_tx(tx_hex: str) -> dict:
    """Parse a raw tx hex into version, inputs, outputs, locktime."""
    pos = 0

    def read_bytes(n):
        nonlocal pos
        result = tx_hex[pos:pos + n * 2]
        pos += n * 2
        return result

    def read_uint32_le():
        h = read_bytes(4)
        b = bytes.fromhex(h)
        return struct.unpack('<I', b)[0]

    def read_uint64_le():
        h = read_bytes(8)
        b = bytes.fromhex(h)
        return struct.unpack('<Q', b)[0]

    def read_varint():
        nonlocal pos
        first = int(tx_hex[pos:pos + 2], 16)
        pos += 2
        if first < 0xFD:
            return first
        if first == 0xFD:
            lo = int(tx_hex[pos:pos + 2], 16)
            hi = int(tx_hex[pos + 2:pos + 4], 16)
            pos += 4
            return lo | (hi << 8)
        raise ValueError('unsupported varint')

    version = read_uint32_le()
    input_count = read_varint()
    inputs = []
    for _ in range(input_count):
        prev_txid = read_bytes(32)
        prev_index = read_uint32_le()
        script_len = read_varint()
        script = read_bytes(script_len)
        sequence = read_uint32_le()
        inputs.append({'prev_txid': prev_txid, 'prev_index': prev_index, 'script': script, 'sequence': sequence})

    output_count = read_varint()
    outputs = []
    for _ in range(output_count):
        satoshis = read_uint64_le()
        script_len = read_varint()
        script = read_bytes(script_len)
        outputs.append({'satoshis': satoshis, 'script': script})

    locktime = read_uint32_le()

    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
    }


# ---------------------------------------------------------------------------
# build_call_transaction
# ---------------------------------------------------------------------------

class TestBuildCallTransaction:
    def test_basic_call_returns_valid_hex(self):
        """A basic call transaction returns (tx_hex, input_count, change_amount)."""
        utxo = _make_utxo(50_000)
        tx_hex, input_count, change_amount = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='5151',  # OP_TRUE OP_TRUE
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
        )

        assert isinstance(tx_hex, str)
        assert len(tx_hex) > 0
        assert all(c in '0123456789abcdef' for c in tx_hex)
        assert input_count == 1
        assert isinstance(change_amount, int)
        # Starts with version 01000000
        assert tx_hex[:8] == '01000000'

    def test_with_additional_utxos(self):
        """Additional funding UTXOs appear as extra inputs."""
        utxo = _make_utxo(10_000, 0)
        funding = [_make_utxo(50_000, 1)]

        tx_hex, input_count, change_amount = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
            additional_utxos=funding,
        )

        assert input_count == 2
        # After version (8 hex), varint should be 02
        assert tx_hex[8:10] == '02'

    def test_with_contract_outputs(self):
        """Multi-output calls pass contract_outputs list."""
        utxo = _make_utxo(50_000)
        outputs = [
            {'script': '51', 'satoshis': 10_000},
            {'script': '51', 'satoshis': 10_000},
        ]

        tx_hex, input_count, change_amount = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='',  # Empty since contract_outputs is used
            new_satoshis=0,
            change_address='00' * 20,
            contract_outputs=outputs,
        )

        assert input_count == 1
        assert isinstance(tx_hex, str)
        assert all(c in '0123456789abcdef' for c in tx_hex)

    def test_change_amount_is_non_negative(self):
        """Change amount should never be negative."""
        utxo = _make_utxo(100_000)
        _, _, change_amount = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
        )
        assert change_amount >= 0

    def test_stateful_call_has_contract_output(self):
        """For a stateful method call, the transaction has a contract continuation output."""
        utxo = _make_utxo(100_000, 0)
        new_locking_script = '76a914' + 'dd' * 20 + '88ac'
        change_script = '76a914' + 'ff' * 20 + '88ac'

        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script=new_locking_script,
            new_satoshis=50_000,
            change_address='changeaddr',
            change_script=change_script,
        )
        parsed = _parse_tx(tx_hex)

        # First output should be the contract continuation
        assert len(parsed['outputs']) >= 1
        assert parsed['outputs'][0]['script'] == new_locking_script
        assert parsed['outputs'][0]['satoshis'] == 50_000

    def test_stateless_call_no_contract_output(self):
        """For a stateless method call (no new_locking_script), only change output is present."""
        utxo = _make_utxo(100_000, 0)
        change_script = '76a914' + 'ff' * 20 + '88ac'

        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='',   # stateless — no continuation output
            new_satoshis=0,
            change_address='changeaddr',
            change_script=change_script,
        )
        parsed = _parse_tx(tx_hex)

        # Only the change output, no contract output
        assert len(parsed['outputs']) == 1
        assert parsed['outputs'][0]['script'] == change_script
        # Fee: 86 bytes at 100 sat/KB → fee = ceil(86*100/1000) = 9 → change = 100000 - 9 = 99991
        assert parsed['outputs'][0]['satoshis'] == 99_991

    def test_call_fee_paid_from_funding_utxos(self):
        """The transaction fee is deducted from the change output (change < total input)."""
        utxo = _make_utxo(100_000, 0)
        change_script = '76a914' + 'ff' * 20 + '88ac'

        tx_hex, _, change_amount = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='00',   # 1-byte unlocking script
            new_locking_script='51',
            new_satoshis=50_000,
            change_address='changeaddr',
            change_script=change_script,
        )
        parsed = _parse_tx(tx_hex)

        # Two outputs: contract + change
        assert len(parsed['outputs']) == 2
        assert parsed['outputs'][0]['satoshis'] == 50_000

        # Change < total_input - new_satoshis (fee was deducted)
        total_input = utxo.satoshis
        assert change_amount < total_input - 50_000
        assert change_amount > 0

        # Verify the parsed change output matches the returned change_amount
        assert parsed['outputs'][1]['satoshis'] == change_amount

    def test_selector_in_unlocking_script_for_multi_method(self):
        """When calling a specific method of a multi-method contract via build_unlocking_script,
        the unlocking script has the correct method selector appended."""
        from runar.sdk.contract import RunarContract
        from runar.sdk.types import RunarArtifact, Abi, AbiMethod, AbiParam

        artifact = RunarArtifact(
            version='runar-v0.1.0',
            contract_name='MultiMethod',
            abi=Abi(
                constructor_params=[],
                methods=[
                    AbiMethod(name='release', params=[], is_public=True),
                    AbiMethod(name='refund', params=[], is_public=True),
                ],
            ),
            script='51',
        )
        contract = RunarContract(artifact, [])

        # 'release' is index 0 → OP_0 = '00'
        release_script = contract.build_unlocking_script('release', [])
        assert release_script == '00'

        # 'refund' is index 1 → OP_1 = '51'
        refund_script = contract.build_unlocking_script('refund', [])
        assert refund_script == '51'

        # Build a tx with the release unlocking script and verify it appears in the tx
        utxo = _make_utxo(50_000)
        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script=release_script,
            new_locking_script='',
            new_satoshis=0,
            change_address='00' * 20,
        )
        parsed = _parse_tx(tx_hex)
        assert parsed['inputs'][0]['script'] == release_script


# ---------------------------------------------------------------------------
# insert_unlocking_script
# ---------------------------------------------------------------------------

class TestInsertUnlockingScript:
    def test_replaces_empty_scriptsig(self):
        """Inserting an unlocking script into an unsigned input replaces the empty scriptSig."""
        utxo = _make_utxo(50_000)
        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',  # 1-byte unlock
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
        )

        new_unlock = 'aabb'  # 2 bytes
        modified = insert_unlocking_script(tx_hex, 0, new_unlock)

        assert isinstance(modified, str)
        assert all(c in '0123456789abcdef' for c in modified)
        # The new unlock script should appear somewhere in the output
        assert new_unlock in modified

    def test_out_of_range_index_raises(self):
        """Inserting at an invalid input index raises ValueError."""
        utxo = _make_utxo(50_000)
        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
        )

        with pytest.raises(ValueError, match='out of range'):
            insert_unlocking_script(tx_hex, 5, 'aabb')


# ---------------------------------------------------------------------------
# Additional structural tests (rows 346, 348, 352-356)
# ---------------------------------------------------------------------------

class TestBuildCallTransactionStructure:
    def test_txid_bytes_reversed_in_wire_format(self):
        """Input prev_txid bytes are reversed (little-endian) in the wire format (row 346).

        UTXO txid 'aabb...cc00' should appear as '00cc...bbaa' in the raw tx.
        """
        utxo = Utxo(
            txid='aabbccdd' + '00' * 28,
            output_index=0,
            satoshis=100_000,
            script='76a914' + '00' * 20 + '88ac',
        )
        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='',
            new_satoshis=0,
            change_address='00' * 20,
        )
        parsed = _parse_tx(tx_hex)
        # In wire format, txid is reversed (LE)
        expected_reversed = '00' * 28 + 'ddccbbaa'
        assert parsed['inputs'][0]['prev_txid'] == expected_reversed

    def test_no_change_output_when_change_is_zero(self):
        """When exact fee is used with no surplus, no change output is produced (row 348)."""
        # Build a tx where fee exactly matches the remaining balance
        # Use a very small locking script to control size exactly
        utxo = _make_utxo(100_000)
        tx_hex, _, change = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=99_850,  # close to total to exhaust change
            change_address='00' * 20,
        )
        parsed = _parse_tx(tx_hex)
        if change == 0:
            # When change == 0, there should be only 1 output (contract)
            assert len(parsed['outputs']) == 1
        else:
            # If change > 0, there should be 2 outputs
            assert len(parsed['outputs']) == 2

    def test_additional_inputs_have_empty_script(self):
        """Additional P2PKH funding inputs should have empty scriptSig in unsigned tx (row 352)."""
        utxo = _make_utxo(10_000, 0)
        funding = [_make_utxo(50_000, 1), _make_utxo(30_000, 2)]

        tx_hex, input_count, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
            additional_utxos=funding,
        )
        parsed = _parse_tx(tx_hex)
        assert input_count == 3
        # Inputs 1 and 2 (funding) should have empty scriptSig
        assert parsed['inputs'][1]['script'] == ''
        assert parsed['inputs'][2]['script'] == ''

    def test_all_input_sequences_are_ffffffff(self):
        """Every input in the transaction should have sequence 0xFFFFFFFF (row 353)."""
        utxo = _make_utxo(50_000, 0)
        funding = [_make_utxo(20_000, 1)]

        tx_hex, input_count, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='51',
            new_satoshis=10_000,
            change_address='00' * 20,
            additional_utxos=funding,
        )
        parsed = _parse_tx(tx_hex)
        for i, inp in enumerate(parsed['inputs']):
            assert inp['sequence'] == 0xFFFFFFFF, (
                f"input {i} sequence expected 0xFFFFFFFF, got {inp['sequence']:#010x}"
            )

    def test_output_index_matches_utxo(self):
        """The prev_index field in the input must match the utxo.output_index (row 354)."""
        utxo = Utxo(
            txid='00' * 32,
            output_index=3,
            satoshis=100_000,
            script='76a914' + '00' * 20 + '88ac',
        )
        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='',
            new_satoshis=0,
            change_address='00' * 20,
        )
        parsed = _parse_tx(tx_hex)
        assert parsed['inputs'][0]['prev_index'] == 3

    def test_defaults_to_current_utxo_satoshis_when_no_new_satoshis(self):
        """When new_satoshis == 0 and there is a new_locking_script, uses current UTXO
        satoshis as the output amount (row 355)."""
        utxo = _make_utxo(50_000)
        new_locking_script = '76a914' + 'aa' * 20 + '88ac'

        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script=new_locking_script,
            new_satoshis=0,  # should default to current_utxo.satoshis
            change_address='',
        )
        parsed = _parse_tx(tx_hex)
        # Output 0 should have satoshis == utxo.satoshis (50_000)
        assert parsed['outputs'][0]['satoshis'] == 50_000

    def test_stateless_no_change_address_zero_outputs(self):
        """Stateless call with no new_locking_script and no change address → 0 outputs (row 356)."""
        utxo = _make_utxo(100_000, 0)

        tx_hex, _, _ = build_call_transaction(
            current_utxo=utxo,
            unlocking_script='51',
            new_locking_script='',    # stateless — no contract output
            new_satoshis=0,
            change_address='',        # no change address
            change_script='',         # no change script
        )
        parsed = _parse_tx(tx_hex)

        # No contract output, no change output → 0 outputs total
        assert len(parsed['outputs']) == 0, (
            f"expected 0 outputs for stateless call with no change address, got {len(parsed['outputs'])}"
        )
