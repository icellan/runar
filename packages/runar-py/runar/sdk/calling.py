"""Transaction construction for method invocation."""

from __future__ import annotations
from runar.sdk.types import Utxo
from runar.sdk.deployment import (
    _to_le32, _to_le64, _encode_varint, _reverse_hex,
    _varint_byte_size, build_p2pkh_script,
)


def build_call_transaction(
    current_utxo: Utxo,
    unlocking_script: str,
    new_locking_script: str,
    new_satoshis: int,
    change_address: str,
    change_script: str = '',
    additional_utxos: list[Utxo] | None = None,
    fee_rate: int = 100,
    contract_outputs: list[dict] | None = None,
    additional_contract_inputs: list[dict] | None = None,
) -> tuple[str, int, int]:
    """Build a raw transaction that spends a contract UTXO.

    contract_outputs: list of {"script": str, "satoshis": int} for multi-output.
    additional_contract_inputs: list of {"utxo": Utxo, "unlocking_script": str}
        for additional contract inputs (e.g. merge).

    Returns (tx_hex, input_count, change_amount).
    """
    extra_contract_inputs = additional_contract_inputs or []
    additional = additional_utxos or []
    all_utxos = (
        [current_utxo]
        + [ci['utxo'] for ci in extra_contract_inputs]
        + additional
    )

    total_input = sum(u.satoshis for u in all_utxos)

    # Determine contract outputs: multi-output takes priority over single
    resolved_contract_outputs: list[dict] = []
    if contract_outputs:
        resolved_contract_outputs = contract_outputs
    elif new_locking_script:
        sats = new_satoshis if new_satoshis > 0 else current_utxo.satoshis
        resolved_contract_outputs = [{'script': new_locking_script, 'satoshis': sats}]

    contract_output_sats = sum(co['satoshis'] for co in resolved_contract_outputs)

    # Estimate fee using actual script sizes
    input0_size = (
        32 + 4 +
        _varint_byte_size(len(unlocking_script) // 2) +
        len(unlocking_script) // 2 +
        4
    )
    extra_contract_inputs_size = 0
    for ci in extra_contract_inputs:
        ci_script = ci['unlocking_script']
        extra_contract_inputs_size += (
            32 + 4 +
            _varint_byte_size(len(ci_script) // 2) +
            len(ci_script) // 2 +
            4
        )
    additional_inputs_size = len(additional) * 148  # P2PKH
    inputs_size = input0_size + extra_contract_inputs_size + additional_inputs_size

    outputs_size = 0
    for co in resolved_contract_outputs:
        s = co['script']
        outputs_size += 8 + _varint_byte_size(len(s) // 2) + len(s) // 2
    if change_address or change_script:
        outputs_size += 34  # P2PKH change

    estimated_size = 10 + inputs_size + outputs_size
    rate = max(1, fee_rate)
    fee = (estimated_size * rate + 999) // 1000

    change = total_input - contract_output_sats - fee

    # Build raw transaction
    tx = ''
    tx += _to_le32(1)  # version
    tx += _encode_varint(len(all_utxos))

    # Input 0: contract UTXO with unlocking script
    tx += _reverse_hex(current_utxo.txid)
    tx += _to_le32(current_utxo.output_index)
    tx += _encode_varint(len(unlocking_script) // 2)
    tx += unlocking_script
    tx += 'ffffffff'

    # Additional contract inputs (with their own unlocking scripts)
    for ci in extra_contract_inputs:
        ci_utxo = ci['utxo']
        ci_script = ci['unlocking_script']
        tx += _reverse_hex(ci_utxo.txid)
        tx += _to_le32(ci_utxo.output_index)
        tx += _encode_varint(len(ci_script) // 2)
        tx += ci_script
        tx += 'ffffffff'

    # P2PKH funding inputs (unsigned)
    for utxo in additional:
        tx += _reverse_hex(utxo.txid)
        tx += _to_le32(utxo.output_index)
        tx += '00'
        tx += 'ffffffff'

    # Outputs
    num_outputs = len(resolved_contract_outputs)
    if change > 0 and (change_address or change_script):
        num_outputs += 1
    tx += _encode_varint(num_outputs)

    # Contract outputs
    for co in resolved_contract_outputs:
        tx += _to_le64(co['satoshis'])
        s = co['script']
        tx += _encode_varint(len(s) // 2)
        tx += s

    # Change output
    if change > 0 and (change_address or change_script):
        actual_change_script = change_script or build_p2pkh_script(change_address)
        tx += _to_le64(change)
        tx += _encode_varint(len(actual_change_script) // 2)
        tx += actual_change_script

    # Locktime
    tx += _to_le32(0)

    return tx, len(all_utxos), change if change > 0 else 0


def insert_unlocking_script(tx_hex: str, input_index: int, unlock_script: str) -> str:
    """Replace the scriptSig of a specific input with the given unlocking script."""
    pos = 0

    # Skip version (4 bytes = 8 hex chars)
    pos += 8

    # Read input count
    input_count, ic_len = _read_varint_hex(tx_hex, pos)
    pos += ic_len

    if input_index >= input_count:
        raise ValueError(
            f"insert_unlocking_script: input index {input_index} out of range ({input_count} inputs)"
        )

    for i in range(input_count):
        # Skip prevTxid (32 bytes = 64 hex chars)
        pos += 64
        # Skip prevOutputIndex (4 bytes = 8 hex chars)
        pos += 8

        # Read scriptSig length
        script_len, sl_len = _read_varint_hex(tx_hex, pos)

        if i == input_index:
            new_script_byte_len = len(unlock_script) // 2
            new_varint = _encode_varint(new_script_byte_len)
            before = tx_hex[:pos]
            after = tx_hex[pos + sl_len + script_len * 2:]
            return before + new_varint + unlock_script + after

        # Skip scriptSig + sequence
        pos += sl_len + script_len * 2 + 8

    raise ValueError(f"insert_unlocking_script: input index {input_index} out of range")


def _read_varint_hex(hex_str: str, pos: int) -> tuple[int, int]:
    """Read a Bitcoin varint from hex. Returns (value, hex_chars_consumed)."""
    first = int(hex_str[pos:pos + 2], 16)
    if first < 0xFD:
        return first, 2
    if first == 0xFD:
        lo = int(hex_str[pos + 2:pos + 4], 16)
        hi = int(hex_str[pos + 4:pos + 6], 16)
        return lo | (hi << 8), 6
    if first == 0xFE:
        b = bytes.fromhex(hex_str[pos + 2:pos + 10])
        return int.from_bytes(b, 'little'), 10
    # 0xFF
    b = bytes.fromhex(hex_str[pos + 2:pos + 18])
    return int.from_bytes(b, 'little'), 18
