"""Tests for runar.sdk.deployment — transaction construction for contract deployment."""

import pytest
from runar.sdk.deployment import (
    build_deploy_transaction, select_utxos, estimate_deploy_fee, build_p2pkh_script,
)
from runar.sdk.types import Utxo


def _make_utxo(satoshis: int, index: int = 0) -> Utxo:
    txid = f'{index:02x}' * 32
    return Utxo(txid=txid, output_index=0, satoshis=satoshis, script='76a914' + '00' * 20 + '88ac')


# ---------------------------------------------------------------------------
# build_deploy_transaction
# ---------------------------------------------------------------------------

class TestBuildDeployTransaction:
    def test_simple_deploy_returns_hex_and_input_count(self):
        """A single-UTXO deploy returns valid hex and correct input count."""
        utxo = _make_utxo(100_000)
        locking_script = '51'  # OP_TRUE
        tx_hex, input_count = build_deploy_transaction(
            locking_script=locking_script,
            utxos=[utxo],
            satoshis=10_000,
            change_address='00' * 20,
        )

        assert input_count == 1
        assert isinstance(tx_hex, str)
        assert len(tx_hex) > 0
        # Every character must be valid hex
        assert all(c in '0123456789abcdef' for c in tx_hex)
        # Starts with version 01000000
        assert tx_hex[:8] == '01000000'

    def test_multiple_utxos_all_consumed(self):
        """When multiple UTXOs are provided, they all appear as inputs."""
        utxos = [_make_utxo(30_000, i) for i in range(3)]
        tx_hex, input_count = build_deploy_transaction(
            locking_script='51',
            utxos=utxos,
            satoshis=10_000,
            change_address='00' * 20,
        )

        assert input_count == 3
        # After version (8 hex) comes varint input count
        assert tx_hex[8:10] == '03'

    def test_no_utxos_raises(self):
        """build_deploy_transaction rejects an empty UTXO list."""
        with pytest.raises(ValueError, match='no UTXOs'):
            build_deploy_transaction(
                locking_script='51',
                utxos=[],
                satoshis=10_000,
                change_address='00' * 20,
            )

    def test_insufficient_funds_raises(self):
        """Raises when the UTXO total cannot cover satoshis + fee."""
        utxo = _make_utxo(100)  # Way too small
        with pytest.raises(ValueError, match='insufficient funds'):
            build_deploy_transaction(
                locking_script='51',
                utxos=[utxo],
                satoshis=10_000,
                change_address='00' * 20,
            )


# ---------------------------------------------------------------------------
# select_utxos
# ---------------------------------------------------------------------------

class TestSelectUtxos:
    def test_largest_first_minimum_set(self):
        """select_utxos picks the fewest UTXOs needed, starting from the largest."""
        utxos = [
            _make_utxo(5_000, 0),
            _make_utxo(50_000, 1),
            _make_utxo(20_000, 2),
        ]
        selected = select_utxos(utxos, target_satoshis=10_000, locking_script_byte_len=1)

        # 50_000 alone is enough, so only 1 should be selected
        assert len(selected) == 1
        assert selected[0].satoshis == 50_000

    def test_multiple_needed(self):
        """When the largest is not enough, additional UTXOs are added."""
        utxos = [
            _make_utxo(3_000, 0),
            _make_utxo(4_000, 1),
            _make_utxo(5_000, 2),
        ]
        selected = select_utxos(utxos, target_satoshis=8_000, locking_script_byte_len=1)

        # 5k + 4k = 9k which should cover 8k + small fee
        assert len(selected) >= 2
        total = sum(u.satoshis for u in selected)
        assert total >= 8_000

    def test_returns_all_when_insufficient(self):
        """When all UTXOs combined are not enough, returns all of them."""
        utxos = [_make_utxo(100, i) for i in range(3)]
        selected = select_utxos(utxos, target_satoshis=1_000_000, locking_script_byte_len=1)
        assert len(selected) == 3


# ---------------------------------------------------------------------------
# estimate_deploy_fee
# ---------------------------------------------------------------------------

class TestEstimateDeployFee:
    def test_returns_positive_integer(self):
        fee = estimate_deploy_fee(num_inputs=1, locking_script_byte_len=25)
        assert isinstance(fee, int)
        assert fee > 0

    def test_more_inputs_higher_fee(self):
        fee1 = estimate_deploy_fee(num_inputs=1, locking_script_byte_len=25)
        fee3 = estimate_deploy_fee(num_inputs=3, locking_script_byte_len=25)
        assert fee3 > fee1

    def test_fee_rate_scales_fee(self):
        fee1 = estimate_deploy_fee(num_inputs=1, locking_script_byte_len=25, fee_rate=1000)
        fee2 = estimate_deploy_fee(num_inputs=1, locking_script_byte_len=25, fee_rate=2000)
        assert fee2 == fee1 * 2


# ---------------------------------------------------------------------------
# build_p2pkh_script
# ---------------------------------------------------------------------------

class TestDeployTransactionStructure:
    """Structural tests for deploy transaction wire format (rows 334, 335)."""

    def _parse_deploy_tx(self, tx_hex: str) -> dict:
        """Minimal parser: returns version, inputs, outputs, locktime."""
        import struct
        pos = 0

        def read_bytes(n):
            nonlocal pos
            r = tx_hex[pos:pos + n * 2]
            pos += n * 2
            return r

        def read_uint32_le():
            h = read_bytes(4)
            return struct.unpack('<I', bytes.fromhex(h))[0]

        def read_uint64_le():
            h = read_bytes(8)
            return struct.unpack('<Q', bytes.fromhex(h))[0]

        def read_varint():
            nonlocal pos
            first = int(tx_hex[pos:pos + 2], 16)
            pos += 2
            if first < 0xFD:
                return first
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
        return {'version': version, 'inputs': inputs, 'outputs': outputs, 'locktime': locktime}

    def test_deploy_locktime_is_zero(self):
        """Deploy transaction locktime is 0 (row 334)."""
        utxo = _make_utxo(100_000)
        tx_hex, _ = build_deploy_transaction(
            locking_script='51',
            utxos=[utxo],
            satoshis=10_000,
            change_address='00' * 20,
        )
        parsed = self._parse_deploy_tx(tx_hex)
        assert parsed['locktime'] == 0, f"expected locktime=0, got {parsed['locktime']}"

    def test_deploy_input_script_is_empty(self):
        """Unsigned deploy transaction has empty scriptSig for all inputs (row 335)."""
        utxo = _make_utxo(100_000)
        tx_hex, _ = build_deploy_transaction(
            locking_script='51',
            utxos=[utxo],
            satoshis=10_000,
            change_address='00' * 20,
        )
        parsed = self._parse_deploy_tx(tx_hex)
        assert len(parsed['inputs']) == 1
        assert parsed['inputs'][0]['script'] == '', (
            f"expected empty scriptSig for unsigned input, got '{parsed['inputs'][0]['script']}'"
        )

    def test_select_utxos_largest_first(self):
        """select_utxos picks the largest UTXO first (row 336)."""
        utxos = [
            _make_utxo(1_000, 0),
            _make_utxo(50_000, 1),
            _make_utxo(200_000, 2),
        ]
        selected = select_utxos(utxos, target_satoshis=10_000, locking_script_byte_len=1)
        # 200_000 alone is sufficient; only 1 UTXO should be selected
        assert len(selected) == 1
        assert selected[0].satoshis == 200_000, (
            f"expected largest UTXO (200000) selected first, got {selected[0].satoshis}"
        )


class TestBuildP2pkhScript:
    def test_hex_pubkey_hash(self):
        """40-char hex pubkey hash produces OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG."""
        pkh = 'aa' * 20
        script = build_p2pkh_script(pkh)
        assert script == '76a914' + pkh + '88ac'

    def test_output_is_50_hex_chars(self):
        """P2PKH script is always 25 bytes = 50 hex chars."""
        pkh = '00' * 20
        script = build_p2pkh_script(pkh)
        assert len(script) == 50

    def test_starts_and_ends_correctly(self):
        pkh = 'ff' * 20
        script = build_p2pkh_script(pkh)
        assert script.startswith('76a914')
        assert script.endswith('88ac')


# F-043: every SDK must accept the same inputs with the same result, using a
# real key: the secp256k1 generator G.
#
# PROVES: a compressed / uncompressed pubkey is hashed with HASH160 (values
# match Go BuildP2PKHScript and TS buildP2PKHScript); a Base58Check address has
# its SHA256d checksum verified (the Genesis address with its last character
# flipped still decodes to 25 bytes and must raise) and its version byte
# checked (P2SH 0x05 refused, testnet 0x6f accepted); a non-Base58 character
# raises ValueError.
# DOES NOT PROVE: that a pubkey is a valid curve point (no SDK checks it).
_G_PUB = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
_G_PUB_UNCOMPRESSED = (
    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
)
_G_PKH = '751e76e8199196d454941c45d1b3a323f1433bd6'


class TestBuildP2pkhScriptF043:
    def test_pubkey_hash_and_pubkeys(self):
        assert build_p2pkh_script(_G_PKH) == '76a914' + _G_PKH + '88ac'
        assert build_p2pkh_script(_G_PUB) == '76a914' + _G_PKH + '88ac'
        assert build_p2pkh_script(_G_PUB_UNCOMPRESSED) == (
            '76a91491b24bf9f5288532960ac687abb035127b1d28a588ac'
        )

    def test_addresses(self):
        assert build_p2pkh_script('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH') == '76a914' + _G_PKH + '88ac'
        assert build_p2pkh_script('mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r') == '76a914' + _G_PKH + '88ac'
        assert build_p2pkh_script('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') == (
            '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac'
        )

    def test_flipped_last_char_bad_checksum_raises(self):
        with pytest.raises(ValueError, match='checksum'):
            build_p2pkh_script('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb')

    def test_p2sh_version_raises(self):
        with pytest.raises(ValueError, match='version byte'):
            build_p2pkh_script('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')

    def test_invalid_char_and_length_raise(self):
        with pytest.raises(ValueError, match='invalid Base58 character'):
            build_p2pkh_script('1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a')
        with pytest.raises(ValueError, match='invalid address length'):
            build_p2pkh_script('1Badx')
