"""Tests for 1sat ordinals support: envelope build/parse, BSV-20/BSV-21, contract integration."""

import json
import pytest

from runar.sdk.ordinals import (
    Inscription,
    EnvelopeBounds,
    build_inscription_envelope,
    parse_inscription_envelope,
    find_inscription_envelope,
    strip_inscription_envelope,
    bsv20_deploy,
    bsv20_mint,
    bsv20_transfer,
    bsv21_deploy_mint,
    bsv21_transfer,
)
from runar.sdk.contract import RunarContract
from runar.sdk.state import find_last_op_return
from runar.sdk.types import (
    RunarArtifact,
    Abi,
    AbiMethod,
    AbiParam,
    StateField,
    ConstructorSlot,
    Utxo,
)


def utf8_to_hex(s: str) -> str:
    return s.encode('utf-8').hex()


def hex_to_utf8(h: str) -> str:
    return bytes.fromhex(h).decode('utf-8')


# ---------------------------------------------------------------------------
# Envelope build/parse
# ---------------------------------------------------------------------------

class TestBuildInscriptionEnvelope:
    def test_builds_text_inscription_envelope(self):
        content_type = 'text/plain'
        data = utf8_to_hex('Hello, ordinals!')
        envelope = build_inscription_envelope(content_type, data)

        # Starts with OP_FALSE OP_IF PUSH3 "ord" OP_1
        assert envelope.startswith('006303' + '6f7264' + '51')
        # Ends with OP_ENDIF
        assert envelope.endswith('68')
        # Contains content type
        assert utf8_to_hex(content_type) in envelope
        # Contains data
        assert data in envelope

    def test_large_data_op_pushdata2(self):
        content_type = 'image/png'
        # 300 bytes of data triggers OP_PUSHDATA2 (> 255 bytes)
        data = 'ff' * 300
        envelope = build_inscription_envelope(content_type, data)

        # Should contain OP_PUSHDATA2 (4d) for the data push
        # 300 bytes = 0x012c LE = 2c01
        assert '4d' + '2c01' + data in envelope
        # Still valid envelope
        assert envelope.startswith('006303' + '6f7264' + '51')
        assert envelope.endswith('68')

    def test_medium_data_op_pushdata1(self):
        # 100 bytes triggers OP_PUSHDATA1 (> 75 bytes, <= 255)
        data = 'ab' * 100
        envelope = build_inscription_envelope('application/octet-stream', data)

        # Should contain OP_PUSHDATA1 (4c) for the data push: 100 = 0x64
        assert '4c' + '64' + data in envelope

    def test_empty_data_op_0(self):
        envelope = build_inscription_envelope('text/plain', '')
        # Data push is OP_0 (00)
        # Pattern: ... OP_0(delimiter) OP_0(data) OP_ENDIF
        assert envelope.endswith('000068')


class TestParseInscriptionEnvelope:
    def test_round_trip_text(self):
        original = Inscription(content_type='text/plain', data=utf8_to_hex('Hello!'))
        envelope = build_inscription_envelope(original.content_type, original.data)
        parsed = parse_inscription_envelope(envelope)

        assert parsed is not None
        assert parsed.content_type == 'text/plain'
        assert parsed.data == original.data

    def test_round_trip_bsv20_json(self):
        json_str = json.dumps({'p': 'bsv-20', 'op': 'deploy', 'tick': 'TEST', 'max': '21000000'})
        original = Inscription(content_type='application/bsv-20', data=utf8_to_hex(json_str))
        envelope = build_inscription_envelope(original.content_type, original.data)
        parsed = parse_inscription_envelope(envelope)

        assert parsed is not None
        assert parsed.content_type == 'application/bsv-20'
        assert parsed.data == original.data

    def test_round_trip_large_data_pushdata2(self):
        data = 'ff' * 300
        original = Inscription(content_type='image/png', data=data)
        envelope = build_inscription_envelope(original.content_type, original.data)
        parsed = parse_inscription_envelope(envelope)

        assert parsed is not None
        assert parsed.content_type == 'image/png'
        assert parsed.data == data

    def test_returns_none_for_no_envelope(self):
        script = 'a914' + '00' * 20 + '87'  # P2SH-like
        assert parse_inscription_envelope(script) is None

    def test_parses_embedded_envelope(self):
        prefix = 'a914' + '00' * 20 + '8788ac'  # some contract code
        data = utf8_to_hex('test')
        envelope = build_inscription_envelope('text/plain', data)
        suffix = '6a' + '08' + '00' * 8  # OP_RETURN + state

        full_script = prefix + envelope + suffix
        parsed = parse_inscription_envelope(full_script)

        assert parsed is not None
        assert parsed.content_type == 'text/plain'
        assert parsed.data == data


class TestFindInscriptionEnvelope:
    def test_finds_bounds(self):
        prefix = 'aabb'
        envelope = build_inscription_envelope('text/plain', utf8_to_hex('hi'))
        suffix = 'ccdd'

        script = prefix + envelope + suffix
        bounds = find_inscription_envelope(script)

        assert bounds is not None
        assert bounds.start_hex == len(prefix)
        assert bounds.end_hex == len(prefix) + len(envelope)

    def test_returns_none_no_envelope(self):
        assert find_inscription_envelope('76a914' + '00' * 20 + '88ac') is None

    def test_finds_between_code_and_op_return(self):
        code = '76a914' + '00' * 20 + '88ac'
        envelope = build_inscription_envelope('text/plain', utf8_to_hex('ord'))
        state = '6a' + '08' + '0000000000000000'

        full_script = code + envelope + state
        bounds = find_inscription_envelope(full_script)

        assert bounds is not None
        assert bounds.start_hex == len(code)
        assert bounds.end_hex == len(code) + len(envelope)


class TestStripInscriptionEnvelope:
    def test_removes_envelope(self):
        prefix = 'aabb'
        envelope = build_inscription_envelope('text/plain', utf8_to_hex('hi'))
        suffix = 'ccdd'

        stripped = strip_inscription_envelope(prefix + envelope + suffix)
        assert stripped == prefix + suffix

    def test_returns_unchanged_if_no_envelope(self):
        script = '76a914' + '00' * 20 + '88ac'
        assert strip_inscription_envelope(script) == script


# ---------------------------------------------------------------------------
# BSV-20 / BSV-21
# ---------------------------------------------------------------------------

class TestBSV20:
    def test_deploy(self):
        inscription = bsv20_deploy('RUNAR', '21000000', lim='1000')
        assert inscription.content_type == 'application/bsv-20'
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'deploy',
            'tick': 'RUNAR',
            'max': '21000000',
            'lim': '1000',
        }

    def test_deploy_without_optional_fields(self):
        inscription = bsv20_deploy('TEST', '1000')
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'deploy',
            'tick': 'TEST',
            'max': '1000',
        }
        assert 'lim' not in data
        assert 'dec' not in data

    def test_deploy_with_decimals(self):
        inscription = bsv20_deploy('USDT', '100000000', dec='8')
        data = json.loads(hex_to_utf8(inscription.data))
        assert data['dec'] == '8'

    def test_mint(self):
        inscription = bsv20_mint('RUNAR', '1000')
        assert inscription.content_type == 'application/bsv-20'
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'mint',
            'tick': 'RUNAR',
            'amt': '1000',
        }

    def test_transfer(self):
        inscription = bsv20_transfer('RUNAR', '50')
        assert inscription.content_type == 'application/bsv-20'
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'transfer',
            'tick': 'RUNAR',
            'amt': '50',
        }


class TestBSV21:
    def test_deploy_mint(self):
        inscription = bsv21_deploy_mint('1000000', dec='18', sym='RNR')
        assert inscription.content_type == 'application/bsv-20'
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'deploy+mint',
            'amt': '1000000',
            'dec': '18',
            'sym': 'RNR',
        }

    def test_deploy_mint_without_optional_fields(self):
        inscription = bsv21_deploy_mint('500')
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'deploy+mint',
            'amt': '500',
        }
        assert 'dec' not in data
        assert 'sym' not in data

    def test_transfer(self):
        inscription = bsv21_transfer(
            '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
            '100',
        )
        assert inscription.content_type == 'application/bsv-20'
        data = json.loads(hex_to_utf8(inscription.data))
        assert data == {
            'p': 'bsv-20',
            'op': 'transfer',
            'id': '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1',
            'amt': '100',
        }


# ---------------------------------------------------------------------------
# Contract integration
# ---------------------------------------------------------------------------

# Minimal P2PKH artifact (stateless)
p2pkh_artifact = RunarArtifact(
    version='runar-v0.1.0',
    compiler_version='0.4.4',
    contract_name='P2PKH',
    abi=Abi(
        constructor_params=[AbiParam(name='pubKeyHash', type='Addr')],
        methods=[
            AbiMethod(
                name='unlock',
                params=[
                    AbiParam(name='sig', type='Sig'),
                    AbiParam(name='pubKey', type='PubKey'),
                ],
                is_public=True,
            ),
        ],
    ),
    script='a9007c7c9c69007c7cac69',
    asm='OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY OP_0 OP_SWAP OP_SWAP OP_CHECKSIG OP_VERIFY',
    constructor_slots=[
        ConstructorSlot(param_index=0, byte_offset=1),
        ConstructorSlot(param_index=0, byte_offset=6),
    ],
)

# Minimal Counter artifact (stateful)
counter_artifact = RunarArtifact(
    version='runar-v0.1.0',
    compiler_version='0.4.4',
    contract_name='Counter',
    abi=Abi(
        constructor_params=[AbiParam(name='count', type='bigint')],
        methods=[
            AbiMethod(
                name='increment',
                params=[
                    AbiParam(name='_changePKH', type='Addr'),
                    AbiParam(name='_changeAmount', type='bigint'),
                    AbiParam(name='txPreimage', type='SigHashPreimage'),
                ],
                is_public=True,
            ),
        ],
    ),
    # Fake minimal script -- just enough to test envelope splicing
    script='aabbccdd',
    asm='OP_NOP',
    state_fields=[
        StateField(name='count', type='bigint', index=0),
    ],
)


class TestRunarContractStatelessInscription:
    def test_get_locking_script_includes_envelope(self):
        pub_key_hash = '00' * 20
        contract = RunarContract(p2pkh_artifact, [pub_key_hash])
        contract.with_inscription(Inscription(
            content_type='text/plain',
            data=utf8_to_hex('Hello!'),
        ))

        locking_script = contract.get_locking_script()

        # The locking script should end with the inscription envelope
        envelope = build_inscription_envelope('text/plain', utf8_to_hex('Hello!'))
        assert locking_script.endswith(envelope)

        # Should be parseable
        parsed = parse_inscription_envelope(locking_script)
        assert parsed is not None
        assert parsed.content_type == 'text/plain'
        assert parsed.data == utf8_to_hex('Hello!')

    def test_get_locking_script_without_inscription_unchanged(self):
        pub_key_hash = '00' * 20
        contract_a = RunarContract(p2pkh_artifact, [pub_key_hash])
        contract_b = RunarContract(p2pkh_artifact, [pub_key_hash])

        assert contract_a.get_locking_script() == contract_b.get_locking_script()

    def test_with_inscription_returns_self_for_chaining(self):
        contract = RunarContract(p2pkh_artifact, ['00' * 20])
        result = contract.with_inscription(Inscription(content_type='text/plain', data=''))
        assert result is contract

    def test_inscription_getter(self):
        contract = RunarContract(p2pkh_artifact, ['00' * 20])
        assert contract.inscription is None
        contract.with_inscription(Inscription(content_type='image/png', data='ff00ff'))
        assert contract.inscription == Inscription(content_type='image/png', data='ff00ff')


class TestRunarContractStatefulInscription:
    def test_envelope_between_code_and_op_return(self):
        contract = RunarContract(counter_artifact, [0])
        contract.with_inscription(Inscription(
            content_type='application/bsv-20',
            data=utf8_to_hex('{"p":"bsv-20","op":"deploy","tick":"TEST","max":"1000"}'),
        ))

        locking_script = contract.get_locking_script()
        envelope = build_inscription_envelope(
            'application/bsv-20',
            utf8_to_hex('{"p":"bsv-20","op":"deploy","tick":"TEST","max":"1000"}'),
        )

        # Script structure: code + envelope + OP_RETURN + state
        code_end = locking_script.index(envelope)
        assert code_end > 0  # envelope follows code

        after_envelope = locking_script[code_end + len(envelope):]
        assert after_envelope.startswith('6a')  # OP_RETURN follows envelope

    def test_find_last_op_return_skips_envelope(self):
        contract = RunarContract(counter_artifact, [42])
        contract.with_inscription(Inscription(
            content_type='text/plain',
            data=utf8_to_hex('test'),
        ))

        locking_script = contract.get_locking_script()
        op_return_pos = find_last_op_return(locking_script)

        assert op_return_pos > 0
        # Everything before OP_RETURN should include both the code and the envelope
        code_part = locking_script[:op_return_pos]
        assert 'aabbccdd' in code_part  # original code
        assert find_inscription_envelope(code_part) is not None  # envelope present


class TestFromUtxoWithInscription:
    def test_detects_inscription_stateless(self):
        pub_key_hash = '00' * 20
        original = RunarContract(p2pkh_artifact, [pub_key_hash])
        original.with_inscription(Inscription(
            content_type='image/png',
            data='deadbeef',
        ))

        locking_script = original.get_locking_script()
        reconnected = RunarContract.from_utxo(p2pkh_artifact, Utxo(
            txid='00' * 32,
            output_index=0,
            satoshis=1,
            script=locking_script,
        ))

        assert reconnected.inscription is not None
        assert reconnected.inscription.content_type == 'image/png'
        assert reconnected.inscription.data == 'deadbeef'

    def test_detects_inscription_and_state_stateful(self):
        original = RunarContract(counter_artifact, [7])
        original.with_inscription(Inscription(
            content_type='text/plain',
            data=utf8_to_hex('my counter'),
        ))

        locking_script = original.get_locking_script()
        reconnected = RunarContract.from_utxo(counter_artifact, Utxo(
            txid='00' * 32,
            output_index=0,
            satoshis=1,
            script=locking_script,
        ))

        # Inscription round-trips
        assert reconnected.inscription is not None
        assert reconnected.inscription.content_type == 'text/plain'
        assert reconnected.inscription.data == utf8_to_hex('my counter')

        # State round-trips
        assert reconnected.get_state()['count'] == 7

    def test_identical_locking_script_on_reconnect(self):
        original = RunarContract(counter_artifact, [99])
        original.with_inscription(Inscription(
            content_type='text/plain',
            data=utf8_to_hex('persisted'),
        ))

        locking_script = original.get_locking_script()
        reconnected = RunarContract.from_utxo(counter_artifact, Utxo(
            txid='00' * 32,
            output_index=0,
            satoshis=1,
            script=locking_script,
        ))

        # Reconnected contract should produce the same locking script
        assert reconnected.get_locking_script() == locking_script

    def test_from_utxo_no_inscription(self):
        contract = RunarContract(p2pkh_artifact, ['00' * 20])
        locking_script = contract.get_locking_script()

        reconnected = RunarContract.from_utxo(p2pkh_artifact, Utxo(
            txid='00' * 32,
            output_index=0,
            satoshis=1,
            script=locking_script,
        ))

        assert reconnected.inscription is None


class TestBSV20ContractIntegration:
    def test_deploy_p2pkh_with_bsv20(self):
        inscription = bsv20_deploy('RUNAR', '21000000')
        contract = RunarContract(p2pkh_artifact, ['00' * 20])
        contract.with_inscription(inscription)

        locking_script = contract.get_locking_script()
        parsed = parse_inscription_envelope(locking_script)

        assert parsed is not None
        assert parsed.content_type == 'application/bsv-20'

        # Verify the JSON content
        data = json.loads(hex_to_utf8(parsed.data))
        assert data['p'] == 'bsv-20'
        assert data['op'] == 'deploy'
        assert data['tick'] == 'RUNAR'


# ---------------------------------------------------------------------------
# Cross-check: Python envelope hex matches TypeScript byte-for-byte
# ---------------------------------------------------------------------------

class TestEnvelopeHexParity:
    """Verify that Python produces byte-for-byte identical envelope hex
    as the TypeScript implementation for known inputs."""

    def test_text_plain_hello(self):
        # Expected from TypeScript: build('text/plain', utf8ToHex('Hello!'))
        # OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) OP_1(51)
        # PUSH10 "text/plain"(0a 746578742f706c61696e)
        # OP_0(00)
        # PUSH6 "Hello!"(06 48656c6c6f21)
        # OP_ENDIF(68)
        expected = (
            '006303' + '6f7264' + '51'
            + '0a' + '746578742f706c61696e'
            + '00'
            + '06' + '48656c6c6f21'
            + '68'
        )
        actual = build_inscription_envelope('text/plain', utf8_to_hex('Hello!'))
        assert actual == expected

    def test_empty_data(self):
        expected = (
            '006303' + '6f7264' + '51'
            + '0a' + '746578742f706c61696e'
            + '00'
            + '00'  # OP_0 for empty data
            + '68'
        )
        actual = build_inscription_envelope('text/plain', '')
        assert actual == expected
