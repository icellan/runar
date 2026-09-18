"""N-043 — an ordinals inscription must not break the code-part length pin.

A stateful contract with a variable-length state section carries an EQUALITY pin
on the deployed code-part length, emitted as a fixed-width nine-byte run::

    76 | 04 LL LL LL LL | 81 | (9c | a2) | 69
    OP_DUP  <len LE32>    OP_BIN2NUM  cmp  OP_VERIFY

``_get_code_part_hex`` concatenates the inscription envelope INTO the code part,
so attaching one makes the real code part longer than the pinned number and every
honest spend aborts at OP_VERIFY with the funds already committed.

Each template below is a 10-byte script — ``OP_1`` followed by the nine-byte pin
run — except the unpinned one. The inscription is a two-byte ``text/plain``
payload whose envelope is exactly 23 bytes, so an inscribed code part is
10 + 23 = 33 bytes.
"""

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.ordinals import Inscription
from runar.sdk.types import RunarArtifact


# Exact pin of 10: correct WITHOUT an envelope, violated by one. Refuse.
PIN_TEMPLATE_EXACT_10 = '5176040a000000819c69'
# Exact pin of 33 (0x21): correct WITH the envelope attached. Accept — and a
# decoder that reads the length big-endian gets 0x21000000 here and wrongly
# refuses.
PIN_TEMPLATE_EXACT_33 = '51760421000000819c69'
# LOWER-BOUND pin (a2 = OP_GREATERTHANOREQUAL) of 10: extra bytes satisfy it, so
# it must never trigger a refusal.
PIN_TEMPLATE_LOWER_BOUND_10 = '5176040a00000081a269'
# No pin at all (a bare P2PKH template). Accept.
PIN_TEMPLATE_NONE = '76a90088ac'


def pin_fixture_contract(script: str) -> RunarContract:
    artifact = RunarArtifact.from_dict({
        'version': 'runar-v1.0.0-rc.1',
        'compilerVersion': '1.0.0-rc.1',
        'contractName': 'PinFixture',
        'parentClass': 'StatefulSmartContract',
        'abi': {
            'constructor': {'params': [{'name': 'memo', 'type': 'ByteString'}]},
            'methods': [
                {
                    'name': 'post',
                    'params': [{'name': 'newMemo', 'type': 'ByteString'}],
                    'isPublic': True,
                },
            ],
        },
        'script': script,
        'stateFields': [
            {
                'name': 'memo',
                'type': 'ByteString',
                'index': 0,
                'encoding': 'pushdata',
                'byteOffset': 0,
            },
        ],
    })
    return RunarContract(artifact, ['48656c6c6f'])


def pin_fixture_inscription() -> Inscription:
    return Inscription(content_type='text/plain', data='6869')


def test_with_inscription_refuses_when_envelope_breaks_exact_pin():
    contract = pin_fixture_contract(PIN_TEMPLATE_EXACT_10)

    with pytest.raises(ValueError) as excinfo:
        contract.with_inscription(pin_fixture_inscription())

    # Assert the REASON, not merely that something failed: a test that accepts
    # any error passes when an unrelated one fires.
    msg = str(excinfo.value)
    for want in ('pins SIZE(_codePart) == 10', 'code part is 33 bytes', 'inscription'):
        assert want in msg, f'refusal message missing {want!r}:\n  {msg}'

    # The contract must be left un-inscribed rather than half-mutated.
    assert contract.inscription is None
    assert len(contract._get_code_part_hex()) // 2 == 10


def test_with_inscription_accepts_when_exact_pin_matches_inscribed_length():
    """Control: a pin that already accounts for the envelope is honoured.

    Also pins the little-endian decode — a big-endian reader sees 0x21000000.
    """
    contract = pin_fixture_contract(PIN_TEMPLATE_EXACT_33)

    result = contract.with_inscription(pin_fixture_inscription())

    assert result is contract
    assert contract.inscription is not None
    assert len(contract._get_code_part_hex()) // 2 == 33


def test_with_inscription_accepts_lower_bound_pin():
    """Control 1 (mandatory): a LOWER-BOUND pin is satisfied by the extra bytes.

    Guarding ``a2`` would turn this fix into an outage for every lower-bound
    contract.
    """
    contract = pin_fixture_contract(PIN_TEMPLATE_LOWER_BOUND_10)

    contract.with_inscription(pin_fixture_inscription())

    assert contract.inscription is not None


def test_with_inscription_accepts_unpinned_contract():
    """Control 2 (mandatory): no pin at all (stateless, or fixed-size state)."""
    contract = pin_fixture_contract(PIN_TEMPLATE_NONE)

    contract.with_inscription(pin_fixture_inscription())

    assert contract.inscription is not None
