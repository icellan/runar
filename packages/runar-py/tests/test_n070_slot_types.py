"""N-070 (extract half) -- ``_interpret_script_element`` must know every ABI
type spelling the compiler can emit.

Two holes, identical in shape across all seven SDK tiers:

  RabinSig / RabinPubKey -- ``bigint`` ALIASES (runar-lang/src/types.ts:68-71)
    that ``verifyRabinSig`` consumes with OP_MOD, i.e. as a Script NUMBER.
    Absent from the branch list, so a restored contract's modulus came back as
    the little-endian hex blob ``'1581e97df4102211'`` instead of the number.
    Feed that back into a call and the rebuilt locking script no longer matches
    what is on chain.

  boolean -- the CANONICAL Runar primitive name; only the alias ``bool`` was
    handled. A boolean slot fell through to the byte branch, so ``True`` came
    back as the string ``'01'`` and ``False`` as ``''``. Java's ContractScript
    was the only tier of seven that tested both spellings.
"""

import pytest

from runar.sdk.script_utils import extract_constructor_args
from runar.sdk.types import Abi, AbiParam, ConstructorSlot, RunarArtifact

MODULUS = 1234567890123456789
RABIN_PUSH = '081581e97df4102211'  # minimal LE sign-magnitude, 8 bytes
BLOB = '04deadbeef'


def artifact(rabin_type: str, bool_type: str) -> RunarArtifact:
    """Template: ``<modulus@0> 7c <flag@2> 7c <blob@4> ac``."""
    return RunarArtifact(
        script='00' + '7c' + '00' + '7c' + '00' + 'ac',
        abi=Abi(constructor_params=[
            AbiParam(name='modulus', type=rabin_type),
            AbiParam(name='flag', type=bool_type),
            AbiParam(name='blob', type='ByteString'),
        ]),
        constructor_slots=[
            ConstructorSlot(param_index=0, byte_offset=0),
            ConstructorSlot(param_index=1, byte_offset=2),
            ConstructorSlot(param_index=2, byte_offset=4),
        ],
    )


def script(flag_opcode: str) -> str:
    return RABIN_PUSH + '7c' + flag_opcode + '7c' + BLOB + 'ac'


@pytest.mark.parametrize('type_name', ['RabinPubKey', 'RabinSig'])
def test_rabin_slots_extract_as_numbers(type_name):
    args = extract_constructor_args(artifact(type_name, 'boolean'), script('51'))
    assert args['modulus'] == MODULUS
    assert isinstance(args['modulus'], int) and not isinstance(args['modulus'], bool)


@pytest.mark.parametrize(('opcode', 'want'), [('51', True), ('00', False)])
def test_canonical_boolean_slot_extracts_as_bool(opcode, want):
    args = extract_constructor_args(artifact('RabinPubKey', 'boolean'), script(opcode))
    assert args['flag'] is want


@pytest.mark.parametrize('opcode', ['51', '00'])
def test_boolean_and_bool_spellings_agree(opcode):
    canonical = extract_constructor_args(artifact('RabinPubKey', 'boolean'), script(opcode))
    alias = extract_constructor_args(artifact('RabinPubKey', 'bool'), script(opcode))
    assert canonical['flag'] is alias['flag']


# -- CONTROLS: the classes that already worked must not move. ---------------

@pytest.mark.parametrize('type_name', ['bigint', 'int'])
def test_control_numeric_spellings_unchanged(type_name):
    args = extract_constructor_args(artifact(type_name, 'bool'), script('51'))
    assert args['modulus'] == MODULUS


def test_control_bytestring_unchanged():
    # A ByteString slot still comes back as its hex payload, NOT a number, and
    # the offset walk past the wide Rabin push still lands on it.
    args = extract_constructor_args(artifact('RabinPubKey', 'boolean'), script('51'))
    assert args['blob'] == 'deadbeef'
    # S1: a 1-byte ByteString MINIMALDATA-encoded as OP_5 is still
    # reconstructed from the opcode.
    s1 = extract_constructor_args(
        artifact('RabinPubKey', 'boolean'), RABIN_PUSH + '7c' + '51' + '7c' + '55' + 'ac'
    )
    assert s1['blob'] == '05'
