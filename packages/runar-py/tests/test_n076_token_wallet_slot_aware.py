"""N-076: ``TokenWallet.get_utxos`` must discover a deployed token contract with
the slot-aware matcher (``matches_artifact``), not a raw prefix of the template.

The template carries a constructor slot, a codeSepIndex slot (baked as OP_1)
and a ``code_part_len_slots`` field (the deployed code-part length), none of
which a literal prefix of the template can equal.

Proves: a deployed instance of such a template (with a state section) is found,
while scripts that share the pre-slot prefix but differ after it, carry a wrong
code-part length, or are unrelated are not.
Does NOT prove: on-chain spendability of the matched UTXO, nor that an artifact
with only codeSepIndex slots (no constructor slots) is matched --
``matches_artifact`` itself compares such a template literally.
"""

from __future__ import annotations

from runar.sdk.provider import MockProvider
from runar.sdk.signer import MockSigner
from runar.sdk.token_wallet import TokenWallet
from runar.sdk.types import (
    CodePartLenSlot,
    CodeSepIndexSlot,
    ConstructorSlot,
    RunarArtifact,
    StateField,
    Utxo,
)

# bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
#   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
ARTIFACT = RunarArtifact(
    contract_name='FungibleToken',
    script='76a9' + '00' + '88' + '00' + '75' + '04' + '00000000' + 'ac',
    state_fields=[StateField(name='balance', type='bigint', index=1)],
    constructor_slots=[ConstructorSlot(param_index=0, byte_offset=2)],
    code_sep_index_slots=[CodeSepIndexSlot(byte_offset=4, code_sep_index=0)],
    code_part_len_slots=[CodePartLenSlot(byte_offset=7)],
)


def deployed(tail: str = 'ac', length: str = '0e000000') -> str:
    # supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes.
    return '76a9' + '02aabb' + '88' + '51' + '75' + '04' + length + tail + '6a' + '0100'


def discover(*scripts: str) -> list[str]:
    provider = MockProvider()
    signer = MockSigner()
    addr = signer.get_address()
    for i, script in enumerate(scripts):
        provider.add_utxo(addr, Utxo(txid=str(i) * 64, output_index=0, satoshis=1000, script=script))
    return [u.txid[0] for u in TokenWallet(ARTIFACT, provider, signer).get_utxos()]


def test_finds_a_deployed_slotted_instance():
    assert discover(deployed()) == ['0']


def test_rejects_scripts_that_only_share_the_prefix():
    assert discover(deployed('ad')) == [], 'differs after the slots'
    assert discover(deployed('ac', '0f000000')) == [], 'wrong code-part length'
    assert discover('76a914' + '11' * 20 + '88ac') == [], 'unrelated script'
