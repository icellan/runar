from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "CovenantVault.runar.py"))
CovenantVault = contract_mod.CovenantVault

from runar import hash160, ALICE, BOB


# Native execution test for CovenantVault is limited because the
# covenant rule (hash256(output) == extract_output_hash(tx_preimage))
# requires a real sighash preimage with matching hashOutputs. The
# mock preimage doesn't produce a meaningful hashOutputs, so we only
# verify that the contract can be instantiated. The contract logic
# is fully verified by the TS test suite and conformance golden files.

def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "CovenantVault.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "CovenantVault.runar.py")
    c = CovenantVault(
        owner=ALICE.pub_key,
        recipient=hash160(BOB.pub_key),
        min_amount=1000,
    )
    # Contract construction succeeds — logic verified by conformance suite
    assert c.owner is not None
