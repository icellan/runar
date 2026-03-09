"""
ConvergenceProof integration test -- stateless contract using EC point operations.

The contract verifies that R_A - R_B = deltaO * G on secp256k1, proving two
OPRF submissions share the same underlying token without revealing it.

We verify compilation, deployment, and spending (valid + invalid deltaO).
"""

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
    ec_mul_gen, encode_point, EC_N,
)
from runar.sdk import RunarContract, DeployOptions


def _generate_test_data():
    """Generate deterministic test data for ConvergenceProof."""
    a = 12345
    b = 6789
    delta_o = ((a - b) % EC_N + EC_N) % EC_N

    ra_x, ra_y = ec_mul_gen(a)
    rb_x, rb_y = ec_mul_gen(b)

    return {
        "rA": encode_point(ra_x, ra_y),
        "rB": encode_point(rb_x, rb_y),
        "deltaO": delta_o,
        "wrongDelta": ((a - b + 1) % EC_N + EC_N) % EC_N,
    }


class TestConvergenceProof:

    def test_compile(self):
        """Compile the ConvergenceProof contract."""
        artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts")
        assert artifact
        assert artifact.contract_name == "ConvergenceProof"

    def test_deploy(self):
        """Deploy with valid EC points."""
        artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts")
        test_data = _generate_test_data()

        contract = RunarContract(artifact, [test_data["rA"], test_data["rB"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert len(txid) == 64

    def test_spend_valid_delta(self):
        """Deploy and spend with valid deltaO."""
        artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts")
        test_data = _generate_test_data()

        contract = RunarContract(artifact, [test_data["rA"], test_data["rB"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        call_txid, _ = contract.call(
            "proveConvergence",
            [test_data["deltaO"]],
            provider, wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_spend_invalid_delta_rejected(self):
        """Invalid deltaO should be rejected."""
        artifact = compile_contract("examples/ts/convergence-proof/ConvergenceProof.runar.ts")
        test_data = _generate_test_data()

        contract = RunarContract(artifact, [test_data["rA"], test_data["rB"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        import pytest
        with pytest.raises(Exception):
            contract.call(
                "proveConvergence",
                [test_data["wrongDelta"]],
                provider, wallet["signer"],
            )
