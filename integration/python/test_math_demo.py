"""
MathDemo integration test -- stateful contract exercising built-in math functions.

MathDemo is a StatefulSmartContract with a single mutable property `value`.
Methods: divideBy(n), clampValue(lo, hi), squareRoot(), exponentiate(n),
         reduceGcd(n), computeLog2(), scaleByRatio(num, den).
"""

import pytest
from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, CallOptions, DeployOptions


class TestMathDemo:

    def test_deploy(self):
        """Deploy with initial value 1000."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_divide_by(self):
        """1000 / 10 = 100."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "divideBy", [10], provider, wallet["signer"],
        )
        assert txid

    def test_divide_then_clamp(self):
        """1000 -> 100 (divideBy 10) -> 50 (clamp 0..50)."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        contract.call(
            "divideBy", [10], provider, wallet["signer"],
        )

        contract.call(
            "clampValue", [0, 50], provider, wallet["signer"],
        )

    def test_square_root(self):
        """sqrt(49) = 7."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [49])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "squareRoot", [], provider, wallet["signer"],
        )
        assert txid

    def test_exponentiate(self):
        """2^10 = 1024."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [2])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "exponentiate", [10], provider, wallet["signer"],
        )
        assert txid

    def test_reduce_gcd(self):
        """gcd(100, 75) = 25."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [100])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "reduceGcd", [75], provider, wallet["signer"],
        )
        assert txid

    def test_compute_log2(self):
        """log2(1024) = 10."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1024])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "computeLog2", [], provider, wallet["signer"],
        )
        assert txid

    def test_scale_by_ratio(self):
        """100 * 3 / 4 = 75."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [100])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "scaleByRatio", [3, 4], provider, wallet["signer"],
        )
        assert txid

    def test_reject_divide_by_zero(self):
        """divideBy(0) should fail."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "divideBy", [0], provider, wallet["signer"],
                CallOptions(new_state={"value": 0}),
            )

    def test_reject_wrong_state(self):
        """Claiming value=999 instead of 100 after divideBy(10) should fail."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "divideBy", [10], provider, wallet["signer"],
                CallOptions(new_state={"value": 999}),
            )

    def test_normalize(self):
        """normalize: sign(-42) = -1."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [-42])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        txid, _ = contract.call(
            "normalize", [], provider, wallet["signer"],
        )
        assert txid

    def test_chain_operations(self):
        """Chain: 1000 -> divideBy(10)=100 -> squareRoot()=10 -> scaleByRatio(5,1)=50."""
        artifact = compile_contract("examples/ts/math-demo/MathDemo.runar.ts")
        contract = RunarContract(artifact, [1000])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        contract.call(
            "divideBy", [10], provider, wallet["signer"],
        )

        contract.call(
            "squareRoot", [], provider, wallet["signer"],
        )

        contract.call(
            "scaleByRatio", [5, 1], provider, wallet["signer"],
        )
