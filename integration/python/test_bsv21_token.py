"""
BSV-21 token integration tests -- compile + deploy + spend the standard
BSV-21 P2PKH wrapper from ``examples/ts/bsv21-token/BSV21Token.runar.ts``.

The deploy-mint and transfer inscription flows are exercised by the TS
suite (``integration/ts/bsv21-token.test.ts``); this module satisfies the
per-case Python gap.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/bsv21-token/BSV21Token.runar.ts"


class TestBSV21Token:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "BSV21Token"
        assert len(artifact.script) > 0

    def test_deploy_and_spend(self):
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [wallet["pubKeyHash"]])
        deploy_txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=5000),
        )
        assert deploy_txid

        call_txid, _ = contract.call(
            "unlock", [None, None], provider, wallet["signer"],
        )
        assert call_txid
