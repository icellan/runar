"""
BSV-20 token integration tests -- compile + deploy + spend the standard
BSV-20 P2PKH wrapper from ``examples/ts/bsv20-token/BSV20Token.runar.ts``.

The token semantics (deploy / mint / transfer inscription envelopes) are
exercised by the TS suite (``integration/ts/bsv20-token.test.ts``); this
module satisfies the per-case Python gap by ensuring the contract
compiles and can be deployed/spent against a real regtest node.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/bsv20-token/BSV20Token.runar.ts"


class TestBSV20Token:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "BSV20Token"
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
        assert len(deploy_txid) == 64

        call_txid, _ = contract.call(
            "unlock", [None, None], provider, wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64
