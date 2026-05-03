"""
OrdinalNFT integration tests -- compile + deploy + spend the
``examples/ts/ordinal-nft/OrdinalNFT.runar.ts`` reference contract.

OrdinalNFT is a P2PKH-style lock that wraps a 1sat ordinal inscription;
the inscription envelope is handled by the SDK ``Inscription`` helper
and is exercised end-to-end by the TS suite. This Python test module
satisfies the per-case audit gap.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/ordinal-nft/OrdinalNFT.runar.ts"


class TestOrdinalNFT:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "OrdinalNFT"
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
