"""
P-384 hybrid-wallet integration smoke tests -- compile + deploy for
``examples/ts/p384-wallet/P384Wallet.runar.ts``.

End-to-end signing flows are exercised by the TS suite
(``integration/ts/p384-wallet.test.ts``); this module satisfies the
per-case Python gap and gives a quick deploy smoke test against the real
regtest node.
"""

import secrets

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet, _hash160
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/p384-wallet/P384Wallet.runar.ts"


class TestP384Wallet:

    def test_compile(self):
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "P384Wallet"
        assert len(artifact.script) > 0

    def test_script_size_in_p384_range(self):
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        assert script_bytes > 100_000, (
            f"expected >100 KB, got {script_bytes} bytes"
        )

    def test_deploy_with_random_p384_pubkey_hash(self):
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        # 49-byte compressed P-384 pubkey: 02/03 prefix + x[48].
        fake_p384_pubkey = bytes([0x02]) + secrets.token_bytes(48)
        p384_pkh = _hash160(fake_p384_pubkey)

        contract = RunarContract(artifact, [wallet["pubKeyHash"], p384_pkh])
        txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=50_000),
        )
        assert txid
        assert len(txid) == 64
