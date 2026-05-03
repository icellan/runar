"""
WOTS+ integration tests -- compile + deploy smoke tests for the
hybrid ECDSA+WOTS+ wallet contract.

Ported from integration/go/wots_test.go. The deeper end-to-end spend
flow with full WOTS+ signing is exercised by ``test_post_quantum_wallet.py``;
this module exists to satisfy the per-case test gap (the audit lists
``wots`` as a regtest case that must have a dedicated Python test file)
and to give a quick deploy smoke test against the real regtest node.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
    wots_keygen, _hash160,
)
from runar.sdk import RunarContract, DeployOptions


CONTRACT_PATH = "examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts"


def _make_test_kp():
    seed = bytearray(32)
    seed[0] = 0x42
    pub_seed = bytearray(32)
    pub_seed[0] = 0x01
    return wots_keygen(bytes(seed), bytes(pub_seed))


class TestWOTS:

    def test_compile(self):
        """Compile the PostQuantumWallet contract — uses the WOTS+ codegen."""
        artifact = compile_contract(CONTRACT_PATH)
        assert artifact
        assert artifact.contract_name == "PostQuantumWallet"
        assert len(artifact.script) > 0

    def test_script_size_in_range(self):
        """Hybrid ECDSA+WOTS+ scripts are ~10 KB."""
        artifact = compile_contract(CONTRACT_PATH)
        script_bytes = len(artifact.script) // 2
        assert 5_000 < script_bytes < 50_000, (
            f"expected 5-50 KB, got {script_bytes} bytes"
        )

    def test_deploy(self):
        """Deploy with ECDSA pubKeyHash + WOTS+ pubKeyHash."""
        artifact = compile_contract(CONTRACT_PATH)
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        kp = _make_test_kp()
        wots_pk_hash = _hash160(bytes.fromhex(kp["pk"]))

        contract = RunarContract(artifact, [wallet["pubKeyHash"], wots_pk_hash])
        txid, _ = contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )
        assert txid
        assert len(txid) == 64

    def test_deploy_different_seed_yields_different_pubkey(self):
        """Different WOTS seeds must produce different pubkeys (sanity)."""
        seed1 = bytearray(32); seed1[0] = 0xAA
        seed2 = bytearray(32); seed2[0] = 0xBB
        pub_seed1 = bytearray(32); pub_seed1[0] = 0x01
        pub_seed2 = bytearray(32); pub_seed2[0] = 0x02

        kp1 = wots_keygen(bytes(seed1), bytes(pub_seed1))
        kp2 = wots_keygen(bytes(seed2), bytes(pub_seed2))
        assert kp1["pk"] != kp2["pk"]
