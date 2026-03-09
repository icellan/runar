"""
SPHINCSWallet integration test -- Hybrid ECDSA + SLH-DSA-SHA2-128s contract.

Security Model: Two-Layer Authentication
=========================================

This contract creates a quantum-resistant spending path by combining
classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):

1. **ECDSA** proves the signature commits to this specific transaction
   (via OP_CHECKSIG over the sighash preimage).
2. **SLH-DSA** proves the ECDSA signature was authorized by the SLH-DSA
   key holder -- the ECDSA signature bytes ARE the message that SLH-DSA signs.

A quantum attacker who can break ECDSA could forge a valid ECDSA
signature, but they cannot produce a valid SLH-DSA signature over their
forged sig without knowing the SLH-DSA secret key. SLH-DSA security
relies only on SHA-256 collision resistance, not on any number-theoretic
assumption vulnerable to Shor's algorithm.

Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
can sign many messages -- it's NIST FIPS 205 standardized.

Constructor
    - ecdsaPubKeyHash: Addr -- 20-byte HASH160 of compressed ECDSA public key
    - slhdsaPubKeyHash: ByteString -- 20-byte HASH160 of 32-byte SLH-DSA public key

Method: spend(slhdsaSig, slhdsaPubKey, sig, pubKey)
    - slhdsaSig: 7,856-byte SLH-DSA-SHA2-128s signature
    - slhdsaPubKey: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16])
    - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
    - pubKey: 33-byte compressed ECDSA public key

Script Size
    ~188 KB -- SLH-DSA verification requires computing multiple WOTS+
    verifications and Merkle tree path checks within the Bitcoin Script VM.

Test Approach
    Deployment tests use hash commitments of test keys. Full spending tests
    require raw transaction construction (two-pass signing: ECDSA first, then
    SLH-DSA over the ECDSA sig). The Go integration suite (TestSLHDSA_ValidSpend)
    implements the complete two-pass spending flow.
"""

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet, _hash160
from runar.sdk import RunarContract, DeployOptions


# Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16])
# Generated from seed [0, 1, 2, ..., 47] with SLH-DSA-SHA2-128s (n=16).
SLHDSA_TEST_PK = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf"
SLHDSA_TEST_PK_HASH = _hash160(bytes.fromhex(SLHDSA_TEST_PK))


class TestSPHINCSWallet:

    def test_compile(self):
        """Compile the SPHINCSWallet contract."""
        artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts")
        assert artifact
        assert artifact.contract_name == "SPHINCSWallet"
        assert len(artifact.script) > 0

    def test_script_size(self):
        """SLH-DSA scripts should be approximately 188 KB."""
        artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts")
        script_bytes = len(artifact.script) // 2
        assert script_bytes > 100000
        assert script_bytes < 500000

    def test_deploy(self):
        """Deploy with ECDSA pubkey hash + SLH-DSA pubkey hash."""
        artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        # Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
        contract = RunarContract(artifact, [wallet["pubKeyHash"], SLHDSA_TEST_PK_HASH])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=50000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_different_key(self):
        """Deploy with a different SLH-DSA public key."""
        artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        other_pk = "aabbccdd00000000000000000000000011223344556677889900aabbccddeeff"
        other_pk_hash = _hash160(bytes.fromhex(other_pk))

        contract = RunarContract(artifact, [wallet["pubKeyHash"], other_pk_hash])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=50000))
        assert txid

    def test_deploy_and_verify_utxo(self):
        """Deploy and verify UTXO exists (full spend requires raw tx construction).

        The hybrid spend pattern requires:
            1. Build unsigned spending transaction
            2. ECDSA-sign the transaction input
            3. SLH-DSA-sign the ECDSA signature bytes
            4. Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>

        This two-pass signing pattern is fully tested in the Go integration suite
        (TestSLHDSA_ValidSpend) which uses raw transaction construction.
        """
        artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [wallet["pubKeyHash"], SLHDSA_TEST_PK_HASH])
        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=50000))

        # Contract is deployed with correct hash commitments
        assert contract.get_utxo() is not None
