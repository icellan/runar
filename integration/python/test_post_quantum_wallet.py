"""
PostQuantumWallet integration test -- Hybrid ECDSA + WOTS+ contract.

Security Model: Two-Layer Authentication
=========================================

This contract creates a quantum-resistant spending path by combining
classical ECDSA with WOTS+ (Winternitz One-Time Signature):

1. **ECDSA** proves the signature commits to this specific transaction
   (via OP_CHECKSIG over the sighash preimage).
2. **WOTS+** proves the ECDSA signature was authorized by the WOTS key
   holder -- the ECDSA signature bytes ARE the message that WOTS signs.

A quantum attacker who can break ECDSA could forge a valid ECDSA
signature, but they cannot produce a valid WOTS+ signature over their
forged sig without knowing the WOTS secret key.

Constructor
    - ecdsaPubKeyHash: Addr -- 20-byte HASH160 of compressed ECDSA public key
    - wotsPubKeyHash: ByteString -- 20-byte HASH160 of 64-byte WOTS+ public key

Method: spend(wotsSig, wotsPubKey, sig, pubKey)
    - wotsSig: 2,144-byte WOTS+ signature (67 chains x 32 bytes)
    - wotsPubKey: 64-byte WOTS+ public key (pubSeed[32] || pkRoot[32])
    - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
    - pubKey: 33-byte compressed ECDSA public key

Script Size
    ~10 KB -- dominated by the inline WOTS+ verification logic.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
    wots_keygen, wots_sign, _hash160,
)
from runar.sdk import RunarContract, DeployOptions


class TestPostQuantumWallet:

    def test_compile(self):
        """Compile the PostQuantumWallet contract."""
        artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts")
        assert artifact
        assert artifact.contract_name == "PostQuantumWallet"
        assert len(artifact.script) > 0

    def test_script_size(self):
        """Hybrid ECDSA+WOTS+ scripts should be approximately 10 KB."""
        artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts")
        script_bytes = len(artifact.script) // 2
        assert script_bytes > 5000
        assert script_bytes < 50000

    def test_deploy(self):
        """Deploy with ECDSA pubkey hash + WOTS+ pubkey hash."""
        artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        # Generate WOTS+ keypair from a deterministic seed
        seed = bytearray(32)
        seed[0] = 0x42
        seed = bytes(seed)
        pub_seed = bytearray(32)
        pub_seed[0] = 0x01
        pub_seed = bytes(pub_seed)

        kp = wots_keygen(seed, pub_seed)

        # WOTS pubkey hash: hash160 of 64-byte pk (pubSeed || pkRoot)
        wots_pk_hash = _hash160(bytes.fromhex(kp["pk"]))

        # Constructor: (ecdsaPubKeyHash, wotsPubKeyHash)
        contract = RunarContract(artifact, [wallet["pubKeyHash"], wots_pk_hash])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_different_seed(self):
        """Deploy with a different seed produces a different WOTS+ public key."""
        artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        seed = bytearray(32)
        seed[0] = 0x99
        seed[1] = 0xAB
        seed = bytes(seed)
        pub_seed = bytearray(32)
        pub_seed[0] = 0x02
        pub_seed = bytes(pub_seed)

        kp = wots_keygen(seed, pub_seed)
        wots_pk_hash = _hash160(bytes.fromhex(kp["pk"]))

        contract = RunarContract(artifact, [wallet["pubKeyHash"], wots_pk_hash])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))
        assert txid

    def test_spend_valid_sig(self):
        """Deploy and verify UTXO exists (full spend requires raw tx construction).

        The hybrid pattern requires:
            1. Build unsigned spending transaction
            2. ECDSA-sign the transaction input
            3. WOTS-sign the ECDSA signature bytes
            4. Construct unlocking script: <wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>

        This two-pass signing pattern is fully tested in the Go integration suite
        (TestWOTS_ValidSpend) which uses raw transaction construction.
        """
        artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        seed = bytearray(32)
        seed[0] = 0x42
        seed = bytes(seed)
        pub_seed = bytearray(32)
        pub_seed[0] = 0x01
        pub_seed = bytes(pub_seed)

        kp = wots_keygen(seed, pub_seed)
        wots_pk_hash = _hash160(bytes.fromhex(kp["pk"]))

        contract = RunarContract(artifact, [wallet["pubKeyHash"], wots_pk_hash])
        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=10000))

        # Contract is deployed with correct hash commitments
        assert contract.get_utxo() is not None
