"""
OraclePriceFeed integration test -- stateless contract with Rabin signature verification.

How It Works
============

OraclePriceFeed locks funds to an oracle's Rabin public key and a receiver's ECDSA
public key. To spend, the oracle must sign a price that exceeds a hardcoded threshold
(50,000), AND the receiver must provide their ECDSA signature. This demonstrates a
two-party spending condition: oracle data feed + receiver authorization.

Constructor
    - oraclePubKey: RabinPubKey (bigint) -- the Rabin modulus n = p*q
    - receiver: PubKey -- the ECDSA public key authorized to receive funds

Method: settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig)
    1. Encode price as 8-byte little-endian (num2bin)
    2. Verify Rabin signature: (sig^2 + padding) mod n === SHA-256(encoded_price) mod n
    3. Assert price > 50000
    4. Verify receiver's ECDSA signature (checkSig)

How Rabin Signatures Work
    - Key: two large primes p, q where p === q === 3 (mod 4), public key n = p*q
    - Sign: find square root of H(msg) mod n using CRT (needs p, q)
    - Verify: check sig^2 === H(msg) + padding (mod n) -- very cheap on-chain
    - Padding: tries values 0..255 until H(msg)+padding is a quadratic residue

Important Notes
    - The Sig param (ECDSA) is auto-computed by the SDK when passed as None
    - The Rabin signature, padding, and price must be computed in the test
    - Uses small test primes (7879, 7883) -- real deployments need 1024+ bit primes
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
    generate_rabin_key_pair, rabin_sign,
)
from runar.sdk import RunarContract, DeployOptions


def num2bin_le(value: int, length: int) -> bytes:
    """Encode an integer as little-endian bytes of the given length.

    Matches the contract's num2bin(price, 8) encoding used for
    Rabin message hashing.
    """
    result = bytearray(length)
    v = value
    for i in range(length):
        result[i] = v & 0xFF
        v >>= 8
    return bytes(result)


class TestOraclePriceFeed:

    def test_compile(self):
        """Compile the OraclePriceFeed contract."""
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")
        assert artifact
        assert artifact.contract_name == "OraclePriceFeed"
        assert len(artifact.script) > 0

    def test_deploy_with_rabin_key(self):
        """Deploy with a Rabin oracle key and receiver pubkey."""
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)
        rabin_kp = generate_rabin_key_pair()
        receiver = create_wallet()

        # Constructor: (oraclePubKey: RabinPubKey, receiver: PubKey)
        # RabinPubKey is bigint (n = p*q), PubKey is hex string
        contract = RunarContract(artifact, [rabin_kp["n"], receiver["pubKeyHex"]])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_different_receiver(self):
        """Deploy with the same oracle key but different receiver."""
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")

        provider = create_provider()
        wallet = create_funded_wallet(provider)
        rabin_kp = generate_rabin_key_pair()
        receiver = create_wallet()

        contract = RunarContract(artifact, [rabin_kp["n"], receiver["pubKeyHex"]])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_spend_valid_price(self):
        """Deploy and spend with a valid oracle price above the 50,000 threshold.

        Steps:
            1. Create the oracle's Rabin keypair (small test primes)
            2. Create the receiver wallet (signer must match the constructor's receiver)
            3. Deploy with (oracleN, receiverPubKey)
            4. Oracle signs price=55001 as 8-byte LE using Rabin signature
            5. Call settle(price, rabinSig, padding, None) -- SDK auto-computes ECDSA sig
        """
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")

        provider = create_provider()

        # The receiver will be the signer -- their ECDSA key must match the constructor
        receiver_wallet = create_funded_wallet(provider)

        rabin_kp = generate_rabin_key_pair()

        # Deploy: oracle Rabin pubkey + receiver's ECDSA pubkey
        contract = RunarContract(artifact, [
            rabin_kp["n"],
            receiver_wallet["pubKeyHex"],
        ])
        contract.deploy(provider, receiver_wallet["signer"], DeployOptions(satoshis=5000))

        # Oracle signs price=55001 (above 50000 threshold)
        price = 55001
        # Encode price as 8-byte LE -- matches the contract's num2bin(price, 8)
        msg_bytes = num2bin_le(price, 8)
        result = rabin_sign(msg_bytes, rabin_kp)

        # Call settle(price, rabinSig, padding, sig=None)
        # - price: the oracle-attested value (must be > 50000)
        # - rabinSig: square root of H(msg)+padding mod n
        # - padding: offset to make hash a quadratic residue
        # - sig: None -> SDK auto-computes ECDSA signature from the receiver's key
        call_txid, _ = contract.call(
            "settle",
            [price, result["sig"], result["padding"], None],
            provider, receiver_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_below_threshold_rejected(self):
        """Settle with price below 50000 threshold should be rejected."""
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")

        provider = create_provider()
        receiver_wallet = create_funded_wallet(provider)
        rabin_kp = generate_rabin_key_pair()

        contract = RunarContract(artifact, [
            rabin_kp["n"],
            receiver_wallet["pubKeyHex"],
        ])
        contract.deploy(provider, receiver_wallet["signer"], DeployOptions(satoshis=5000))

        # Oracle signs price=49999 (below 50000 threshold)
        price = 49999
        msg_bytes = num2bin_le(price, 8)
        result = rabin_sign(msg_bytes, rabin_kp)

        with pytest.raises(Exception):
            contract.call(
                "settle",
                [price, result["sig"], result["padding"], None],
                provider, receiver_wallet["signer"],
            )

    def test_wrong_receiver_rejected(self):
        """Settle with wrong receiver signer should be rejected."""
        artifact = compile_contract("examples/ts/oracle-price/OraclePriceFeed.runar.ts")

        provider = create_provider()
        receiver_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        rabin_kp = generate_rabin_key_pair()

        contract = RunarContract(artifact, [
            rabin_kp["n"],
            receiver_wallet["pubKeyHex"],
        ])
        contract.deploy(provider, receiver_wallet["signer"], DeployOptions(satoshis=5000))

        # Oracle signs a valid price above threshold
        price = 55001
        msg_bytes = num2bin_le(price, 8)
        result = rabin_sign(msg_bytes, rabin_kp)

        # Try to settle with wrong signer (not the receiver)
        with pytest.raises(Exception):
            contract.call(
                "settle",
                [price, result["sig"], result["padding"], None],
                provider, wrong_wallet["signer"],
            )
