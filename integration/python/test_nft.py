"""
SimpleNFT integration test -- stateful contract with addOutput.

SimpleNFT is a StatefulSmartContract with properties:
    - owner: PubKey (mutable)
    - tokenId: ByteString (readonly)
    - metadata: ByteString (readonly)

The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestSimpleNFT:

    def test_compile(self):
        """Compile the SimpleNFT contract."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")
        assert artifact
        assert artifact.contract_name == "SimpleNFT"

    def test_deploy_with_metadata(self):
        """Deploy with owner, tokenId, and metadata."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"NFT-001".hex()
        metadata_hex = b"My First NFT".hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"],
            token_id_hex,
            metadata_hex,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_different_owners(self):
        """Deploy two NFTs with different owners, verify distinct txids."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner1 = create_wallet()
        owner2 = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"NFT-MULTI".hex()
        metadata_hex = b"Unique Art Piece".hex()

        contract1 = RunarContract(artifact, [
            owner1["pubKeyHex"], token_id_hex, metadata_hex,
        ])
        txid1, _ = contract1.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid1

        contract2 = RunarContract(artifact, [
            owner2["pubKeyHex"], token_id_hex, metadata_hex,
        ])
        txid2, _ = contract2.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid2

        assert txid1 != txid2

    def test_deploy_long_metadata(self):
        """Deploy with 256 bytes of metadata."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner = create_wallet()
        wallet = create_funded_wallet(provider)

        token_id_hex = b"NFT-LONG-META".hex()
        metadata_hex = (b"A" * 256).hex()

        contract = RunarContract(artifact, [
            owner["pubKeyHex"], token_id_hex, metadata_hex,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_transfer(self):
        """Deploy and transfer NFT to a new owner."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        new_owner = create_wallet()

        token_id_hex = b"NFT-XFER".hex()
        metadata_hex = b"Transfer Test".hex()

        # Owner is the funded signer
        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            token_id_hex,
            metadata_hex,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=1))

        # transfer: sig=None (auto), newOwner, outputSatoshis
        # State auto-computed from ANF IR (owner changes to newOwner)
        # outputSatoshis must match the deploy satoshis since the SDK constructs
        # a continuation output with currentUtxo.satoshis. The on-chain script's
        # addOutput uses outputSatoshis for the output amount.
        call_txid, _ = contract.call(
            "transfer",
            [None, new_owner["pubKeyHex"], 1],
            provider, owner_wallet["signer"],
        )
        assert call_txid

    def test_burn(self):
        """Deploy and burn an NFT."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)

        token_id_hex = b"NFT-BURN".hex()
        metadata_hex = b"Burn Test".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            token_id_hex,
            metadata_hex,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        # burn: sig=None (auto), no state continuation
        call_txid, _ = contract.call(
            "burn", [None], provider, owner_wallet["signer"],
        )
        assert call_txid

    def test_wrong_owner_rejected(self):
        """Transfer with wrong signer (not the owner) should be rejected."""
        artifact = compile_contract("examples/ts/token-nft/NFTExample.runar.ts")

        provider = create_provider()
        owner_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        new_owner = create_wallet()

        token_id_hex = b"NFT-REJECT".hex()
        metadata_hex = b"Reject Test".hex()

        contract = RunarContract(artifact, [
            owner_wallet["pubKeyHex"],
            token_id_hex,
            metadata_hex,
        ])

        contract.deploy(provider, owner_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "transfer",
                [None, new_owner["pubKeyHex"], 5000],
                provider, wrong_wallet["signer"],
            )
