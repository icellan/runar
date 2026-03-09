"""
Auction integration test -- stateful contract.

Auction is a StatefulSmartContract with properties:
    - auctioneer: PubKey (readonly)
    - highestBidder: PubKey (mutable)
    - highestBid: bigint (mutable)
    - deadline: bigint (readonly)

Methods: bid(bidder, bidAmount), close(sig).
The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions


class TestAuction:

    def test_compile(self):
        """Compile the Auction contract."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")
        assert artifact
        assert artifact.contract_name == "Auction"

    def test_deploy(self):
        """Deploy with auctioneer, initial bidder, bid, and deadline."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")

        provider = create_provider()
        auctioneer = create_wallet()
        initial_bidder = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            auctioneer["pubKeyHex"],
            initial_bidder["pubKeyHex"],
            1000,
            1000000,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_deploy_zero_initial_bid(self):
        """Deploy with zero initial bid."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")

        provider = create_provider()
        auctioneer = create_wallet()
        initial_bidder = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            auctioneer["pubKeyHex"],
            initial_bidder["pubKeyHex"],
            0,
            500000,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_deploy_same_key_auctioneer_bidder(self):
        """Deploy with the same key as auctioneer and initial bidder."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")

        provider = create_provider()
        dual_role = create_wallet()
        wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            dual_role["pubKeyHex"],
            dual_role["pubKeyHex"],
            500,
            999999,
        ])

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

    def test_close_auction(self):
        """Deploy and close the auction with auto-computed Sig."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")

        provider = create_provider()
        # Auctioneer is the funded signer
        auctioneer_wallet = create_funded_wallet(provider)
        bidder = create_wallet()

        # deadline=0 so extractLocktime(txPreimage) >= deadline passes with nLocktime=0
        contract = RunarContract(artifact, [
            auctioneer_wallet["pubKeyHex"],
            bidder["pubKeyHex"],
            100,
            0,
        ])

        contract.deploy(provider, auctioneer_wallet["signer"], DeployOptions(satoshis=5000))

        # close: sig=None (auto-computed from signer who is the auctioneer)
        call_txid, _ = contract.call(
            "close", [None], provider, auctioneer_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_wrong_signer_rejected(self):
        """Close auction with wrong signer should be rejected."""
        artifact = compile_contract("examples/ts/auction/Auction.runar.ts")

        provider = create_provider()
        auctioneer_wallet = create_funded_wallet(provider)
        wrong_wallet = create_funded_wallet(provider)
        bidder = create_wallet()

        contract = RunarContract(artifact, [
            auctioneer_wallet["pubKeyHex"],
            bidder["pubKeyHex"],
            100,
            0,
        ])

        contract.deploy(provider, auctioneer_wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call(
                "close", [None], provider, wrong_wallet["signer"],
            )
