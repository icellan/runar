# frozen_string_literal: true

# Auction integration test -- stateful contract.
#
# Auction is a StatefulSmartContract with properties:
#   - auctioneer:   PubKey (readonly)
#   - highestBidder: PubKey (mutable)
#   - highestBid:   bigint (mutable)
#   - deadline:     bigint (readonly)
#
# Methods: bid(bidder, bidAmount), close(sig).
# The SDK auto-computes Sig params when nil is passed.

require 'spec_helper'

RSpec.describe 'Auction' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the Auction contract' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('Auction')
  end

  it 'deploys with auctioneer, initial bidder, bid, and deadline' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')

    provider        = create_provider
    auctioneer      = create_wallet
    initial_bidder  = create_wallet
    wallet          = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      auctioneer[:pub_key_hex],
      initial_bidder[:pub_key_hex],
      1000,
      1_000_000
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with zero initial bid' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')

    provider       = create_provider
    auctioneer     = create_wallet
    initial_bidder = create_wallet
    wallet         = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      auctioneer[:pub_key_hex],
      initial_bidder[:pub_key_hex],
      0,
      500_000
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys with the same key as auctioneer and initial bidder' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')

    provider  = create_provider
    dual_role = create_wallet
    wallet    = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [
      dual_role[:pub_key_hex],
      dual_role[:pub_key_hex],
      500,
      999_999
    ])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys and closes the auction with auto-computed Sig' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')

    provider          = create_provider
    # Auctioneer is the funded signer
    auctioneer_wallet = create_funded_wallet(provider)
    bidder            = create_wallet

    # G5: a REAL non-zero block-height deadline paired with a matching
    # CallOptions#locktime, mirroring integration/rust/tests/auction.rs. The old
    # deadline=0 + nLockTime=0 combination made
    # `extractLocktime(txPreimage) >= deadline` vacuously true, so a regression
    # in the SDK's locktime threading (or in extractLocktime codegen) would not
    # have been caught. nLockTime=1 is safely in the past so the tx is
    # immediately mineable — but if the SDK stopped writing the locktime into the
    # preimage, the preimage would carry 0 and `0 >= 1` would fail the spend.
    deadline = 1
    contract = Runar::SDK::RunarContract.new(artifact, [
      auctioneer_wallet[:pub_key_hex],
      bidder[:pub_key_hex],
      100,
      deadline
    ])

    contract.deploy(provider, auctioneer_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # close: sig=nil (auto-computed from signer who is the auctioneer)
    call_txid, _count = contract.call(
      'close', [nil], provider, auctioneer_wallet[:signer],
      Runar::SDK::CallOptions.new(locktime: deadline)
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects close auction with wrong signer' do
    artifact = compile_contract('examples/ts/auction/Auction.runar.ts')

    provider          = create_provider
    auctioneer_wallet = create_funded_wallet(provider)
    wrong_wallet      = create_funded_wallet(provider)
    bidder            = create_wallet

    contract = Runar::SDK::RunarContract.new(artifact, [
      auctioneer_wallet[:pub_key_hex],
      bidder[:pub_key_hex],
      100,
      1 # non-zero block-height deadline (see the close example above)
    ])

    contract.deploy(provider, auctioneer_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # locktime is set so the ONLY reason for rejection is the wrong signer, not
    # an unsatisfied deadline.
    expect_node_rejected(provider) do
      contract.call(
        'close', [nil], provider, wrong_wallet[:signer],
        Runar::SDK::CallOptions.new(locktime: 1)
      )
    end
  end
end
