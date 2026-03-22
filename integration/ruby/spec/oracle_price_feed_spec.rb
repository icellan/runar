# frozen_string_literal: true

# OraclePriceFeed integration test -- stateless contract with Rabin signature verification.
#
# OraclePriceFeed locks funds to an oracle's Rabin public key and a receiver's ECDSA
# public key. To spend, the oracle must sign a price that exceeds a hardcoded threshold
# (50,000), AND the receiver must provide their ECDSA signature.
#
# Constructor
#   - oraclePubKey: RabinPubKey (bigint) -- the Rabin modulus n = p*q
#   - receiver:     PubKey              -- the ECDSA public key authorised to receive funds
#
# Method: settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig)
#   1. Encode price as 8-byte little-endian (num2bin)
#   2. Verify Rabin signature: (sig^2 + padding) mod n === SHA-256(encoded_price) mod n
#   3. Assert price > 50000
#   4. Verify receiver's ECDSA signature (checkSig)

require 'spec_helper'

# Encode an integer as little-endian bytes of the given length.
# Matches the contract's num2bin(price, 8) encoding used for Rabin message hashing.
#
# @param value  [Integer] the integer to encode
# @param length [Integer] number of bytes
# @return [String] binary string
def num2bin_le(value, length)
  result = String.new("\x00" * length, encoding: 'binary')
  v = value
  length.times do |i|
    result.setbyte(i, v & 0xFF)
    v >>= 8
  end
  result
end

RSpec.describe 'OraclePriceFeed' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the OraclePriceFeed contract' do
    artifact = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('OraclePriceFeed')
    expect(artifact.script.length).to be > 0
  end

  it 'deploys with a Rabin oracle key and receiver pubkey' do
    artifact  = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')
    provider  = create_provider
    wallet    = create_funded_wallet(provider)
    rabin_kp  = generate_rabin_key_pair
    receiver  = create_wallet

    # Constructor: (oraclePubKey: RabinPubKey, receiver: PubKey)
    # RabinPubKey is bigint (n = p*q), PubKey is hex string
    contract = Runar::SDK::RunarContract.new(artifact, [rabin_kp[:n], receiver[:pub_key_hex]])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with the same oracle key but different receiver' do
    artifact = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)
    rabin_kp = generate_rabin_key_pair
    receiver = create_wallet

    contract = Runar::SDK::RunarContract.new(artifact, [rabin_kp[:n], receiver[:pub_key_hex]])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
  end

  it 'deploys and spends with a valid oracle price above the 50,000 threshold' do
    # Steps:
    #   1. Create the oracle's Rabin keypair (small test primes)
    #   2. Create the receiver wallet (signer must match the constructor's receiver)
    #   3. Deploy with (oracleN, receiverPubKey)
    #   4. Oracle signs price=55001 as 8-byte LE using Rabin signature
    #   5. Call settle(price, rabinSig, padding, nil) -- SDK auto-computes ECDSA sig
    artifact = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')

    provider        = create_provider
    # The receiver will be the signer — their ECDSA key must match the constructor
    receiver_wallet = create_funded_wallet(provider)
    rabin_kp        = generate_rabin_key_pair

    # Deploy: oracle Rabin pubkey + receiver's ECDSA pubkey
    contract = Runar::SDK::RunarContract.new(artifact, [
      rabin_kp[:n],
      receiver_wallet[:pub_key_hex]
    ])
    contract.deploy(provider, receiver_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Oracle signs price=55001 (above 50000 threshold)
    price     = 55001
    # Encode price as 8-byte LE — matches the contract's num2bin(price, 8)
    msg_bytes = num2bin_le(price, 8)
    result    = rabin_sign(msg_bytes, rabin_kp)

    # Call settle(price, rabinSig, padding, sig=nil)
    # sig: nil -> SDK auto-computes ECDSA signature from the receiver's key
    call_txid, _count = contract.call(
      'settle',
      [price, result[:sig], result[:padding], nil],
      provider, receiver_wallet[:signer]
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects settle with price below 50000 threshold' do
    artifact = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')

    provider        = create_provider
    receiver_wallet = create_funded_wallet(provider)
    rabin_kp        = generate_rabin_key_pair

    contract = Runar::SDK::RunarContract.new(artifact, [
      rabin_kp[:n],
      receiver_wallet[:pub_key_hex]
    ])
    contract.deploy(provider, receiver_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Oracle signs price=49999 (below 50000 threshold)
    price     = 49999
    msg_bytes = num2bin_le(price, 8)
    result    = rabin_sign(msg_bytes, rabin_kp)

    expect do
      contract.call(
        'settle',
        [price, result[:sig], result[:padding], nil],
        provider, receiver_wallet[:signer]
      )
    end.to raise_error(StandardError)
  end

  it 'rejects settle with wrong receiver signer' do
    artifact = compile_contract('examples/ts/oracle-price/OraclePriceFeed.runar.ts')

    provider        = create_provider
    receiver_wallet = create_funded_wallet(provider)
    wrong_wallet    = create_funded_wallet(provider)
    rabin_kp        = generate_rabin_key_pair

    contract = Runar::SDK::RunarContract.new(artifact, [
      rabin_kp[:n],
      receiver_wallet[:pub_key_hex]
    ])
    contract.deploy(provider, receiver_wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    # Oracle signs a valid price above threshold
    price     = 55001
    msg_bytes = num2bin_le(price, 8)
    result    = rabin_sign(msg_bytes, rabin_kp)

    # Try to settle with wrong signer (not the receiver)
    expect do
      contract.call(
        'settle',
        [price, result[:sig], result[:padding], nil],
        provider, wrong_wallet[:signer]
      )
    end.to raise_error(StandardError)
  end
end
