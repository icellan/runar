# frozen_string_literal: true

# SchnorrZKP integration test -- stateless contract with EC scalar math verification.
#
# SchnorrZKP implements a Schnorr zero-knowledge proof verifier on-chain.
# The contract locks funds to an EC public key P, and spending requires proving
# knowledge of the discrete logarithm k (i.e., P = k*G) without revealing k.
#
# The challenge e is derived on-chain via the Fiat-Shamir heuristic:
#   e = bin2num(hash256(cat(rPoint, pubKey)))
#
# Constructor
#   - pubKey: Point -- the EC public key (64-byte uncompressed x[32] || y[32])
#
# Method: verify(rPoint: Point, s: bigint)
#   The prover generates a proof:
#     1. Pick random nonce r, compute R = r*G (commitment)
#     2. e is derived on-chain: e = bin2num(hash256(R || P))
#     3. Compute s = r + e*k (mod n) (response)
#   The contract checks: s*G === R + e*P (Schnorr verification equation)
#
# Script Size: ~877 KB

require 'spec_helper'
require 'digest'

# Derive the Fiat-Shamir challenge: e = bin2num(hash256(R || P)).
#
# hash256 is double-SHA256. bin2num interprets the result as a Bitcoin Script
# number (little-endian signed-magnitude).
#
# @param r_point_hex [String] 128-char hex (64 bytes)
# @param pub_key_hex [String] 128-char hex (64 bytes)
# @return [Integer] challenge value (may be negative)
def derive_fiat_shamir_challenge(r_point_hex, pub_key_hex)
  combined = [r_point_hex + pub_key_hex].pack('H*')
  h1 = Digest::SHA256.digest(combined)
  h2 = Digest::SHA256.digest(h1)

  data = h2.bytes

  # bin2num: LE signed-magnitude
  is_neg = (data[31] & 0x80) != 0
  data[31] &= 0x7F

  # LE bytes to integer
  magnitude = data.each_with_index.sum { |byte, i| byte << (i * 8) }
  is_neg ? -magnitude : magnitude
end

RSpec.describe 'SchnorrZKP' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the SchnorrZKP contract' do
    artifact = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('SchnorrZKP')
    expect(artifact.script.length).to be > 0
  end

  it 'has an EC-heavy script approximately 877 KB' do
    artifact     = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 100_000
    expect(script_bytes).to be < 2_000_000
  end

  it 'deploys with an EC public key point' do
    artifact = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    # Generate keypair: k is private, P = k*G is the public key point
    k = 42
    px, py = ec_mul_gen(k)

    # Constructor: (pubKey: Point) -- 64-byte hex (x[32] || y[32])
    pub_key_hex = encode_point(px, py)
    contract    = Runar::SDK::RunarContract.new(artifact, [pub_key_hex])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with a different public key' do
    artifact = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    k = 123_456_789
    px, py = ec_mul_gen(k)
    pub_key_hex = encode_point(px, py)

    contract = Runar::SDK::RunarContract.new(artifact, [pub_key_hex])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))
    expect(txid).to be_truthy
  end

  it 'deploys and spends with a valid Schnorr ZKP proof' do
    # The proof satisfies the Schnorr verification equation s*G = R + e*P:
    #   1. Private key k=42, public key P = k*G
    #   2. Nonce r=7777, commitment R = r*G
    #   3. Challenge e = bin2num(hash256(R || P)) (Fiat-Shamir)
    #   4. Response s = r + e*k mod n
    #   5. Call verify(R, s) -- e is derived on-chain
    artifact = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    # Step 1: Generate keypair
    k = 42
    px, py = ec_mul_gen(k)
    pub_key_hex = encode_point(px, py)

    contract = Runar::SDK::RunarContract.new(artifact, [pub_key_hex])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    # Step 2: Generate the Schnorr ZKP proof
    r = 7777
    rx, ry = ec_mul_gen(r)
    r_point_hex = encode_point(rx, ry)

    # Fiat-Shamir challenge: e = bin2num(hash256(R || P))
    e = derive_fiat_shamir_challenge(r_point_hex, pub_key_hex)

    # Response s = r + e*k (mod n)
    s = (r + e * k) % IntegrationHelpers::EC_N

    # Step 3: Call verify(rPoint, s)
    call_txid, _count = contract.call(
      'verify',
      [r_point_hex, s],
      provider, wallet[:signer]
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'rejects verify with tampered s value' do
    artifact = compile_contract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    k = 42
    px, py = ec_mul_gen(k)
    pub_key_hex = encode_point(px, py)

    contract = Runar::SDK::RunarContract.new(artifact, [pub_key_hex])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    r = 7777
    rx, ry = ec_mul_gen(r)
    r_point_hex = encode_point(rx, ry)

    # Fiat-Shamir challenge
    e = derive_fiat_shamir_challenge(r_point_hex, pub_key_hex)
    s = (r + e * k) % IntegrationHelpers::EC_N

    # Tamper s by adding 1
    tampered_s = (s + 1) % IntegrationHelpers::EC_N

    expect do
      contract.call(
        'verify',
        [r_point_hex, tampered_s],
        provider, wallet[:signer]
      )
    end.to raise_error(StandardError)
  end
end
