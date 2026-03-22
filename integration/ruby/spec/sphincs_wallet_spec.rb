# frozen_string_literal: true

# SPHINCSWallet integration test -- Hybrid ECDSA + SLH-DSA-SHA2-128s contract.
#
# Security Model: Two-Layer Authentication
# ==========================================
#
# This contract creates a quantum-resistant spending path by combining
# classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
#
# 1. ECDSA proves the signature commits to this specific transaction
#    (via OP_CHECKSIG over the sighash preimage).
# 2. SLH-DSA proves the ECDSA signature was authorised by the SLH-DSA
#    key holder — the ECDSA signature bytes ARE the message that SLH-DSA signs.
#
# Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
# can sign many messages — it's NIST FIPS 205 standardised.
#
# Constructor
#   - ecdsaPubKeyHash:  Addr       -- 20-byte HASH160 of compressed ECDSA public key
#   - slhdsaPubKeyHash: ByteString -- 20-byte HASH160 of 32-byte SLH-DSA public key
#
# Method: spend(slhdsaSig, slhdsaPubKey, sig, pubKey)
#   - slhdsaSig:    7,856-byte SLH-DSA-SHA2-128s signature
#   - slhdsaPubKey: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16])
#   - sig:          ~72-byte DER-encoded ECDSA signature + sighash flag
#   - pubKey:       33-byte compressed ECDSA public key
#
# Script Size: ~188 KB

require 'spec_helper'

# Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16])
# Generated from seed [0, 1, 2, ..., 47] with SLH-DSA-SHA2-128s (n=16).
SLHDSA_TEST_PK      = '00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf'.freeze
SLHDSA_TEST_PK_HASH = begin
  require 'openssl'
  sha  = Digest::SHA256.digest([SLHDSA_TEST_PK].pack('H*'))
  ripe = OpenSSL::Digest::RIPEMD160.digest(sha)
  ripe.unpack1('H*')
end.freeze

RSpec.describe 'SPHINCSWallet' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the SPHINCSWallet contract' do
    artifact = compile_contract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('SPHINCSWallet')
    expect(artifact.script.length).to be > 0
  end

  it 'has an SLH-DSA script approximately 188 KB' do
    artifact     = compile_contract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 100_000
    expect(script_bytes).to be < 500_000
  end

  it 'deploys with ECDSA pubkey hash + SLH-DSA pubkey hash' do
    artifact = compile_contract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    # Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], SLHDSA_TEST_PK_HASH])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with a different SLH-DSA public key' do
    artifact = compile_contract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    other_pk      = 'aabbccdd00000000000000000000000011223344556677889900aabbccddeeff'
    other_pk_hash = hash160([other_pk].pack('H*'))

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], other_pk_hash])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))
    expect(txid).to be_truthy
  end

  it 'deploys and verifies UTXO exists (full spend requires raw tx construction)' do
    # The hybrid spend pattern requires:
    #   1. Build unsigned spending transaction
    #   2. ECDSA-sign the transaction input
    #   3. SLH-DSA-sign the ECDSA signature bytes
    #   4. Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>
    #
    # This two-pass signing pattern is fully tested in the Go integration suite
    # (TestSLHDSA_ValidSpend) which uses raw transaction construction.
    artifact = compile_contract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], SLHDSA_TEST_PK_HASH])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 50_000))

    # Contract is deployed with correct hash commitments
    expect(contract.get_utxo).not_to be_nil
  end
end
