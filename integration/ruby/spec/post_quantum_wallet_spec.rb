# frozen_string_literal: true

# PostQuantumWallet integration test -- Hybrid ECDSA + WOTS+ contract.
#
# Security Model: Two-Layer Authentication
# ==========================================
#
# This contract creates a quantum-resistant spending path by combining
# classical ECDSA with WOTS+ (Winternitz One-Time Signature):
#
# 1. ECDSA proves the signature commits to this specific transaction
#    (via OP_CHECKSIG over the sighash preimage).
# 2. WOTS+ proves the ECDSA signature was authorised by the WOTS key
#    holder — the ECDSA signature bytes ARE the message that WOTS signs.
#
# Constructor
#   - ecdsaPubKeyHash: Addr       -- 20-byte HASH160 of compressed ECDSA public key
#   - wotsPubKeyHash:  ByteString -- 20-byte HASH160 of 64-byte WOTS+ public key
#
# Method: spend(wotsSig, wotsPubKey, sig, pubKey)
#   - wotsSig:    2,144-byte WOTS+ signature (67 chains × 32 bytes)
#   - wotsPubKey: 64-byte WOTS+ public key (pubSeed[32] || pkRoot[32])
#   - sig:        ~72-byte DER-encoded ECDSA signature + sighash flag
#   - pubKey:     33-byte compressed ECDSA public key
#
# Script Size: ~10 KB

require 'spec_helper'

RSpec.describe 'PostQuantumWallet' do # rubocop:disable RSpec/DescribeClass
  it 'compiles the PostQuantumWallet contract' do
    artifact = compile_contract('examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts')
    expect(artifact).not_to be_nil
    expect(artifact.contract_name).to eq('PostQuantumWallet')
    expect(artifact.script.length).to be > 0
  end

  it 'has a hybrid ECDSA+WOTS+ script approximately 10 KB' do
    artifact     = compile_contract('examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts')
    script_bytes = artifact.script.length / 2
    expect(script_bytes).to be > 5000
    expect(script_bytes).to be < 50_000
  end

  it 'deploys with ECDSA pubkey hash + WOTS+ pubkey hash' do
    artifact = compile_contract('examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    # Generate WOTS+ keypair from a deterministic seed
    seed     = "\x42" + ("\x00" * 31)
    pub_seed = "\x01" + ("\x00" * 31)

    kp           = wots_keygen(seed, pub_seed)
    wots_pk_hash = hash160([kp[:pk]].pack('H*'))

    # Constructor: (ecdsaPubKeyHash, wotsPubKeyHash)
    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], wots_pk_hash])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))
    expect(txid).to be_truthy
    expect(txid).to be_a(String)
    expect(txid.length).to eq(64)
  end

  it 'deploys with a different seed producing a different WOTS+ public key' do
    artifact = compile_contract('examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    seed     = "\x99\xAB" + ("\x00" * 30)
    pub_seed = "\x02" + ("\x00" * 31)

    kp           = wots_keygen(seed, pub_seed)
    wots_pk_hash = hash160([kp[:pk]].pack('H*'))

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], wots_pk_hash])

    txid, _count = contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))
    expect(txid).to be_truthy
  end

  it 'deploys and verifies UTXO exists (full spend requires raw tx construction)' do
    # The hybrid pattern requires:
    #   1. Build unsigned spending transaction
    #   2. ECDSA-sign the transaction input
    #   3. WOTS-sign the ECDSA signature bytes
    #   4. Construct unlocking script: <wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>
    #
    # This two-pass signing pattern is fully tested in the Go integration suite
    # (TestWOTS_ValidSpend) which uses raw transaction construction.
    artifact = compile_contract('examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts')

    provider = create_provider
    wallet   = create_funded_wallet(provider)

    seed     = "\x42" + ("\x00" * 31)
    pub_seed = "\x01" + ("\x00" * 31)

    kp           = wots_keygen(seed, pub_seed)
    wots_pk_hash = hash160([kp[:pk]].pack('H*'))

    contract = Runar::SDK::RunarContract.new(artifact, [wallet[:pub_key_hash], wots_pk_hash])
    contract.deploy(provider, wallet[:signer], Runar::SDK::DeployOptions.new(satoshis: 10_000))

    # Contract is deployed with correct hash commitments
    expect(contract.get_utxo).not_to be_nil
  end
end
