# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# N-258 (user decision R99): a zero-mutable-field +StatefulSmartContract+ call
# that also spends +additional_contract_inputs+ builds a REAL per-input unlock
# for every extra contract input (its own OP_PUSH_TX preimage over its own
# outpoint / scriptCode / amount, and its own Sig signed at its own input index
# over the post-OP_CODESEPARATOR subscript), instead of refusing (N-227) or
# shipping the sizing placeholder. Fee/change are re-derived from the real
# unlocks.
#
# The scenario is the cross-tier N-258 vector: same contract, key, outpoints
# and amounts as packages/runar-sdk/src/__tests__/n258-zero-mutable-field-
# merge.test.ts, whose tx @bsv/sdk Spend accepts on every input (and the go-sdk
# interpreter and Python bsv-sdk Spend accept in their tiers).
#
# Proves: the Ruby SDK builds that merge tx byte for byte. Ruby ships no script
# interpreter, so script validity in this tier rests on that byte parity with
# the interpreter-checked tiers.
#
# Does NOT prove: merges on a zero-mutable-field contract with more than one
# public method (the stateless branch derives OP_PUSH_TX from the primary's
# code-separator index), allPrevouts auto-resolution on this branch, or the
# terminal-outputs path.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-258 zero-mutable-field StatefulSmartContract merge' do
  # rubocop:enable RSpec/DescribeClass
  n258_merge_tx_hex = '0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fde502483045022100ade686ada1bdadb2468b07f0699412c9d7016ca589633ac0730ea806c47437db022073f4f2a4e1bc2def562624d3ac86e4233410ca8aa84e102615ea3176fd84bb85414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fde5024830450221009a9a66120d3a5e7f7d936b6b3c5a50116922b0eb6ae6255cc2c4280bab7b2f8b02200cb7382c58409af60b09bde18c241316f68dd95f2d1326109142f7794953704a414d990201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdfa0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffbeeb1fa51feba41db76fb4b7c36a128ec3bec67bada65fbf951be782f1d1c09e0000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000069463043021f10b0ce2db56a17ad04c53de15da45671cd370f10aef72f52f1b07d41c9c4c102206ccf57f5b8e81448179f0882f269ffca5baddf87066c7c2cbf48fa4a6c0b7e7c412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01d0b40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000'

  it 'builds the cross-tier merge vector byte for byte' do
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    src = File.expand_path('../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts', __dir__)
    art = Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(src)))
    expect(art.parent_class).to eq('StatefulSmartContract')
    expect(art.state_fields).to be_empty

    signer = Runar::SDK::LocalSigner.new('0000000000000000000000000000000000000000000000000000000000000003')
    address = signer.get_address
    pub_key = signer.get_public_key
    locking_hex = Runar::SDK::RunarContract.new(art, [pub_key]).get_locking_script

    primary = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000, script: locking_hex)
    extra = Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 1, satoshis: 7_000, script: locking_hex)

    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(address, Runar::SDK::Utxo.new(
      txid: 'bb' * 32, output_index: 0, satoshis: 100_000, script: Runar::SDK.build_p2pkh_script(address)
    ))
    provider.add_contract_utxo(locking_hex, primary)
    provider.add_contract_utxo("#{locking_hex}:extra", extra)

    contract = Runar::SDK::RunarContract.from_utxo(art, primary)
    contract.call('claim', [nil, nil], provider, signer,
                  Runar::SDK::CallOptions.new(additional_contract_inputs: [extra]))

    expect(provider.get_broadcasted_txs.last).to eq(n258_merge_tx_hex)
  end
end
