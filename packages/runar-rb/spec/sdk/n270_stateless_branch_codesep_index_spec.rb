# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# N-270: the "stateless branch" of +call+ (taken whenever +is_stateful+ —
# derived from a non-empty +state_fields+ — is false, which includes a
# zero-mutable-field +StatefulSmartContract+) computes +code_sep_idx+ via
# +get_code_sep_index(find_method_index(method_name))+ unconditionally, never
# gated on +is_stateful+ (see +contract.rb+ line ~472). This is the behaviour
# TS and Go's +prepareCall+ lacked (see
# packages/runar-sdk/src/__tests__/n270-stateless-branch-codesep-index.test.ts
# and packages/runar-go/sdk_n270_stateless_branch_codesep_index_test.go, each
# fixed alongside this item).
#
# +TwoMethodReadonly+ has ZERO mutable fields but two public methods, each
# with its own auto-injected checkPreimage and its own OP_CODESEPARATOR at a
# DIFFERENT byte offset.
#
# Proves: the Ruby SDK builds the +methodB+ (real index 1) call tx byte for
# byte identical to the TS SDK's (and the never-buggy Python SDK's, used as
# an independent oracle before this value was pinned here) vector — i.e.
# Ruby was never buggy here. Ruby ships no script interpreter, so script
# validity in this tier rests on that byte parity with the interpreter-
# checked tiers (TS/Go).
#
# Does NOT prove: the terminal-call branch, a merge
# (+additional_contract_inputs+) on this fixture, or any tier besides
# TS/Go/Python (this spec is a parity pin, not a TDD red/green item — Ruby
# had no bug to fix).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-270 stateless-branch OP_PUSH_TX uses the REAL method index' do
  # rubocop:enable RSpec/DescribeClass
  N270_SRC = <<~TS
    import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
    class TwoMethodReadonly extends StatefulSmartContract {
      readonly owner: PubKey;
      constructor(owner: PubKey) { super(owner); this.owner = owner; }
      public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
      public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
    }
  TS

  n270_method_b_tx_hex = '0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc202473044022025bdb788c88800da0e122ee07bd7e7cf108c4c6d53ebf09ed2ed7f37e4ab1ec3022012880daf6cb232de74f645e6c69e69b74e7096257735aea1ff394d87d6309fcf414d760201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdd70176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000'

  def load_artifact(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'TwoMethodReadonly.runar.ts')
    File.write(path, N270_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  it 'fixture has distinct per-method code separators (discriminating precondition)' do
    Dir.mktmpdir do |dir|
      art = load_artifact(dir)
      expect(art.parent_class).to eq('StatefulSmartContract')
      expect(art.state_fields).to be_empty
      expect(art.code_separator_indices.length).to eq(2)
      expect(art.code_separator_indices[0]).not_to eq(art.code_separator_indices[1])
    end
  end

  it 'builds the methodB (real index 1) cross-tier vector byte for byte' do
    Dir.mktmpdir do |dir|
      art = load_artifact(dir)

      signer = Runar::SDK::LocalSigner.new('0000000000000000000000000000000000000000000000000000000000000003')
      address = signer.get_address
      pub_key = signer.get_public_key
      locking_hex = Runar::SDK::RunarContract.new(art, [pub_key]).get_locking_script

      primary = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000, script: locking_hex)

      provider = Runar::SDK::MockProvider.new
      provider.add_utxo(address, Runar::SDK::Utxo.new(
        txid: 'bb' * 32, output_index: 0, satoshis: 100_000, script: Runar::SDK.build_p2pkh_script(address)
      ))
      provider.add_contract_utxo(locking_hex, primary)

      contract = Runar::SDK::RunarContract.from_utxo(art, primary)
      contract.call('methodB', [nil, nil], provider, signer)

      expect(provider.get_broadcasted_txs.last).to eq(n270_method_b_tx_hex)
    end
  end
end
