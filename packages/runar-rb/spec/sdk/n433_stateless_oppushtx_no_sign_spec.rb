# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-433 -- the stateless / zero-mutable-field prepare_call branch and the
# stateless terminal branch computed a k=1 OP_PUSH_TX ECDSA signature through
# SDK.compute_op_push_tx and never put it in any output (build_stateful_prefix
# discards its argument; the only reader of the value was a
# final_op_push_tx_sig emptiness flag that is true exactly when
# needs_op_push_tx is). They now use SDK.compute_op_push_tx_preimage (N-253).
#
# Proves: on each stateless path (zero-mutable merge with an extra contract
# input, single-input call, terminal call) zero OP_PUSH_TX signs happen,
# counted by spying SDK.sign_preimage_k1, and the broadcast bytes equal the
# pinned pre-change cross-tier vectors (N-258 merge, N-270 methodB, terminal
# vector captured at base).
# Does not prove anything on-chain: Ruby ships no script interpreter, so
# validity rests on byte parity with the interpreter-checked tiers.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-433 -- stateless OP_PUSH_TX paths compute no signature' do
  # rubocop:enable RSpec/DescribeClass
  n258_merge_tx_hex = '0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdea02473044022033b20ee497b244a5f44ea460cbeb66c867d72ee622cf6e8163651998b66da33d02200b7580e4c31b3bf66410bbd033e935bcf41449fcabfdf90275cc2a7df78f8911414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac778813000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdea0247304402203b86795685f996d25ad0c7db76fb2b1d3ba6e1127332ba7806f9786e6ef03d0602201eca36661b0bb5e080c43fe881cae23d59194a557a76fdbca879995aaabc2314414d9f0201000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fd000276aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f97c2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac77581b000000000000ffffffffe0fb8d8fe33024ae55861c19ec7c3056e7ba656aa6623274dc5d6140edcd3d370000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b483045022100fe183c7919d2e06724b2134fa072fa1d6a698eb1b6cc07dd42341eeff238c11f02200abfed215d06dcaae1226e0497cff4ef3834ea7043cdbb76af44104c630b7c25412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01ceb40100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000'
  n270_method_b_tx_hex = '0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc802473044022061c3519e6e4cfa60f9dde9c5f0d4e460e5ef60197ba44c0e71cca562c47c4a71022010e5eab8367b1acf7fd6ec54818e4dda8e47660e53190564d41e0b4904b37f49414d7c0201000000ef9b6802354444eada24842d68525e3b2860d0af5b1b6abc6c2438eb193da948752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffffb80a35939e20ceea1e5b24188c0630fdc61fad29e98ab26a0a7546b96748de06000000004100000051ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006a47304402200274b1644d07fe4be16d71199ab51edb6c62666285ae09526a0badb16bbc815c022019c1ea6f05f733859e15312ef965dd2cb0fb9d6f8c4632828763fc7a1fad2238412102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ffffffff01c9990100000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000'
  n433_terminal_tx_hex = '0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc8024730440220620e5c2cd05d97ca2d91951469bfc3a61a9bb4b1dc1959e16e510f69fba043e902203900d7ee047c058c57776952d71d634d41fe175107bbf35b5518275d8e38bb53414d7c02010000006324e33631b1cb491f73dac8baa476a642eaeccfc7e00c2708764468c82a4e6c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddd0176aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad698254947f7701007e8101419d2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac688813000000000000ffffffff5a1ddad12332f96e1d310e510254be705e6fea5b749df0e0192092b1d56a4c14000000004100000051ffffffff01a00f0000000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac00000000'

  two_method_src = <<~TS
    import { StatefulSmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';
    class TwoMethodReadonly extends StatefulSmartContract {
      readonly owner: PubKey;
      constructor(owner: PubKey) { super(owner); this.owner = owner; }
      public methodA(sig: Sig): void { assert(checkSig(sig, this.owner)); }
      public methodB(sig: Sig): void { assert(checkSig(sig, this.owner)); }
    }
  TS

  def n433_artifact(src_path)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(src_path)))
  end

  def n433_count_signs
    count = 0
    allow(Runar::SDK).to receive(:sign_preimage_k1).and_wrap_original do |m, *args|
      count += 1
      m.call(*args)
    end
    -> { count }
  end

  def n433_setup(art)
    signer = Runar::SDK::LocalSigner.new('0000000000000000000000000000000000000000000000000000000000000003')
    pub_key = signer.get_public_key
    locking_hex = Runar::SDK::RunarContract.new(art, [pub_key]).get_locking_script
    primary = Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000, script: locking_hex)
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(signer.get_address, Runar::SDK::Utxo.new(
      txid: 'bb' * 32, output_index: 0, satoshis: 100_000, script: Runar::SDK.build_p2pkh_script(signer.get_address)
    ))
    provider.add_contract_utxo(locking_hex, primary)
    [signer, pub_key, primary, provider, locking_hex]
  end

  def n433_two_method_artifact(src)
    require 'tmpdir'
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'TwoMethodReadonly.runar.ts')
      File.write(path, src)
      n433_artifact(path)
    end
  end

  it 'zero-mutable merge computes no signature and keeps the N-258 bytes' do
    art = n433_artifact(File.expand_path('../../../../examples/ts/all-readonly-cleanstack/AllReadonlyCleanstack.runar.ts', __dir__))
    signer, _pub, primary, provider, locking_hex = n433_setup(art)
    extra = Runar::SDK::Utxo.new(txid: 'cc' * 32, output_index: 1, satoshis: 7_000, script: locking_hex)
    provider.add_contract_utxo("#{locking_hex}:extra", extra)
    signs = n433_count_signs
    Runar::SDK::RunarContract.from_utxo(art, primary).call(
      'claim', [nil, nil], provider, signer,
      Runar::SDK::CallOptions.new(additional_contract_inputs: [extra])
    )
    expect(signs.call).to eq(0)
    expect(provider.get_broadcasted_txs.last).to eq(n258_merge_tx_hex)
  end

  it 'stateless single-input call computes no signature and keeps the N-270 bytes' do
    art = n433_two_method_artifact(two_method_src)
    signer, _pub, primary, provider, = n433_setup(art)
    signs = n433_count_signs
    Runar::SDK::RunarContract.from_utxo(art, primary).call('methodB', [nil, nil], provider, signer)
    expect(signs.call).to eq(0)
    expect(provider.get_broadcasted_txs.last).to eq(n270_method_b_tx_hex)
  end

  it 'stateless terminal call computes no signature and keeps the pre-change bytes' do
    art = n433_two_method_artifact(two_method_src)
    signer, pub_key, primary, provider, = n433_setup(art)
    signs = n433_count_signs
    Runar::SDK::RunarContract.from_utxo(art, primary).call(
      'methodB', [nil, nil], provider, signer,
      Runar::SDK::CallOptions.new(
        terminal_outputs: [Runar::SDK::TerminalOutput.new(script_hex: Runar::SDK.build_p2pkh_script(pub_key), satoshis: 4_000)]
      )
    )
    expect(signs.call).to eq(0)
    expect(provider.get_broadcasted_txs.last).to eq(n433_terminal_tx_hex)
  end
end
