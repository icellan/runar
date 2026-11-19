# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'digest'
require 'runar/sdk'

# D25 (twin-input binding) — the Ruby SDK builds valid call transactions for
# both new continuation shapes. Port of the honest-chain half of
# packages/runar-sdk/src/__tests__/d25-twin-input.test.ts.
#
# Class 1 (Counter, every continuation method mutate-only): methods carry ABI
# sigHashType 0x43 and take (_newAmount, txPreimage); the covenant preimage is
# built under SINGLE|FORKID and its hashOutputs is hash256(output[0]) alone.
# Class 2 (MixedPot, an auto-continuation beside an addOutput method): the
# state carries a trailing _spentOutpointHash = sha256(outpoint of the spent
# UTXO), zero at deploy; every method stays ALL|FORKID.
#
# Proves (through the validating MockProvider, which checks every broadcast
# parses, spends known outpoints and conserves value): two chained honest
# calls of each method build transactions whose covenant preimage, read back
# from the PreparedCall, carries the method's sighash type, the REAL spent
# outpoint, and a hashOutputs equal to the BIP-143 digest this spec recomputes
# from its own parse of the transaction (output[0] alone under SINGLE, every
# output under ALL); the continuation is output 0, carries at least the input
# amount (F-024 floor) and equals the SDK's tracked post-state script; the
# class-2 hidden field equals sha256(spent outpoint) in the tracked state and
# in the output script, for both the auto-continuation and the addOutput
# method. A user Sig under a SINGLE covenant gets the ALL|FORKID digest; a
# SINGLE call with additional_contract_inputs is refused before any build.
#
# Does NOT prove: script execution. The Ruby tier ships no Script VM (root
# CLAUDE.md, "Off-chain Script VM"), so no spec here runs the locking script;
# the on-chain verdict (honest spends accepted, twins rejected) rests on the
# TS @bsv/sdk Spend, go-sdk interpreter and Python bsv-sdk Spend replays of
# byte-identical scripts (the Ruby compiler matches the TS goldens).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'D25: twin-input continuation binding (SDK)' do
  # rubocop:enable RSpec/DescribeClass
  D25_COUNTER_SRC = File.expand_path('../../../../examples/ts/stateful-counter/Counter.runar.ts', __dir__)

  D25_MIXED_POT_SRC = <<~TS
    import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
    class MixedPot extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public increment() { this.count++; }
      public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
    }
  TS

  D25_SIGNED_COUNTER_SRC = <<~TS
    import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
    import type { PubKey, Sig } from 'runar-lang';
    class OwnedCounter extends StatefulSmartContract {
      count: bigint;
      readonly owner: PubKey;
      constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
      public increment(sig: Sig) { assert(checkSig(sig, this.owner)); this.count++; }
    }
  TS

  D25_PRIV_KEY = '11' * 32

  def compile_artifact(path)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  def compile_src(src, name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "#{name}.runar.ts")
      File.write(path, src)
      compile_artifact(path)
    end
  end

  def hash256_hex(hex)
    Digest::SHA256.hexdigest(Digest::SHA256.digest([hex].pack('H*')))
  end

  # A minimal independent tx parser: { inputs: [{ outpoint:, unlock: }], outputs: [{ satoshis:, script:, raw: }] }.
  def parse_tx(hex)
    b = [hex].pack('H*')
    pos = 4
    take = lambda do |n|
      s = b.byteslice(pos, n)
      pos += n
      s
    end
    varint = lambda do
      n = take.call(1).ord
      next n if n < 0xfd

      take.call({ 0xfd => 2, 0xfe => 4, 0xff => 8 }.fetch(n)).bytes.each_with_index.sum { |x, i| x << (8 * i) }
    end
    inputs = Array.new(varint.call) do
      outpoint = take.call(36).unpack1('H*')
      unlock = take.call(varint.call).unpack1('H*')
      take.call(4)
      { outpoint: outpoint, unlock: unlock }
    end
    outputs = Array.new(varint.call) do
      start = pos
      sats = take.call(8).unpack1('Q<')
      script = take.call(varint.call).unpack1('H*')
      { satoshis: sats, script: script, raw: b.byteslice(start, pos - start).unpack1('H*') }
    end
    { inputs: inputs, outputs: outputs }
  end

  # The BIP-143 fields a covenant reads, sliced from the END of the preimage
  # (scriptCode is variable-length): [outpoint, amount, hashOutputs, sighashType].
  def preimage_fields(pre_hex)
    b = [pre_hex].pack('H*')
    n = b.bytesize
    [
      b.byteslice(68, 36).unpack1('H*'),
      b.byteslice(n - 52, 8).unpack1('Q<'),
      b.byteslice(n - 40, 32).unpack1('H*'),
      b.byteslice(n - 4, 4).unpack1('V')
    ]
  end

  def outpoint_hex(utxo)
    [utxo.txid].pack('H*').reverse.unpack1('H*') + [utxo.output_index].pack('V').unpack1('H*')
  end

  def deployed(artifact, args, satoshis: 10_000)
    signer = Runar::SDK::LocalSigner.new(D25_PRIV_KEY)
    provider = Runar::SDK::MockProvider.new # validate_broadcasts: true (fail closed)
    provider.add_utxo(signer.get_address,
                      Runar::SDK::Utxo.new(txid: 'ab' * 32, output_index: 0, satoshis: 10_000_000,
                                           script: Runar::SDK.build_p2pkh_script(signer.get_address)))
    contract = Runar::SDK::RunarContract.new(artifact, args)
    contract.connect(provider, signer)
    contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: satoshis))
    [contract, provider, signer]
  end

  # One honest call through prepare_call + finalize_call. Returns
  # [spent_utxo, preimage_fields, parsed_tx].
  def honest_call(contract, provider, method, args = [])
    spent = contract.get_utxo
    prepared = contract.prepare_call(method, args)
    contract.finalize_call(prepared, {}, provider)
    tx = parse_tx(provider.get_broadcasted_txs.last)
    expect(provider.last_validated_input_count).to be >= 1
    expect(tx[:inputs][0][:outpoint]).to eq(outpoint_hex(spent))
    [spent, preimage_fields(prepared.preimage), tx]
  end

  describe 'class 1 (Counter, SINGLE default)' do
    let(:artifact) { compile_artifact(D25_COUNTER_SRC) }

    it 'carries sigHashType 0x43 and no change params' do
      %w[increment decrement].each do |name|
        m = artifact.abi.methods.find { |x| x.name == name }
        expect(m.sig_hash_type).to eq(0x43)
        expect(m.params.map(&:name)).to eq(%w[_newAmount txPreimage])
      end
      expect(artifact.state_fields.map(&:name)).to eq(['count'])
    end

    it 'chains two honest calls: SINGLE preimage committing output[0] alone, continuation at index 0' do
      contract, provider, = deployed(artifact, [0])
      [%w[increment 1], %w[increment 2], %w[decrement 1]].each do |method, want|
        spent, (outpoint, amount, hash_outputs, sighash), tx = honest_call(contract, provider, method)
        expect(sighash).to eq(0x43)
        expect(outpoint).to eq(outpoint_hex(spent))
        expect(amount).to eq(spent.satoshis)
        # SINGLE: hashOutputs = hash256(output[inputIndex = 0]) alone.
        expect(hash_outputs).to eq(hash256_hex(tx[:outputs][0][:raw]))
        expect(tx[:outputs].length).to be >= 2 # change after the continuation, uncommitted
        expect(hash_outputs).not_to eq(hash256_hex(tx[:outputs].map { |o| o[:raw] }.join))
        expect(tx[:outputs][0][:satoshis]).to be >= spent.satoshis # F-024 floor
        expect(tx[:outputs][0][:script]).to eq(contract.get_locking_script)
        expect(contract.get_state['count']).to eq(Integer(want))
      end
    end

    it 'refuses additional_contract_inputs into one SINGLE continuation before building' do
      contract, provider, = deployed(artifact, [0])
      before = provider.get_broadcasted_txs.length
      opts = Runar::SDK::CallOptions.new
      opts.additional_contract_inputs = [Runar::SDK::Utxo.new(txid: 'cd' * 32, output_index: 0, satoshis: 10_000,
                                                              script: contract.get_utxo.script)]
      expect { contract.call('increment', [], nil, nil, opts) }
        .to raise_error(ArgumentError,
                        /additionalContractInputs cannot be spent into one continuation by a SIGHASH_SINGLE method/)
      expect(provider.get_broadcasted_txs.length).to eq(before)
    end
  end

  describe 'class 1 with a user Sig' do
    it 'PreparedCall#sighash is the ALL|FORKID digest while the covenant preimage stays SINGLE' do
      artifact = compile_src(D25_SIGNED_COUNTER_SRC, 'OwnedCounter')
      signer = Runar::SDK::LocalSigner.new(D25_PRIV_KEY)
      inc = artifact.abi.methods.find { |m| m.name == 'increment' }
      expect(inc.sig_hash_type).to eq(0x43)
      contract, provider, = deployed(artifact, [0, signer.get_public_key])
      spent = contract.get_utxo
      prepared = contract.prepare_call('increment', [nil])
      expect(preimage_fields(prepared.preimage)[3]).to eq(0x43)

      # Independent digest: BIP-143 ALL|FORKID over the same tx, the
      # post-OP_CODESEPARATOR subscript (stateful contract), input 0.
      subscript = spent.script
      subscript = subscript[((prepared.code_sep_idx + 1) * 2)..] if prepared.code_sep_idx >= 0
      tx = Runar::SDK::BIP143.parse_raw_tx([prepared.tx_hex].pack('H*'))
      want = Runar::SDK::BIP143.bip143_sighash(tx, 0, [subscript].pack('H*'), spent.satoshis, 0x41).unpack1('H*')
      expect(prepared.sighash).to eq(want)
      expect(prepared.sighash).not_to eq(hash256_hex(prepared.preimage))

      # And call() (which signs with the default ALL|FORKID) still broadcasts.
      contract.call('increment', [nil], provider, signer)
      expect(contract.get_state['count']).to eq(1)
    end
  end

  describe 'class 2 (MixedPot, hidden spent-outpoint field)' do
    let(:artifact) { compile_src(D25_MIXED_POT_SRC, 'MixedPot') }
    let(:field) { '_spentOutpointHash' }

    it 'appends a zero-initialised Sha256 state field outside the constructor ABI; methods stay ALL' do
      expect(artifact.state_fields.map(&:name)).to eq(['count', field])
      expect(artifact.abi.constructor_params.map(&:name)).to eq(['count'])
      expect(artifact.abi.methods.find { |m| m.name == 'increment' }.sig_hash_type).to be_nil
      expect(artifact.abi.methods.find { |m| m.name == 'bump' }.sig_hash_type).to be_nil
      contract, = deployed(artifact, [0])
      expect(contract.get_state[field]).to eq('00' * 32)
      expect(contract.get_locking_script).to end_with('00' * 32)
    end

    it 'chains honest calls of both methods, committing sha256(the real spent outpoint)' do
      contract, provider, = deployed(artifact, [0])
      [%w[increment 1], %w[bump 2], %w[increment 3], %w[bump 4]].each do |method, want|
        spent, (outpoint, _amount, hash_outputs, sighash), tx = honest_call(contract, provider, method)
        binding = Digest::SHA256.hexdigest([outpoint_hex(spent)].pack('H*'))
        expect(sighash).to eq(0x41)
        expect(outpoint).to eq(outpoint_hex(spent))
        # ALL: hashOutputs = hash256(every output, change included).
        expect(hash_outputs).to eq(hash256_hex(tx[:outputs].map { |o| o[:raw] }.join))
        expect(tx[:outputs][0][:satoshis]).to be >= spent.satoshis
        expect(tx[:outputs][0][:script]).to eq(contract.get_locking_script)
        expect(tx[:outputs][0][:script]).to end_with(binding)
        expect(contract.get_state[field]).to eq(binding)
        expect(contract.get_state['count']).to eq(Integer(want))
      end
    end

    # CallOptions#new_state / #outputs never name the hidden field. The SDK
    # must write sha256(the outpoint this call spends) itself: left out,
    # serialize_state has no value; copied from get_state, it is the previous
    # outpoint's hash and the covenant rejects the spend. No Script VM in this
    # tier: the continuation is compared with a locking script this spec
    # builds itself (code part || OP_RETURN || count as 8-byte LE || binding).
    it 'writes sha256(the real spent outpoint) into caller-supplied state (outputs, stale and partial new_state)' do
      contract, provider, = deployed(artifact, [1])
      deploy_state = "#{[1].pack('q<').unpack1('H*')}#{'00' * 32}"
      expect(contract.get_utxo.script).to end_with("6a#{deploy_state}")
      code_part = contract.get_utxo.script[0...-(2 + deploy_state.length)]
      expected_script = lambda do |count, spent|
        binding = Digest::SHA256.hexdigest([outpoint_hex(spent)].pack('H*'))
        "#{code_part}6a#{[count].pack('q<').unpack1('H*')}#{binding}"
      end
      broadcast_continuation = lambda do |method, opts|
        spent = contract.get_utxo
        before = provider.get_broadcasted_txs.length
        contract.call(method, [], provider, nil, opts)
        expect(provider.get_broadcasted_txs.length).to eq(before + 1)
        expect(provider.last_validated_input_count).to be >= 1
        tx = parse_tx(provider.get_broadcasted_txs.last)
        expect(tx[:inputs][0][:outpoint]).to eq(outpoint_hex(spent))
        [spent, tx]
      end

      # 1. outputs: state without the hidden field.
      spent, tx = broadcast_continuation.call(
        'bump', Runar::SDK::CallOptions.new(outputs: [Runar::SDK::OutputSpec.new(satoshis: 10_000, state: { 'count' => 2 })])
      )
      expect(tx[:outputs][0][:script]).to eq(expected_script.call(2, spent))
      expect(contract.get_utxo.script).to eq(expected_script.call(2, spent))

      # 2. new_state copied from get_state (the stale deploy-time hash).
      stale = contract.get_state.dup.merge('count' => 3)
      expect(stale[field]).to eq('00' * 32)
      spent, tx = broadcast_continuation.call('increment', Runar::SDK::CallOptions.new(new_state: stale))
      expect(tx[:outputs][0][:script]).to eq(expected_script.call(3, spent))
      expect(contract.get_state[field]).to eq(Digest::SHA256.hexdigest([outpoint_hex(spent)].pack('H*')))
      expect(contract.get_locking_script).to eq(expected_script.call(3, spent))

      # 3. new_state without the field (the tracked one is now the previous call's).
      spent, tx = broadcast_continuation.call('increment', Runar::SDK::CallOptions.new(new_state: { 'count' => 4 }))
      expect(tx[:outputs][0][:script]).to eq(expected_script.call(4, spent))
      expect(contract.get_state[field]).to eq(Digest::SHA256.hexdigest([outpoint_hex(spent)].pack('H*')))
    end
  end
end
