# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'runar/sdk'

# D12 D2: the SDK ANF interpreter answered extractLocktime / extractSequence /
# extractOutpoint with dummies (0 / 0xfffffffe / 36 zero bytes). A state field
# derived from one of them got a value the script never computes, so the
# covenant refused the continuation. prepare_call now hands the interpreter
# the real values of the transaction it builds.
#
# Proves: with no locktime (input sequence 0xffffffff) and with locktime 500
# (sequence 0xfffffffe), the committed state equals the broadcast tx's own
# call options locktime, the input sequence resolve_input_sequence puts on
# input 0, and the spent outpoint (txid LE || vout LE).
# Does not prove: script acceptance (Ruby ships no ScriptVM).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'D12: preimage extractors see the real call transaction' do
  # rubocop:enable RSpec/DescribeClass
  let(:caller_address) { '00' * 20 }
  let(:caller_pub_key) { '02' + ('00' * 32) }

  PROBE_SRC = <<~TS
    import { StatefulSmartContract, ByteString, extractLocktime, extractSequence, extractOutpoint } from 'runar-lang';

    class Probe extends StatefulSmartContract {
      lt: bigint;
      sq: bigint;
      op: ByteString;
      constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }
      public probe() {
        this.lt = extractLocktime(this.txPreimage);
        this.sq = extractSequence(this.txPreimage);
        this.op = extractOutpoint(this.txPreimage);
      }
    }
  TS

  def load_probe(dir)
    compiler_lib = File.expand_path('../../../../compilers/ruby/lib', __dir__)
    $LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)
    require 'runar_compiler'
    path = File.join(dir, 'Probe.runar.ts')
    File.write(path, PROBE_SRC)
    Runar::SDK::RunarArtifact.from_json(RunarCompiler.artifact_to_json(RunarCompiler.compile_from_source(path)))
  end

  [[nil, 0xffffffff], [500, 0xfffffffe]].each do |locktime, want_seq|
    it "commits the tx's own locktime/sequence/outpoint (locktime=#{locktime.inspect})" do
      Dir.mktmpdir do |dir|
        contract = Runar::SDK::RunarContract.new(load_probe(dir), [7, 7, '00'])
        provider = Runar::SDK::MockProvider.new
        signer   = Runar::SDK::MockSigner.new(pub_key_hex: caller_pub_key, address: caller_address)
        contract.connect(provider, signer)
        provider.add_utxo(caller_address, Runar::SDK::Utxo.new(txid: 'aa' * 32, output_index: 0, satoshis: 5_000_000,
                                                               script: "76a914#{caller_address}88ac"))
        contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
        spent = contract.get_utxo
        opts = Runar::SDK::CallOptions.new
        opts.locktime = locktime
        contract.call('probe', [], nil, nil, opts)
        st = contract.get_state
        want_op = [spent.txid].pack('H*').reverse.unpack1('H*') + [spent.output_index].pack('V').unpack1('H*')
        expect(st['lt']).to eq(locktime || 0)
        expect(st['sq']).to eq(want_seq)
        expect(st['op']).to eq(want_op)
      end
    end
  end
end
