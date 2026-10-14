# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'
require 'open3'
require 'tmpdir'

# Issue #123 — per-method @sighash mode threaded through the SDK preimage/signing.
#
# compute_op_push_tx takes an optional sighash_type driving BOTH the BIP-143
# scope (which preimage fields get zeroed) and the appended DER sighash flag
# byte. The hand-rolled preimage mirrors the BIP-143 zeroing: hashPrevouts under
# ANYONECANPAY, hashSequence unless pure ALL, hashOutputs under NONE, and — F5 —
# hashOutputs = output[inputIndex] ONLY under SINGLE.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Issue #123 — SDK sighash threading' do
  # rubocop:enable RSpec/DescribeClass
  S123_SUBSCRIPT = '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac'

  # A 1-input, 2-output raw tx (out0=1000 to bb*20, out1=2000 to cc*20).
  S123_OUT0 = 'e803000000000000' + '19' + '76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac'
  S123_OUT1 = 'd007000000000000' + '19' + '76a914cccccccccccccccccccccccccccccccccccccccc88ac'
  S123_TX2  = '0100000001' +
         ('aa' * 32) + '00000000' + '00' + 'ffffffff' +
         '02' + S123_OUT0 + S123_OUT1 +
         '00000000'
  S123_SATS = 50_000

  def dsha(hex)
    Runar::SDK.double_sha256(hex)
  end

  # --- appended sighash flag byte + preimage sighashType field ----------------

  describe 'appended sighash flag byte' do
    it 'default (0x41) is byte-identical to no argument' do
      sig_default, pre_default = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1)
      sig_explicit, pre_explicit = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x41)
      expect(sig_explicit).to eq(sig_default)
      expect(pre_explicit).to eq(pre_default)
      expect(sig_default[-2, 2]).to eq('41')
      expect(pre_default[-8, 8]).to eq('41000000') # sighashType (LE uint32)
    end

    it 'SINGLE|FORKID (0x43) appends 0x43 to the sig and the preimage sighashType' do
      sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x43)
      expect(sig[-2, 2]).to eq('43')
      expect(pre[-8, 8]).to eq('43000000')
    end

    it 'ANYONECANPAY (0xC1) appends 0xc1' do
      sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0xc1)
      expect(sig[-2, 2]).to eq('c1')
      expect(pre[-8, 8]).to eq('c1000000')
    end
  end

  # --- BIP-143 field zeroing --------------------------------------------------

  describe 'BIP-143 field zeroing' do
    let(:all_hashoutputs)    { dsha(S123_OUT0 + S123_OUT1) }
    let(:single_hashoutputs) { dsha(S123_OUT0) } # F5: same-index (input 0) only
    let(:zero32)             { '00' * 32 }

    it 'ALL commits hashOutputs over the whole output set' do
      _sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x41)
      expect(pre).to include(all_hashoutputs)
    end

    it 'SINGLE commits hashOutputs to output[inputIndex] ONLY (F5)' do
      _sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x43)
      expect(pre).to include(single_hashoutputs)
      expect(pre).not_to include(all_hashoutputs)
    end

    it 'NONE zeroes hashOutputs' do
      # sighashType field is also 02000000, so match the hashOutputs slot: it
      # differs from both the ALL and SINGLE digests and equals 32 zero bytes.
      _sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x42)
      expect(pre).not_to include(all_hashoutputs)
      expect(pre).not_to include(single_hashoutputs)
      # hashOutputs slot immediately precedes nLocktime(00000000) + sighashType.
      expect(pre[-8 - 8 - 64, 64]).to eq(zero32)
    end

    it 'ANYONECANPAY zeroes hashPrevouts (the all-inputs digest)' do
      _sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0xc1)
      # hashPrevouts occupies bytes [4, 36) of the preimage.
      expect(pre[8, 64]).to eq(zero32)
    end

    it 'non-ALL zeroes hashSequence (bytes [36, 68))' do
      _sig, pre = Runar::SDK.compute_op_push_tx(S123_TX2, 0, S123_SUBSCRIPT, S123_SATS, -1, 0x43)
      expect(pre[72, 64]).to eq(zero32)
    end
  end

  # --- End-to-end: a SINGLE|FORKID method's call builds a 0x43 preimage -------

  S123_SINGLE_SRC = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public bump(): void { this.addOutput(1000n, this.n); }
    }
  TS

  def compile_single
    repo_root = File.expand_path('../../../..', __dir__)
    cli = File.join(repo_root, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')
    return nil unless File.exist?(cli)

    # Per-call private temp dir (not the shared Dir.tmpdir root) so a
    # concurrent compile of this same spec can't collide on the filename
    # the CLI dispatches on (CK18-FU8).
    Dir.mktmpdir do |dir|
      src_path = File.join(dir, 'SingleCounter.runar.ts')
      File.write(src_path, S123_SINGLE_SRC)
      out, _err, status = Open3.capture3('ruby', cli, '--source', src_path)
      return status.success? ? out : nil
    end
  end

  it 'ABI advertises SINGLE|FORKID (0x43) so the SDK builds the matching preimage' do
    compiled = compile_single
    skip 'Ruby compiler CLI unavailable' if compiled.nil?

    artifact = Runar::SDK::RunarArtifact.from_json(compiled)
    bump = artifact.abi.methods.find { |m| m.name == 'bump' }
    expect(bump.sig_hash_type).to eq(0x43)

    contract = Runar::SDK::RunarContract.new(artifact, [0])
    expect(contract.send(:resolve_sighash_type, 'bump')).to eq(0x43)
    # A method with no directive falls back to 0x41.
    expect(contract.send(:resolve_sighash_type, 'nonexistent')).to eq(0x41)
  end
end
