# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'
require 'tmpdir'
require_relative '../support/ruby_compiler_cli'

# Issue #106 — EMPTY_SIG producer-side convention for OR-CHECKSIG branched auth.
#
# An OR-CHECKSIG method — checkSig(sigA, pkA) || checkSig(sigB, pkB) — runs BOTH
# OP_CHECKSIG branches (|| lowers to the non-lazy OP_BOOLOR). Only the matching
# branch supplies a real signature; the failing branch MUST push an empty
# signature (OP_0) or BIP146 NULLFAIL rejects the whole spend.
#
# Ruby ships no off-chain ScriptVM, so parity with the TS reference is asserted
# at the WIRE level: with [nil, EMPTY_SIG] the failing branch's push is OP_0
# (empty); with [nil, nil] both slots carry the same non-empty signature (the
# byte pattern a NULLFAIL-enforcing node rejects).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Issue #106 — EMPTY_SIG for OR-CHECKSIG branched authorization' do
  # rubocop:enable RSpec/DescribeClass
  E106_SRC = <<~TS
    import { SmartContract, assert, checkSig } from 'runar-lang';
    import type { PubKey, Sig } from 'runar-lang';
    class OrChecksig extends SmartContract {
      readonly pkA: PubKey;
      readonly pkB: PubKey;
      constructor(pkA: PubKey, pkB: PubKey) { super(pkA, pkB); this.pkA = pkA; this.pkB = pkB; }
      public execute(sigA: Sig, sigB: Sig): void {
        assert(checkSig(sigA, this.pkA) || checkSig(sigB, this.pkB));
      }
    }
  TS

  E106_ALICE_KEY = ('00' * 31) + '03'
  E106_BOB_KEY   = ('00' * 31) + '07'

  def compile_or_checksig
    # Per-call private temp dir (not the shared Dir.tmpdir root) so a
    # concurrent compile of this same spec can't collide on the filename
    # the CLI dispatches on (CK18-FU8).
    Dir.mktmpdir do |dir|
      src_path = File.join(dir, 'OrChecksig.runar.ts')
      File.write(src_path, E106_SRC)
      return RubyCompilerCli.compile(src_path)
    end
  end

  # Parse input[0]'s unlocking-script hex out of a raw transaction hex.
  def input0_unlock(tx_hex)
    i = 8
    i += 2 # input count varint (single contract input)
    i += 64 + 8 # txid + vout
    slen = tx_hex[i, 2].to_i(16)
    i += 2
    if slen == 0xfd
      slen = (tx_hex[i + 2, 2].to_i(16) * 256) + tx_hex[i, 2].to_i(16)
      i += 4
    end
    tx_hex[i, slen * 2]
  end

  # Parse the data elements pushed by a scriptSig hex. OP_0 yields an empty push.
  def parse_pushes(script_hex)
    pushes = []
    p = 0
    n = script_hex.length / 2
    byte_at = ->(idx) { script_hex[idx * 2, 2].to_i(16) }
    while p < n
      op = byte_at.call(p)
      p += 1
      if op.zero?
        pushes << '' # OP_0 -> empty push
      elsif op >= 0x01 && op <= 0x4b
        pushes << script_hex[p * 2, op * 2]
        p += op
      elsif op == 0x4c
        len = byte_at.call(p)
        p += 1
        pushes << script_hex[p * 2, len * 2]
        p += len
      else
        pushes << '' # bare opcode (not expected here)
      end
    end
    pushes
  end

  def deploy_or_checksig
    compiled = compile_or_checksig
    return nil if compiled.nil?

    artifact = Runar::SDK::RunarArtifact.from_json(compiled)
    alice = Runar::SDK::LocalSigner.new(E106_ALICE_KEY)
    bob   = Runar::SDK::LocalSigner.new(E106_BOB_KEY)
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(
      alice.get_address,
      Runar::SDK::Utxo.new(
        txid: 'aa' * 32, output_index: 0, satoshis: 500_000,
        script: '76a914' + ('00' * 20) + '88ac'
      )
    )
    contract = Runar::SDK::RunarContract.new(artifact, [alice.get_public_key, bob.get_public_key])
    contract.connect(provider, alice)
    contract.deploy
    { contract: contract, provider: provider }
  end

  describe 'EMPTY_SIG sentinel' do
    it 'is recognised by empty_sig? and distinct from nil / hex' do
      expect(Runar::SDK.empty_sig?(Runar::SDK::EMPTY_SIG)).to be(true)
      expect(Runar::SDK.empty_sig?(nil)).to be(false)
      expect(Runar::SDK.empty_sig?('00' * 72)).to be(false)
    end

    it 'encodes EMPTY_SIG as OP_0 (empty signature push)' do
      artifact = Runar::SDK::RunarArtifact.from_json(
        compile_or_checksig || (skip 'Ruby compiler CLI unavailable')
      )
      alice = Runar::SDK::LocalSigner.new(E106_ALICE_KEY)
      bob = Runar::SDK::LocalSigner.new(E106_BOB_KEY)
      contract = Runar::SDK::RunarContract.new(artifact, [alice.get_public_key, bob.get_public_key])
      expect(contract.send(:encode_arg, Runar::SDK::EMPTY_SIG)).to eq('00')
    end
  end

  it 'GREEN: [nil, EMPTY_SIG] leaves the failing branch OP_0 (empty)' do
    setup = deploy_or_checksig
    skip 'Ruby compiler CLI unavailable' if setup.nil?

    setup[:contract].call('execute', [nil, Runar::SDK::EMPTY_SIG])
    call_tx = setup[:provider].get_broadcasted_txs.last
    pushes = parse_pushes(input0_unlock(call_tx))

    expect(pushes.length).to eq(2)
    expect(pushes[0].length).to be > 0 # branch A: real signature
    expect(pushes[1]).to eq('')        # branch B: OP_0 — satisfies NULLFAIL
  end

  it 'RED baseline: [nil, nil] fills the failing branch with a non-empty sig' do
    setup = deploy_or_checksig
    skip 'Ruby compiler CLI unavailable' if setup.nil?

    setup[:contract].call('execute', [nil, nil])
    call_tx = setup[:provider].get_broadcasted_txs.last
    pushes = parse_pushes(input0_unlock(call_tx))

    expect(pushes.length).to eq(2)
    expect(pushes[0].length).to be > 0 # branch A: real signature
    expect(pushes[1].length).to be > 0 # branch B: non-empty -> trips NULLFAIL
    expect(pushes[1]).to eq(pushes[0]) # same single-signer signature in both slots
  end
end
