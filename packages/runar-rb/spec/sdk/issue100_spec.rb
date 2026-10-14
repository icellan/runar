# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'
require 'open3'
require 'tmpdir'

# Issue #100: a terminal method that reads variable-length (ByteString) state
# must receive _codePart in its unlocking script. Without it the on-chain
# var-length deserialization is skipped and the read returns the deploy-time
# initial value instead of the live state.
#
# codePart is ~472 bytes, so its push begins with PUSHDATA2 (0x4d); without the
# fix the unlock would begin with the ~72-byte opSig push (0x48).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Issue #100 — terminal var-len state read gets _codePart' do
  # rubocop:enable RSpec/DescribeClass
  # Named I100_SRC (not the bare SRC the file used before) because `SRC = ...`
  # directly inside an `RSpec.describe do ... end` block defines a TOP-LEVEL
  # Ruby constant, not a scoped one — a bare `SRC` here collides with any
  # other spec file that also binds a bare `SRC` (e.g.
  # n227_zero_mutable_field_fee_floor_spec.rb), and whichever loads last
  # wins for every unqualified `SRC` reference for the rest of the process.
  # That is exactly why this item's own full-suite run showed
  # `uses_code_part` nil / wrong ABI methods and not alone (CK18-FU8). The
  # sibling issue106/issue123 specs already avoid this via distinct names
  # (`E106_SRC`, `S123_SINGLE_SRC`); this file now follows the same
  # convention.
  I100_SRC = <<~TS
    import { StatefulSmartContract, assert, substr } from 'runar-lang';
    import type { ByteString } from 'runar-lang';
    class StateRead extends StatefulSmartContract {
      s: ByteString;
      constructor(s: ByteString) { super(s); this.s = s; }
      public update(ns: ByteString): void { this.s = ns; }
      public termCheck(expected: ByteString): void { assert(substr(this.s, 8n, 20n) === expected); }
    }
  TS

  # Compile via the Ruby compiler CLI; skip cleanly if the repo layout/CLI is
  # unavailable (keeps the SDK gem's spec run self-contained).
  def compile_state_read(src = I100_SRC)
    repo_root = File.expand_path('../../../..', __dir__)
    cli = File.join(repo_root, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')
    return nil unless File.exist?(cli)

    # Per-call private temp dir (not the shared Dir.tmpdir root) so a
    # concurrent compile of this same spec can't collide on the filename
    # the CLI dispatches on (CK18-FU8).
    Dir.mktmpdir do |dir|
      src_path = File.join(dir, 'StateRead.runar.ts')
      File.write(src_path, src)
      yield if block_given?
      out, _err, status = Open3.capture3('ruby', cli, '--source', src_path)
      return status.success? ? out : nil
    end
  end

  # Parse input[0]'s unlocking-script hex out of a raw transaction hex.
  def input0_unlock(tx_hex)
    i = 8 # advance past the 4-byte version
    i += 2 # input count varint (single input)
    i += 64 + 8 # txid (32) + vout (4)
    slen = tx_hex[i, 2].to_i(16)
    i += 2
    if slen == 0xfd
      slen = (tx_hex[i + 2, 2].to_i(16) * 256) + tx_hex[i, 2].to_i(16)
      i += 4
    end
    tx_hex[i, slen * 2]
  end

  it 'marks the ABI method usesCodePart and prefixes the unlock with codePart' do
    compiled = compile_state_read
    skip 'Ruby compiler CLI unavailable' if compiled.nil?

    artifact = Runar::SDK::RunarArtifact.from_json(compiled)
    term = artifact.abi.methods.find { |m| m.name == 'termCheck' }
    expect(term.uses_code_part).to be(true)

    signer   = Runar::SDK::LocalSigner.new(('00' * 31) + '03')
    provider = Runar::SDK::MockProvider.new
    provider.add_utxo(
      signer.get_address,
      Runar::SDK::Utxo.new(
        txid: 'aa' * 32, output_index: 0, satoshis: 500_000,
        script: '76a914' + ('00' * 20) + '88ac'
      )
    )

    init = ('00' * 8) + ('cc' * 20)
    live = ('11' * 8) + ('dd' * 20)
    contract = Runar::SDK::RunarContract.new(artifact, [init])
    contract.connect(provider, signer)
    contract.deploy
    contract.call('update', [live])
    contract.call('termCheck', ['dd' * 20])

    unlock = input0_unlock(provider.get_broadcasted_txs.last)
    # PUSHDATA2 (0x4d) prefix => codePart push leads the unlock (issue #100).
    expect(unlock[0, 2]).to eq('4d')
  end

  # CK18-FU8: compile_state_read used to write its source to a single fixed
  # path (File.join(Dir.tmpdir, 'StateRead.runar.ts')) shared by every
  # caller. A second concurrent compile of this same file — another rspec
  # process running this spec at the same time, or a full-suite run
  # overlapping a solo run — writes to that identical path and can corrupt
  # whichever compile reads it last. This test forces that exact overlap
  # deterministically: the block passed to compile_state_read runs after
  # this call's own write but before its compiler subprocess reads the
  # file, simulating a second concurrent writer landing on the shared path.
  # It proves: a per-call-isolated temp path makes the compile immune to a
  # second writer on the legacy shared path, which is what CK18-FU8 fixes.
  # It does not prove: real OS-level process scheduling always produces
  # this exact interleaving in the wild — only that IF it does, the fix
  # tolerates it (the forced overlap removes timing luck from the proof).
  it 'is not corrupted by a second concurrent compile sharing the same tmp path' do
    other_src = I100_SRC.sub('termCheck', 'termCheckOther')

    compiled = compile_state_read do
      File.write(File.join(Dir.tmpdir, 'StateRead.runar.ts'), other_src)
    end
    skip 'Ruby compiler CLI unavailable' if compiled.nil?

    artifact = Runar::SDK::RunarArtifact.from_json(compiled)
    expect(artifact.abi.methods.map(&:name)).to include('termCheck')
  end
end
