# frozen_string_literal: true

# Intent-intrinsic ANF interpreter coverage (Ruby tier port of the TS
# reference suite at
# packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts).
#
# The compiler desugars the four intent-covenant intrinsics
# (+extractPrevOutputScript+, +requireOutputP2PKH+, +currentBlockHeight+,
# plus +len+-branching on a read-only intrinsic value) into ANF chains
# built from existing primitives (+load_param+, +hash256+, +substr+,
# +cat+, +num2bin+, +extractLocktime+, +extractOutputHash+, +bin_op+,
# +assert+). These tests exercise {Runar::SDK::ANFInterpreter
# .execute_strict_with_witness} against the four shipping conformance
# fixtures end-to-end, mirroring the TS coverage 1:1 (10 cases).

require 'spec_helper'
require 'json'
require 'digest'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::ANFInterpreter intent intrinsics' do
  # rubocop:enable RSpec/DescribeClass

  # Namespaced under the describe block so the constants don't collide
  # with same-named globals defined in other spec files (e.g.
  # +spec/sdk/compile_check_spec.rb+'s top-level REPO_ROOT).
  REPO = File.expand_path('../../../../..', __dir__).freeze
  IR   = File.join(REPO, 'conformance', 'tests').freeze

  def load_ir(name)
    JSON.parse(File.read(File.join(IR, name, 'expected-ir.json')))
  end

  # Double-SHA256 (Bitcoin hash256) of a raw 8-bit byte string, returned
  # as a lowercase hex string (matching ANF interpreter byte conventions).
  def hash256_hex(bytes)
    once = Digest::SHA256.digest(bytes)
    Digest::SHA256.hexdigest(once)
  end

  def hex(bytes)
    bytes.unpack1('H*')
  end

  def from_hex(s)
    [s].pack('H*')
  end

  # Build a canonical 34-byte P2PKH output: 8-byte LE amount ‖ 1976a914 ‖
  # pkh (20 bytes) ‖ 88ac.
  def p2pkh_output(amount, pkh_bytes)
    raise ArgumentError, 'pkh must be 20 bytes' if pkh_bytes.bytesize != 20

    amount_le = (0...8).map { |i| (amount >> (8 * i)) & 0xff }.pack('C*')
    amount_le + "\x19\x76\xa9\x14".b + pkh_bytes + "\x88\xac".b
  end

  # Wrap a +execute_strict_with_witness+ call in a TS-shaped result envelope
  # ({success, error, outputs}) so the assertions mirror the reference
  # vitest cases byte-for-byte.
  def call_intent(anf, method_name, current_state, args, **witness_opts)
    new_state, _data, _raw, state_outputs = Runar::SDK::ANFInterpreter
                                            .execute_strict_with_witness(
                                              anf, method_name, current_state, args, **witness_opts
                                            )
    { success: true, error: nil, state: new_state, outputs: state_outputs }
  rescue Runar::SDK::AssertionFailureError, RuntimeError => e
    { success: false, error: e.message, state: nil, outputs: [] }
  end

  # ---------------------------------------------------------------------
  # intent-prev-output-script
  # ---------------------------------------------------------------------

  context 'intent-prev-output-script' do
    let(:anf) { load_ir('intent-prev-output-script') }
    let(:prev_out_script_bytes) do
      from_hex('76a91400112233445566778899aabbccddeeff0011223388ac')
    end
    let(:expected_hash_hex) { hash256_hex(prev_out_script_bytes) }

    it 'success: hash256(witness) === expectedHash → call returns' do
      r = call_intent(
        anf, 'bind',
        { 'expectedHash' => expected_hash_hex, 'count' => 0 },
        {},
        witness_bytes: { '_prevOutScript_0' => prev_out_script_bytes },
      )
      expect(r[:success]).to be(true)
      expect(r[:error]).to be_nil
      expect(r[:state]['count']).to eq(1)
    end

    it 'failure: witness mismatches expectedHash → assertion failure' do
      r = call_intent(
        anf, 'bind',
        { 'expectedHash' => expected_hash_hex, 'count' => 0 },
        {},
        witness_bytes: { '_prevOutScript_0' => from_hex('deadbeef') },
      )
      expect(r[:success]).to be(false)
      expect(r[:error]).to match(/extractPrevOutputScript.*hash256/)
    end

    it 'failure: no witness supplied → explicit error' do
      r = call_intent(
        anf, 'bind',
        { 'expectedHash' => expected_hash_hex, 'count' => 0 },
        {},
      )
      expect(r[:success]).to be(false)
      expect(r[:error]).to match(/requires witness bytes/)
    end
  end

  # ---------------------------------------------------------------------
  # intent-output-p2pkh
  # ---------------------------------------------------------------------

  context 'intent-output-p2pkh' do
    let(:anf) { load_ir('intent-output-p2pkh') }
    let(:bond_pkh_bytes)  { from_hex('00112233445566778899aabbccddeeff00112233') }
    let(:bond_pkh_hex)    { bond_pkh_bytes.unpack1('H*') }
    let(:bond_amount)     { 5000 }
    let(:serialised)      { p2pkh_output(bond_amount, bond_pkh_bytes) }
    let(:output_hash_hex) { hash256_hex(serialised) }

    it 'success: serialised P2PKH bytes match expected → call returns' do
      r = call_intent(
        anf, 'payBond',
        { 'bondPKH' => bond_pkh_hex, 'bondAmount' => bond_amount, 'count' => 0 },
        {},
        witness_bytes:       { '_serialisedOutputs' => serialised },
        mock_preimage_bytes: { 'outputHash' => output_hash_hex },
      )
      expect(r[:success]).to be(true)
      expect(r[:error]).to be_nil
      expect(r[:state]['count']).to eq(1)
    end

    it 'failure: wrong pubkey-hash in serialised outputs → substring mismatch' do
      wrong_pkh_bytes = from_hex('ff' * 20)
      wrong_serialised = p2pkh_output(bond_amount, wrong_pkh_bytes)
      wrong_hash = hash256_hex(wrong_serialised)

      r = call_intent(
        anf, 'payBond',
        { 'bondPKH' => bond_pkh_hex, 'bondAmount' => bond_amount, 'count' => 0 },
        {},
        witness_bytes:       { '_serialisedOutputs' => wrong_serialised },
        # outer hash check must still pass so the per-output substr is
        # the assertion that trips.
        mock_preimage_bytes: { 'outputHash' => wrong_hash },
      )
      expect(r[:success]).to be(false)
      expect(r[:error]).to match(/requireOutputP2PKH.*mismatch/)
    end

    it 'failure: hashOutputs preimage mismatch → outer hash assertion' do
      r = call_intent(
        anf, 'payBond',
        { 'bondPKH' => bond_pkh_hex, 'bondAmount' => bond_amount, 'count' => 0 },
        {},
        witness_bytes:       { '_serialisedOutputs' => serialised },
        # Wrong outputHash on the preimage — desugar's first assertion fails.
        mock_preimage_bytes: { 'outputHash' => '00' * 32 },
      )
      expect(r[:success]).to be(false)
      expect(r[:error]).to match(/hash256\(serialisedOutputs\) !== preimage\.hashOutputs/)
    end
  end

  # ---------------------------------------------------------------------
  # intent-current-block-height
  # ---------------------------------------------------------------------

  context 'intent-current-block-height' do
    let(:anf) { load_ir('intent-current-block-height') }

    it 'success: locktime <= deadline → assertion holds' do
      r = call_intent(
        anf, 'spend',
        { 'deadline' => 1_000_000, 'count' => 0 },
        {},
        mock_preimage: { 'locktime' => 500_000 },
      )
      expect(r[:success]).to be(true)
      expect(r[:error]).to be_nil
      expect(r[:state]['count']).to eq(1)
    end

    it 'failure: locktime > deadline → assertion failure' do
      r = call_intent(
        anf, 'spend',
        { 'deadline' => 100, 'count' => 0 },
        {},
        mock_preimage: { 'locktime' => 999_999 },
      )
      expect(r[:success]).to be(false)
      expect(r[:error]).to match(/assert/i)
    end
  end

  # ---------------------------------------------------------------------
  # branched-readonly-len — both arms succeed (no failure path).
  # Validates that state mutation under a len(...)-driven branch executes
  # cleanly through the ANF interpreter.
  # ---------------------------------------------------------------------

  context 'branched-readonly-len' do
    let(:anf) { load_ir('branched-readonly-len') }

    it 'then-branch: len(scratch) > 0 → count += 1, tag := scratch' do
      r = call_intent(
        anf, 'spend',
        { 'count' => 10, 'tag' => '00' },
        { 'scratch' => 'aabbcc' },
      )
      expect(r[:success]).to be(true)
      expect(r[:error]).to be_nil
      expect(r[:state]['count']).to eq(11)
      expect(r[:state]['tag']).to eq('aabbcc')
      # Single addOutput emitted at 1000 satoshis.
      expect(r[:outputs].length).to eq(1)
      expect(r[:outputs][0][:satoshis]).to eq(1000)
    end

    it 'else-branch: len(scratch) == 0 → count -= 1, tag := "3030"' do
      r = call_intent(
        anf, 'spend',
        { 'count' => 10, 'tag' => 'aa' },
        { 'scratch' => '' },
      )
      expect(r[:success]).to be(true)
      expect(r[:error]).to be_nil
      expect(r[:state]['count']).to eq(9)
      expect(r[:state]['tag']).to eq('3030')
      expect(r[:outputs].length).to eq(1)
    end
  end
end
