# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# F-164 (round 2): execute_strict must mock the WHOLE auto-injected
# stateful prologue (checkPreimage's assert AND the sighash-type assert),
# not just developer asserts.
#
# See packages/runar-sdk/src/anf-interpreter.ts for the TS reference this
# ports (detectAutoInjectedPrologueAsserts there,
# detect_auto_injected_prologue_asserts here).
#
# Round 1 of F-164 fixed the 'check_preimage' ANF-node kind to mock-return
# true in strict mode. That alone is NOT enough: the compiler's prologue
# also emits a SECOND, un-marked assert right after -- the sighash-type
# check (assert(extractSigHashType(txPreimage) === <mode>)) -- and
# extractSigHashType has no real/mock value off-chain. Before round 2, a
# strict-mode call against a REAL compiled stateful method would get past
# checkPreimage only to throw at the sighash-type assert instead -- never
# reaching the method's actual body.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::ANFInterpreter F-164 round 2' do
  # rubocop:enable RSpec/DescribeClass

  let(:mod) { Runar::SDK::ANFInterpreter }

  def load_tx_preimage(name)
    { 'name' => name, 'value' => { 'kind' => 'load_param', 'name' => 'txPreimage' } }
  end

  def check_preimage(name, preimage_ref)
    { 'name' => name, 'value' => { 'kind' => 'check_preimage', 'preimage' => preimage_ref } }
  end

  def assert_binding(name, pred_ref)
    { 'name' => name, 'value' => { 'kind' => 'assert', 'value' => pred_ref } }
  end

  def extract_sighash_call(name, preimage_ref)
    { 'name' => name, 'value' => { 'kind' => 'call', 'func' => 'extractSigHashType', 'args' => [preimage_ref] } }
  end

  def bin_op_eq(name, left, right)
    { 'name' => name, 'value' => { 'kind' => 'bin_op', 'op' => '===', 'left' => left, 'right' => right } }
  end

  def const(name, value)
    { 'name' => name, 'value' => { 'kind' => 'load_const', 'value' => value } }
  end

  # The exact 8-binding prologue compilers/ruby/.../anf_lower.rb's
  # stateful-prologue emitter injects at the START of every public stateful
  # method (mirrors compiled conformance/tests/stateful-counter
  # expected-ir.json: t0-t7), followed by whatever user_body bindings the
  # caller supplies.
  def full_prologue_anf(user_body)
    body = [
      load_tx_preimage('t0'),
      check_preimage('t1', 't0'),
      assert_binding('t2', 't1'),
      load_tx_preimage('t3'),
      extract_sighash_call('t4', 't3'),
      const('t5', 65),
      bin_op_eq('t6', 't4', 't5'),
      assert_binding('t7', 't6'),
    ] + user_body
    {
      'contractName' => 'Counter',
      'properties' => [{ 'name' => 'count', 'type' => 'bigint', 'readonly' => false }],
      'methods' => [
        {
          'name' => 'increment',
          'params' => [{ 'name' => 'txPreimage', 'type' => 'SigHashPreimage' }],
          'body' => body,
          'isPublic' => true,
        },
      ],
    }
  end

  it 'mocks the WHOLE auto-injected prologue, including the sighash-type assert' do
    anf = full_prologue_anf([
                               { 'name' => 't8', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
                               const('t9', 1),
                               { 'name' => 't10',
                                 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't8', 'right' => 't9' } },
                               { 'name' => 't11',
                                 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't10' } },
                             ])

    state, = mod.execute_strict(anf, 'increment', { 'count' => 0 }, {})
    expect(state['count']).to eq(1)
  end

  it 'does NOT mock a user-written assert that also calls extractSigHashType after the prologue' do
    anf = full_prologue_anf([
                               load_tx_preimage('u0'),
                               extract_sighash_call('u1', 'u0'),
                               const('u2', 1), # wrong expected mode (real mode is 65)
                               bin_op_eq('u3', 'u1', 'u2'),
                               assert_binding('userAssert', 'u3'),
                               { 'name' => 't8', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
                               const('t9', 1),
                               { 'name' => 't10',
                                 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't8', 'right' => 't9' } },
                               { 'name' => 't11',
                                 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't10' } },
                             ])

    expect { mod.execute_strict(anf, 'increment', { 'count' => 0 }, {}) }
      .to raise_error(Runar::SDK::AssertionFailureError) do |err|
        expect(err.binding_name).to eq('userAssert')
      end
  end
end
