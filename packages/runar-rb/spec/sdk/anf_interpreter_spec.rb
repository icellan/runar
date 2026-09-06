# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::ANFInterpreter' do
  # rubocop:enable RSpec/DescribeClass

  let(:mod) { Runar::SDK::ANFInterpreter }

  # ---------------------------------------------------------------------------
  # ANF IR fixtures
  # ---------------------------------------------------------------------------

  # Minimal Counter ANF with increment and decrement public methods.
  COUNTER_ANF = {
    'contractName' => 'Counter',
    'properties' => [
      { 'name' => 'count', 'type' => 'bigint', 'readonly' => false },
    ],
    'methods' => [
      {
        'name' => 'constructor',
        'params' => [{ 'name' => 'count', 'type' => 'bigint' }],
        'body' => [],
        'isPublic' => false,
      },
      {
        'name' => 'increment',
        'params' => [
          { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
          { 'name' => '_changePKH', 'type' => 'Addr' },
          { 'name' => '_changeAmount', 'type' => 'bigint' },
        ],
        'body' => [
          { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
          { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
          { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't0', 'right' => 't1' } },
          { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't2' } },
        ],
        'isPublic' => true,
      },
      {
        'name' => 'decrement',
        'params' => [
          { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
          { 'name' => '_changePKH', 'type' => 'Addr' },
          { 'name' => '_changeAmount', 'type' => 'bigint' },
        ],
        'body' => [
          { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
          { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
          { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '-', 'left' => 't0', 'right' => 't1' } },
          { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 't2' } },
        ],
        'isPublic' => true,
      },
    ],
  }.freeze

  # Counter that increments by 1 when count > 0, else by 2.
  BRANCH_COUNTER_ANF = {
    'contractName' => 'BranchCounter',
    'properties' => [
      { 'name' => 'count', 'type' => 'bigint', 'readonly' => false },
    ],
    'methods' => [
      {
        'name' => 'constructor',
        'params' => [{ 'name' => 'count', 'type' => 'bigint' }],
        'body' => [],
        'isPublic' => false,
      },
      {
        'name' => 'step',
        'params' => [
          { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
          { 'name' => '_changePKH', 'type' => 'Addr' },
          { 'name' => '_changeAmount', 'type' => 'bigint' },
        ],
        'body' => [
          { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
          { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 0 } },
          { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>', 'left' => 't0', 'right' => 't1' } },
          {
            'name' => 't3',
            'value' => {
              'kind' => 'if',
              'cond' => 't2',
              'then' => [
                { 'name' => 'ta0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
                { 'name' => 'ta1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
                { 'name' => 'ta2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 'ta0', 'right' => 'ta1' } },
                { 'name' => 'ta3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 'ta2' } },
              ],
              'else' => [
                { 'name' => 'tb0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
                { 'name' => 'tb1', 'value' => { 'kind' => 'load_const', 'value' => 2 } },
                { 'name' => 'tb2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 'tb0', 'right' => 'tb1' } },
                { 'name' => 'tb3', 'value' => { 'kind' => 'update_prop', 'name' => 'count', 'value' => 'tb2' } },
              ],
            },
          },
        ],
        'isPublic' => true,
      },
    ],
  }.freeze

  # Helper: build a minimal ANF fixture with a single arithmetic operation.
  def arith_anf(op)
    {
      'contractName' => 'Arith',
      'properties' => [
        { 'name' => 'result', 'type' => 'bigint', 'readonly' => false },
      ],
      'methods' => [
        { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
        {
          'name' => 'compute',
          'params' => [
            { 'name' => 'a', 'type' => 'bigint' },
            { 'name' => 'b', 'type' => 'bigint' },
          ],
          'body' => [
            { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
            { 'name' => 't1', 'value' => { 'kind' => 'load_param', 'name' => 'b' } },
            { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => op, 'left' => 't0', 'right' => 't1' } },
            { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't2' } },
          ],
          'isPublic' => true,
        },
      ],
    }
  end

  # Helper: build a hash-function ANF fixture.
  def hash_anf(func)
    {
      'contractName' => 'HashTest',
      'properties' => [
        { 'name' => 'digest', 'type' => 'ByteString', 'readonly' => false },
      ],
      'methods' => [
        { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
        {
          'name' => 'compute',
          'params' => [{ 'name' => 'data', 'type' => 'ByteString' }],
          'body' => [
            { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'data' } },
            { 'name' => 't1', 'value' => { 'kind' => 'call', 'func' => func, 'args' => ['t0'] } },
            { 'name' => 't2', 'value' => { 'kind' => 'update_prop', 'name' => 'digest', 'value' => 't1' } },
          ],
          'isPublic' => true,
        },
      ],
    }
  end

  # ---------------------------------------------------------------------------
  # compute_new_state — counter increment / decrement
  # ---------------------------------------------------------------------------

  describe '.compute_new_state' do
    context 'Counter increment' do
      it 'increments count from 0 to 1' do
        new_state = mod.compute_new_state(COUNTER_ANF, 'increment', { 'count' => 0 }, {})
        expect(new_state['count']).to eq(1)
      end

      it 'increments count from 5 to 6' do
        new_state = mod.compute_new_state(COUNTER_ANF, 'increment', { 'count' => 5 }, {})
        expect(new_state['count']).to eq(6)
      end

      it 'decrements count from 5 to 4' do
        new_state = mod.compute_new_state(COUNTER_ANF, 'decrement', { 'count' => 5 }, {})
        expect(new_state['count']).to eq(4)
      end
    end

    context 'if/else branch selection' do
      it 'takes the then-branch when count > 0 (adds 1)' do
        new_state = mod.compute_new_state(BRANCH_COUNTER_ANF, 'step', { 'count' => 3 }, {})
        expect(new_state['count']).to eq(4)
      end

      it 'takes the else-branch when count == 0 (adds 2)' do
        new_state = mod.compute_new_state(BRANCH_COUNTER_ANF, 'step', { 'count' => 0 }, {})
        expect(new_state['count']).to eq(2)
      end
    end

    context 'arithmetic operations' do
      it 'adds 3 + 4 to produce 7' do
        new_state = mod.compute_new_state(arith_anf('+'), 'compute', { 'result' => 0 }, { 'a' => 3, 'b' => 4 })
        expect(new_state['result']).to eq(7)
      end

      it 'subtracts 10 - 3 to produce 7' do
        new_state = mod.compute_new_state(arith_anf('-'), 'compute', { 'result' => 0 }, { 'a' => 10, 'b' => 3 })
        expect(new_state['result']).to eq(7)
      end

      it 'multiplies 5 * 6 to produce 30' do
        new_state = mod.compute_new_state(arith_anf('*'), 'compute', { 'result' => 0 }, { 'a' => 5, 'b' => 6 })
        expect(new_state['result']).to eq(30)
      end
    end

    context '@ref: aliases in load_const' do
      let(:ref_anf) do
        {
          'contractName' => 'RefTest',
          'properties' => [
            { 'name' => 'val', 'type' => 'bigint', 'readonly' => false },
          ],
          'methods' => [
            { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
            {
              'name' => 'copy',
              'params' => [{ 'name' => 'x', 'type' => 'bigint' }],
              'body' => [
                { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'x' } },
                { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => '@ref:t0' } },
                { 'name' => 't2', 'value' => { 'kind' => 'update_prop', 'name' => 'val', 'value' => 't1' } },
              ],
              'isPublic' => true,
            },
          ],
        }
      end

      it 'resolves @ref:t0 to the value of t0' do
        new_state = mod.compute_new_state(ref_anf, 'copy', { 'val' => 0 }, { 'x' => 42 })
        expect(new_state['val']).to eq(42)
      end
    end

    context 'unknown method' do
      it 'raises ArgumentError with "not found" in the message' do
        expect do
          mod.compute_new_state(COUNTER_ANF, 'nonexistent', { 'count' => 0 }, {})
        end.to raise_error(ArgumentError, /not found/)
      end
    end

    context 'implicit params' do
      it 'does not require txPreimage, _changePKH, or _changeAmount in args' do
        new_state = mod.compute_new_state(COUNTER_ANF, 'increment', { 'count' => 5 }, {})
        expect(new_state['count']).to eq(6)
      end
    end

    context 'hash built-ins' do
      it 'sha256 of empty input produces 64 hex chars (32 bytes)' do
        new_state = mod.compute_new_state(hash_anf('sha256'), 'compute', { 'digest' => '' }, { 'data' => '' })
        expect(new_state['digest'].length).to eq(64)
      end

      it 'hash256 of empty input produces 64 hex chars' do
        new_state = mod.compute_new_state(hash_anf('hash256'), 'compute', { 'digest' => '' }, { 'data' => '' })
        expect(new_state['digest'].length).to eq(64)
      end

      it 'hash160 of empty input produces 40 hex chars (20 bytes)' do
        new_state = mod.compute_new_state(hash_anf('hash160'), 'compute', { 'digest' => '' }, { 'data' => '' })
        expect(new_state['digest'].length).to eq(40)
      end

      it 'ripemd160 of empty input produces 40 hex chars' do
        new_state = mod.compute_new_state(hash_anf('ripemd160'), 'compute', { 'digest' => '' }, { 'data' => '' })
        expect(new_state['digest'].length).to eq(40)
      end
    end

    context 'checkSig mock' do
      let(:checksig_anf) do
        {
          'contractName' => 'SigTest',
          'properties' => [
            { 'name' => 'result', 'type' => 'bool', 'readonly' => false },
          ],
          'methods' => [
            { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
            {
              'name' => 'verify',
              'params' => [
                { 'name' => 'sig', 'type' => 'Sig' },
                { 'name' => 'pubKey', 'type' => 'PubKey' },
              ],
              'body' => [
                { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'sig' } },
                { 'name' => 't1', 'value' => { 'kind' => 'load_param', 'name' => 'pubKey' } },
                { 'name' => 't2', 'value' => { 'kind' => 'call', 'func' => 'checkSig', 'args' => ['t0', 't1'] } },
                { 'name' => 't3', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't2' } },
              ],
              'isPublic' => true,
            },
          ],
        }
      end

      it 'always returns true in simulation' do
        sig_hex = '00' * 72
        pk_hex  = '02' + 'ab' * 32
        new_state = mod.compute_new_state(
          checksig_anf, 'verify', { 'result' => false }, { 'sig' => sig_hex, 'pubKey' => pk_hex }
        )
        expect(new_state['result']).to be true
      end
    end

    context 'add_output state continuation' do
      let(:add_output_anf) do
        {
          'contractName' => 'StatefulCounter',
          'properties' => [
            { 'name' => 'count', 'type' => 'bigint', 'readonly' => false },
          ],
          'methods' => [
            { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
            {
              'name' => 'increment',
              'params' => [
                { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' },
                { 'name' => '_changePKH', 'type' => 'Addr' },
                { 'name' => '_changeAmount', 'type' => 'bigint' },
              ],
              'body' => [
                { 'name' => 't0', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
                { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
                { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 't0', 'right' => 't1' } },
                {
                  'name' => 't3',
                  'value' => {
                    'kind' => 'add_output',
                    'satoshis' => '_newAmount',
                    'stateValues' => ['t2'],
                  },
                },
              ],
              'isPublic' => true,
            },
          ],
        }
      end

      it 'maps stateValues to mutable props so count becomes 1' do
        new_state = mod.compute_new_state(add_output_anf, 'increment', { 'count' => 0 }, {})
        expect(new_state['count']).to eq(1)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # eval_bin_op — direct unit tests
  # ---------------------------------------------------------------------------

  describe '.eval_bin_op' do
    it 'adds integers' do
      expect(mod.eval_bin_op('+', 3, 4)).to eq(7)
    end

    it 'subtracts integers' do
      expect(mod.eval_bin_op('-', 10, 3)).to eq(7)
    end

    it 'multiplies integers' do
      expect(mod.eval_bin_op('*', 5, 6)).to eq(30)
    end

    it 'divides integers truncating toward zero (positive)' do
      expect(mod.eval_bin_op('/', 7, 2)).to eq(3)
    end

    it 'divides integers truncating toward zero (negative numerator)' do
      # -7 / 2: Python int(-7/2) = -3 (truncates toward zero)
      expect(mod.eval_bin_op('/', -7, 2)).to eq(-3)
    end

    it 'returns 0 on division by zero' do
      expect(mod.eval_bin_op('/', 5, 0)).to eq(0)
    end

    it 'computes modulo truncating toward zero' do
      expect(mod.eval_bin_op('%', 7, 3)).to eq(1)
    end

    it 'handles modulo with negative numerator (truncate-toward-zero)' do
      # -7 % 3: truncate_div(-7, 3) = -2, so -7 - (-2*3) = -1
      expect(mod.eval_bin_op('%', -7, 3)).to eq(-1)
    end

    it 'compares with ==' do
      expect(mod.eval_bin_op('==', 3, 3)).to be true
      expect(mod.eval_bin_op('==', 3, 4)).to be false
    end

    it 'compares with !=' do
      expect(mod.eval_bin_op('!=', 3, 4)).to be true
    end

    it 'evaluates && (and)' do
      expect(mod.eval_bin_op('&&', 1, 1)).to be true
      expect(mod.eval_bin_op('&&', 1, 0)).to be false
    end

    it 'evaluates || (or)' do
      expect(mod.eval_bin_op('||', 0, 1)).to be true
      expect(mod.eval_bin_op('||', 0, 0)).to be false
    end

    it 'concatenates byte strings when both operands are strings' do
      expect(mod.eval_bin_op('+', 'aabb', 'ccdd')).to eq('aabbccdd')
    end

    it 'concatenates byte strings when result_type is bytes' do
      expect(mod.eval_bin_op('+', 'aabb', 'ccdd', 'bytes')).to eq('aabbccdd')
    end

    it 'handles bitwise AND' do
      expect(mod.eval_bin_op('&', 0b1010, 0b1100)).to eq(0b1000)
    end

    it 'handles left shift' do
      expect(mod.eval_bin_op('<<', 1, 3)).to eq(8)
    end

    it 'handles right shift' do
      expect(mod.eval_bin_op('>>', 16, 2)).to eq(4)
    end
  end

  # ---------------------------------------------------------------------------
  # eval_unary_op — direct unit tests
  # ---------------------------------------------------------------------------

  describe '.eval_unary_op' do
    it 'negates an integer' do
      expect(mod.eval_unary_op('-', 5)).to eq(-5)
    end

    it 'applies logical not to a truthy value' do
      expect(mod.eval_unary_op('!', 1)).to be false
    end

    it 'applies logical not to a falsy value' do
      expect(mod.eval_unary_op('!', 0)).to be true
    end

    it 'applies bitwise not' do
      # OP_INVERT flips the operand's minimal script-number BYTES. 0 encodes to
      # the empty byte string, so ~0 is 0 (not native Ruby -1). See the
      # script-number byte-semantics block below.
      expect(mod.eval_unary_op('~', 0)).to eq(0)
    end

    it 'applies bitwise not to bytes when result_type is bytes' do
      # ~0x00 = 0xff; ~0xff = 0x00
      expect(mod.eval_unary_op('~', '00ff', 'bytes')).to eq('ff00')
    end
  end

  # ---------------------------------------------------------------------------
  # Script-number byte semantics for & | ^ ~ << >>
  #
  # These ops lower to OP_AND/OP_OR/OP_XOR/OP_INVERT/OP_LSHIFT/OP_RSHIFT, which
  # operate on the operands' MINIMAL script-number BYTES, not their numeric
  # value. The interpreter must agree with the deployed script byte-for-byte:
  # AND/OR/XOR abort on unequal operand lengths, shifts preserve byte length and
  # abort on negative counts, and INVERT flips each byte of the minimal
  # encoding. Mirrors packages/runar-testing/src/vm/utils.ts scriptNumber*.
  # ---------------------------------------------------------------------------

  describe 'script-number byte semantics' do
    it 'left-shifts on the byte string, not the numeric value' do
      expect(mod.eval_bin_op('<<', 255, 1)).to eq(254) # NOT 510
      expect(mod.eval_bin_op('<<', 256, 1)).to eq(512)
      expect(mod.eval_bin_op('<<', 5, 3)).to eq(40)
    end

    it 'right-shifts on the byte string, not the numeric value' do
      expect(mod.eval_bin_op('>>', 32, 3)).to eq(4)
      expect(mod.eval_bin_op('>>', 255, 1)).to eq(-127)
    end

    it 'inverts the minimal script-number bytes' do
      expect(mod.eval_unary_op('~', 5)).to eq(-122) # NOT -6
      expect(mod.eval_unary_op('~', 255)).to eq(-32512)
      expect(mod.eval_unary_op('~', 0)).to eq(0)
    end

    it 'AND/OR/XOR operate bytewise on equal-length operands' do
      expect(mod.eval_bin_op('&', 5, 3)).to eq(1)
      expect(mod.eval_bin_op('&', -1, 5)).to eq(1) # NOT 5
    end

    it 'aborts AND/OR when operand byte-lengths differ' do
      expect { mod.eval_bin_op('&', 255, 1) }.to raise_error(/OP_AND: operands must be same length/)
      expect { mod.eval_bin_op('|', 7, 0) }.to raise_error(/OP_OR: operands must be same length/)
    end

    it 'aborts on a negative shift count' do
      expect { mod.eval_bin_op('<<', 5, -1) }.to raise_error(/OP_LSHIFT: negative shift/)
    end
  end

  # ---------------------------------------------------------------------------
  # Chained script-number byte semantics (funds-relevant side-map threading)
  #
  # A single byte-array op on minimal operands is already correct. A CHAINED
  # expression diverges: a shift/bitwise RESULT is a fixed-length, possibly
  # NON-minimal byte array on-chain (e.g. `2 << 8` leaves a 1-byte 0x00, whose
  # minimal encoding of 0 is empty). Feeding that result to a length-sensitive
  # `& | ^`/shift makes a naive interpreter (which re-minimises the numeric
  # result) decide the byte length WRONG. The interpreter threads the real
  # stack bytes of each op's result through a per-binding side-map so a chained
  # op reads the deployed length, not a re-minimised one. Mirrors the TS
  # anf-interpreter scriptBytes threading.
  # ---------------------------------------------------------------------------

  describe 'chained script-number byte semantics' do
    # Build an ANF fixture computing `(a <shift_op> amount) <bitwise_op> other`
    # in two chained bin_op bindings — the shift result feeds the bitwise op.
    def chained_shift_bitwise_anf(shift_op, amount, bitwise_op, other)
      {
        'contractName' => 'Chained',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => amount } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => shift_op, 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => other } },
              { 'name' => 't4', 'value' => { 'kind' => 'bin_op', 'op' => bitwise_op, 'left' => 't2', 'right' => 't3' } },
              { 'name' => 't5', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't4' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    # Build an ANF fixture computing `~(a <shift_op> amount)` — the shift result
    # feeds a chained unary invert.
    def chained_shift_invert_anf(shift_op, amount)
      {
        'contractName' => 'ChainedInvert',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => amount } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => shift_op, 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'unary_op', 'op' => '~', 'operand' => 't2' } },
              { 'name' => 't4', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'threads shift-result bytes into OR: (2<<8)|5 == 5 (on-chain), not an abort' do
      # On-chain: OP_OR([0x00],[0x05]) == [0x05] == 5. A naive re-minimise of
      # (2<<8)=0 to the empty encoding would length-mismatch and abort.
      new_state = mod.compute_new_state(chained_shift_bitwise_anf('<<', 8, '|', 5), 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(5)
    end

    it 'threads shift-result bytes into AND: ((1<<8)&0) aborts on length mismatch' do
      # On-chain: OP_AND([0x00],[]) length-mismatches and aborts. A naive
      # re-minimise (0 & 0 = 0) would silently spend — a funds-loss divergence.
      expect do
        mod.compute_new_state(chained_shift_bitwise_anf('<<', 8, '&', 0), 'compute', { 'result' => 0 }, { 'a' => 1 })
      end.to raise_error(/OP_AND: operands must be same length/)
    end

    it 'threads shift-result bytes into INVERT: ~(2<<8) == -127' do
      # On-chain: OP_INVERT([0x00]) == [0xff] == -127 (little-endian sign-mag).
      # A naive re-minimise (~0 == 0) would give 0.
      new_state = mod.compute_new_state(chained_shift_invert_anf('<<', 8), 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(-127)
    end

    it 'threads a 2-byte shift result into AND: (256<<8)&256 == 0' do
      # (256<<8) on-chain is [0x01,0x00] (len 2); minimal 256 is [0x00,0x01]
      # (len 2); AND is [0x00,0x00] == 0. Lengths match so this spends to 0.
      new_state = mod.compute_new_state(chained_shift_bitwise_anf('<<', 8, '&', 256), 'compute', { 'result' => 0 }, { 'a' => 256 })
      expect(new_state['result']).to eq(0)
    end
  end

  # ---------------------------------------------------------------------------
  # NON-MINIMAL numeric operands (funds-locking)
  #
  # A shift PRESERVES its operand's byte length, so +1 >> 1+ leaves the 1-byte
  # array +[0x00]+ — a NON-minimal zero (minimal zero is the empty array).
  # Every NUMERIC consumer on-chain (OP_ADD/OP_SUB/OP_MUL/OP_DIV/OP_MOD,
  # OP_NUMEQUAL/OP_NUMNOTEQUAL and the relational ops, and a shift's COUNT
  # operand) decodes with +fRequireMinimal = true+ and ABORTS on that encoding.
  #
  # The interpreter threads the real stack bytes through the byte ops but the
  # NUMERIC path used to read only the decoded value, re-minimising +[0x00]+ to
  # 0 and reporting the spend VALID. A developer testing off-chain saw green
  # and deployed a UTXO the chain will never let them spend.
  #
  # OP_AND/OP_OR/OP_XOR/OP_INVERT and a shift's VALUE operand are NOT covered
  # by +fRequireMinimal+ — they legitimately take non-minimal bytes and only
  # require equal length. Those must stay accepted (see the controls below and
  # conformance/fuzz-regressions/entries/2026-07-14-chained-shift-or-nonminimal).
  # ---------------------------------------------------------------------------

  describe 'non-minimal numeric operands' do
    # Build an ANF fixture whose +t2+ binding is +a >> 1+ — raw stack bytes
    # [0x00] when +a+ is 1 — and then feeds +t2+ / the minimal consts +t3+
    # (0) and +t4+ (1) to a final numeric +bin_op+.
    def numeric_consumer_anf(op, left, right)
      {
        'contractName' => 'NonMinimal',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>>', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => 0 } },
              { 'name' => 't4', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't5', 'value' => { 'kind' => 'bin_op', 'op' => op, 'left' => left, 'right' => right } },
              { 'name' => 't6', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't5' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    {
      # The canonical funds-locking guard: `(n >> 1) === 0`.
      '(1>>1)===0'  => ['===', 't2', 't3', 'OP_NUMEQUAL'],
      # ...and with the non-minimal operand on the right.
      '0===(1>>1)'  => ['===', 't3', 't2', 'OP_NUMEQUAL'],
      '(1>>1)+1'    => ['+',   't2', 't4', 'OP_ADD'],
      '(1>>1)-1'    => ['-',   't2', 't4', 'OP_SUB'],
      '(1>>1)*1'    => ['*',   't2', 't4', 'OP_MUL'],
      '(1>>1)/1'    => ['/',   't2', 't4', 'OP_DIV'],
      '(1>>1)%1'    => ['%',   't2', 't4', 'OP_MOD'],
      '(1>>1)!==1'  => ['!==', 't2', 't4', 'OP_NUMNOTEQUAL'],
      '(1>>1)<1'    => ['<',   't2', 't4', 'OP_LESSTHAN'],
      '(1>>1)<=1'   => ['<=',  't2', 't4', 'OP_LESSTHANOREQUAL'],
      '(1>>1)>1'    => ['>',   't2', 't4', 'OP_GREATERTHAN'],
      '(1>>1)>=1'   => ['>=',  't2', 't4', 'OP_GREATERTHANOREQUAL'],
      # A shift's COUNT operand IS read as a number -> fRequireMinimal.
      '1<<(1>>1)'   => ['<<',  't4', 't2', 'OP_LSHIFT'],
      '1>>(1>>1)'   => ['>>',  't4', 't2', 'OP_RSHIFT'],
    }.each do |label, (op, left, right, opcode)|
      it "aborts #{label} — #{opcode} decodes with fRequireMinimal" do
        expect do
          mod.compute_new_state(numeric_consumer_anf(op, left, right), 'compute', { 'result' => 0 }, { 'a' => 1 })
        end.to raise_error(/#{opcode}: non-minimally encoded script number/)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CONTROLS for the non-minimal check. None of these carry a non-minimal
  # encoding into a numeric consumer, so all must keep spending as before.
  # ---------------------------------------------------------------------------

  describe 'minimal operands stay accepted' do
    # `(a >> 1) === 1` — with a = 2 the shift leaves [0x01], which IS the
    # minimal encoding of 1, so the numeric compare is legal on-chain.
    def minimal_shift_compare_anf
      {
        'contractName' => 'MinimalShift',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>>', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'bin_op', 'op' => '===', 'left' => 't2', 'right' => 't1' } },
              { 'name' => 't4', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    # `((a << 8) | 5) === 5` — the OR takes the non-minimal [0x00] happily
    # (equal length only), and its result [0x05] IS minimal, so the compare
    # is legal too.
    def or_then_compare_anf
      {
        'contractName' => 'OrThenCompare',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 8 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '<<', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => 5 } },
              { 'name' => 't4', 'value' => { 'kind' => 'bin_op', 'op' => '|', 'left' => 't2', 'right' => 't3' } },
              { 'name' => 't5', 'value' => { 'kind' => 'bin_op', 'op' => '===', 'left' => 't4', 'right' => 't3' } },
              { 'name' => 't6', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't5' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    # `((a << 8) << 1) | 5` — a shift's VALUE operand is not fRequireMinimal,
    # so re-shifting the non-minimal [0x00] is legal and stays 1 byte.
    def reshift_then_or_anf
      {
        'contractName' => 'ReshiftThenOr',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 8 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '<<', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't4', 'value' => { 'kind' => 'bin_op', 'op' => '<<', 'left' => 't2', 'right' => 't3' } },
              { 'name' => 't5', 'value' => { 'kind' => 'load_const', 'value' => 5 } },
              { 'name' => 't6', 'value' => { 'kind' => 'bin_op', 'op' => '|', 'left' => 't4', 'right' => 't5' } },
              { 'name' => 't7', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't6' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'compares a MINIMAL shift result: (2>>1)===1 still accepts' do
      new_state = mod.compute_new_state(minimal_shift_compare_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to be true
    end

    it 'ORs non-minimal equal-length operands then compares: (2<<8)|5 === 5 still accepts' do
      # Pinned by conformance/fuzz-regressions/entries/
      # 2026-07-14-chained-shift-or-nonminimal — rejecting this is WRONG.
      new_state = mod.compute_new_state(or_then_compare_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to be true
    end

    it "re-shifts a non-minimal VALUE operand: ((2<<8)<<1)|5 == 5 still accepts" do
      new_state = mod.compute_new_state(reshift_then_or_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(5)
    end

    it 'leaves plain arithmetic untouched' do
      expect(mod.eval_bin_op('+', 1, 1)).to eq(2)
      expect(mod.eval_bin_op('===', 2, 2)).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # +@ref:+ ALIAS bindings must carry the threaded stack bytes.
  #
  # The lowering turns every named local into an alias: +const left = this.a <<
  # 3n+ becomes +t2 = a << 3n+ followed by +left = @ref:t2+, and the consumer
  # reads +left+. The side-map is keyed by binding name, so an alias that does
  # not copy the entry drops the real stack bytes — silently disabling BOTH the
  # non-minimal numeric check AND the chained byte-op threading, on exactly the
  # shape the compiler actually emits.
  #
  # +conformance/tests/shift-ops+ is a live example: +left = this.a << 3n;
  # assert(left >= 0n || left < 0n)+. With +a = 32+ the shift leaves the 1-byte
  # [0x00] and OP_GREATERTHANOREQUAL aborts on chain.
  # ---------------------------------------------------------------------------

  describe '@ref: alias bindings carry the threaded stack bytes' do
    # Build `t2 = a <shift_op> amount; s = @ref:t2; result = s <op> other`.
    def aliased_chain_anf(shift_op, amount, op, other)
      {
        'contractName' => 'Aliased',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => amount } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => shift_op, 'left' => 't0', 'right' => 't1' } },
              # The alias the lowering emits for `const s = a <shift_op> amount`.
              { 'name' => 's', 'value' => { 'kind' => 'load_const', 'value' => '@ref:t2' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => other } },
              { 'name' => 't4', 'value' => { 'kind' => 'bin_op', 'op' => op, 'left' => 's', 'right' => 't3' } },
              { 'name' => 't5', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't4' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'aborts a numeric consumer fed an aliased non-minimal result' do
      # a = 1: (1>>1) leaves [0x00]; OP_NUMEQUAL decodes with fRequireMinimal
      # and aborts. Dropping the alias entry reports a clean spend instead.
      expect do
        mod.compute_new_state(aliased_chain_anf('>>', 1, '===', 0), 'compute', { 'result' => 0 }, { 'a' => 1 })
      end.to raise_error(/OP_NUMEQUAL: non-minimally encoded script number/)
    end

    it 'still feeds aliased non-minimal bytes to a byte op (no false abort)' do
      # CONTROL, and a regression for the byte-op threading itself: an alias
      # that drops the entry makes OP_OR re-derive 0's EMPTY encoding and abort
      # on a length mismatch the chain never sees.
      new_state = mod.compute_new_state(aliased_chain_anf('<<', 8, '|', 5), 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(5)
    end

    it 'still accepts an aliased MINIMAL shift result' do
      # a = 2: (2>>1) leaves [0x01], which IS minimal for 1.
      new_state = mod.compute_new_state(aliased_chain_anf('>>', 1, '===', 1), 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # eval_call — built-in functions
  # ---------------------------------------------------------------------------

  describe '.eval_call' do
    it 'returns true for checkSig' do
      expect(mod.eval_call('checkSig', ['00' * 72, '02' + 'ab' * 32])).to be true
    end

    it 'computes sha256 of empty bytes' do
      expect(mod.eval_call('sha256', [''])).to be_a(String)
      expect(mod.eval_call('sha256', [''])).to have_attributes(length: 64)
    end

    it 'computes hash160 of empty bytes' do
      expect(mod.eval_call('hash160', [''])).to have_attributes(length: 40)
    end

    it 'concatenates with cat' do
      expect(mod.eval_call('cat', ['aabb', 'ccdd'])).to eq('aabbccdd')
    end

    it 'extracts a substr in bytes' do
      # 'aabbccdd' — substr(0, 2) => 'aabb'
      expect(mod.eval_call('substr', ['aabbccdd', 0, 2])).to eq('aabb')
    end

    it 'reverses bytes' do
      expect(mod.eval_call('reverseBytes', ['aabbcc'])).to eq('ccbbaa')
    end

    it 'returns byte length via len' do
      expect(mod.eval_call('len', ['aabbcc'])).to eq(3)
    end

    it 'computes abs' do
      expect(mod.eval_call('abs', [-7])).to eq(7)
    end

    it 'computes min' do
      expect(mod.eval_call('min', [3, 7])).to eq(3)
    end

    it 'computes max' do
      expect(mod.eval_call('max', [3, 7])).to eq(7)
    end

    it 'evaluates within (inclusive lower, exclusive upper)' do
      expect(mod.eval_call('within', [5, 1, 10])).to be true
      expect(mod.eval_call('within', [10, 1, 10])).to be false
    end

    it 'safediv returns 0 when divisor is zero' do
      expect(mod.eval_call('safediv', [10, 0])).to eq(0)
    end

    it 'safediv truncates toward zero' do
      expect(mod.eval_call('safediv', [-7, 2])).to eq(-3)
    end

    it 'clamps a value between lo and hi' do
      expect(mod.eval_call('clamp', [5, 1, 10])).to eq(5)
      expect(mod.eval_call('clamp', [0, 1, 10])).to eq(1)
      expect(mod.eval_call('clamp', [15, 1, 10])).to eq(10)
    end

    it 'computes sign' do
      expect(mod.eval_call('sign', [5])).to eq(1)
      expect(mod.eval_call('sign', [-3])).to eq(-1)
      expect(mod.eval_call('sign', [0])).to eq(0)
    end

    it 'computes pow' do
      expect(mod.eval_call('pow', [2, 8])).to eq(256)
    end

    it 'computes integer sqrt' do
      expect(mod.eval_call('sqrt', [9])).to eq(3)
      expect(mod.eval_call('sqrt', [8])).to eq(2)  # floor
    end

    it 'computes gcd' do
      expect(mod.eval_call('gcd', [12, 8])).to eq(4)
    end

    it 'computes log2' do
      expect(mod.eval_call('log2', [8])).to eq(3)
      expect(mod.eval_call('log2', [9])).to eq(3)  # floor
    end

    it 'casts to bool (1 for truthy, 0 for falsy)' do
      expect(mod.eval_call('bool', [1])).to eq(1)
      expect(mod.eval_call('bool', [0])).to eq(0)
    end

    it 'computes mulDiv' do
      expect(mod.eval_call('mulDiv', [10, 3, 2])).to eq(15)
    end

    it 'computes percentOf' do
      # 10% of 1000 = 100 bps * 1000 / 10000 = 10
      expect(mod.eval_call('percentOf', [1000, 100])).to eq(10)
    end
  end

  # ---------------------------------------------------------------------------
  # to_int — numeric coercion
  # ---------------------------------------------------------------------------

  describe '.to_int' do
    it 'passes Integer through unchanged' do
      expect(mod.to_int(42)).to eq(42)
    end

    it 'converts true to 1' do
      expect(mod.to_int(true)).to eq(1)
    end

    it 'converts false to 0' do
      expect(mod.to_int(false)).to eq(0)
    end

    it 'truncates Float' do
      expect(mod.to_int(3.9)).to eq(3)
    end

    it 'parses "42n" BigInt format' do
      expect(mod.to_int('42n')).to eq(42)
    end

    it 'parses "-7n" negative BigInt format' do
      expect(mod.to_int('-7n')).to eq(-7)
    end

    it 'parses plain integer strings' do
      expect(mod.to_int('100')).to eq(100)
    end

    it 'returns 0 for non-numeric strings' do
      expect(mod.to_int('hello')).to eq(0)
    end
  end

  # ---------------------------------------------------------------------------
  # is_truthy — truthiness semantics
  # ---------------------------------------------------------------------------

  describe '.is_truthy' do
    it 'true is truthy' do
      expect(mod.is_truthy(true)).to be true
    end

    it 'false is falsy' do
      expect(mod.is_truthy(false)).to be false
    end

    it 'non-zero integer is truthy' do
      expect(mod.is_truthy(1)).to be true
    end

    it 'zero integer is falsy' do
      expect(mod.is_truthy(0)).to be false
    end

    it 'non-empty, non-zero string is truthy' do
      expect(mod.is_truthy('hello')).to be true
    end

    it 'empty string is falsy' do
      expect(mod.is_truthy('')).to be false
    end

    it '"0" string is falsy' do
      expect(mod.is_truthy('0')).to be false
    end

    it '"false" string is falsy' do
      expect(mod.is_truthy('false')).to be false
    end

    # Bitcoin Script semantics for hex-encoded byte strings
    it 'hex "00" (single zero byte) is falsy' do
      expect(mod.is_truthy('00')).to be false
    end

    it 'hex "0000" (two zero bytes) is falsy' do
      expect(mod.is_truthy('0000')).to be false
    end

    it 'hex "80" (negative zero) is falsy' do
      expect(mod.is_truthy('80')).to be false
    end

    it 'hex "0080" (negative zero, 2 bytes) is falsy' do
      expect(mod.is_truthy('0080')).to be false
    end

    it 'hex "01" (non-zero byte) is truthy' do
      expect(mod.is_truthy('01')).to be true
    end

    it 'hex "0001" (non-zero somewhere) is truthy' do
      expect(mod.is_truthy('0001')).to be true
    end

    it 'hex "ff" (non-zero byte) is truthy' do
      expect(mod.is_truthy('ff')).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # num2bin_hex / bin2num_int — byte encoding round-trip
  # ---------------------------------------------------------------------------

  describe '.num2bin_hex' do
    it 'encodes zero as all-zero bytes' do
      expect(mod.num2bin_hex(0, 2)).to eq('0000')
    end

    it 'encodes 1 in a 1-byte result' do
      expect(mod.num2bin_hex(1, 1)).to eq('01')
    end

    it 'encodes 256 in a 2-byte result (little-endian)' do
      expect(mod.num2bin_hex(256, 2)).to eq('0001')
    end

    it 'encodes -1 with sign bit set in last byte' do
      # -1 in 1 byte: magnitude=1, sign bit set → 0x81
      expect(mod.num2bin_hex(-1, 1)).to eq('81')
    end
  end

  describe '.bin2num_int' do
    it 'decodes empty string as 0' do
      expect(mod.bin2num_int('')).to eq(0)
    end

    it 'decodes 0x01 as 1' do
      expect(mod.bin2num_int('01')).to eq(1)
    end

    it 'decodes 0x81 as -1 (sign bit set)' do
      expect(mod.bin2num_int('81')).to eq(-1)
    end

    it 'round-trips positive value' do
      hex = mod.num2bin_hex(300, 2)
      expect(mod.bin2num_int(hex)).to eq(300)
    end

    it 'round-trips negative value' do
      hex = mod.num2bin_hex(-300, 2)
      expect(mod.bin2num_int(hex)).to eq(-300)
    end
  end

  # ---------------------------------------------------------------------------
  # Private method calls via eval_method_call
  # ---------------------------------------------------------------------------

  describe '.eval_method_call' do
    let(:private_method_anf) do
      {
        'contractName' => 'Helper',
        'properties' => [
          { 'name' => 'result', 'type' => 'bigint', 'readonly' => false },
        ],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'double',
            'params' => [{ 'name' => 'x', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 'r0', 'value' => { 'kind' => 'load_param', 'name' => 'x' } },
              { 'name' => 'r1', 'value' => { 'kind' => 'load_const', 'value' => 2 } },
              { 'name' => 'r2', 'value' => { 'kind' => 'bin_op', 'op' => '*', 'left' => 'r0', 'right' => 'r1' } },
            ],
            'isPublic' => false,
          },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'n', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'n' } },
              {
                'name' => 't1',
                'value' => {
                  'kind' => 'method_call',
                  'object' => nil,
                  'method' => 'double',
                  'args' => ['t0'],
                },
              },
              { 'name' => 't2', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't1' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'calls a private method and returns its result' do
      new_state = mod.compute_new_state(private_method_anf, 'compute', { 'result' => 0 }, { 'n' => 5 })
      expect(new_state['result']).to eq(10)
    end
  end

  # ---------------------------------------------------------------------------
  # Loop evaluation
  # ---------------------------------------------------------------------------

  describe 'loop evaluation' do
    let(:loop_anf) do
      # Accumulates: result += i for i in 0..3 (0+1+2+3 = 6)
      {
        'contractName' => 'LoopTest',
        'properties' => [
          { 'name' => 'result', 'type' => 'bigint', 'readonly' => false },
        ],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'run',
            'params' => [],
            'body' => [
              {
                'name' => 'lresult',
                'value' => {
                  'kind' => 'loop',
                  'count' => 4,
                  'iterVar' => 'i',
                  'body' => [
                    { 'name' => 'li0', 'value' => { 'kind' => 'load_prop', 'name' => 'result' } },
                    { 'name' => 'li1', 'value' => { 'kind' => 'load_param', 'name' => 'i' } },
                    { 'name' => 'li2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 'li0', 'right' => 'li1' } },
                    { 'name' => 'li3', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 'li2' } },
                  ],
                },
              },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'accumulates loop iterations: sum of 0..3 = 6' do
      new_state = mod.compute_new_state(loop_anf, 'run', { 'result' => 0 }, {})
      expect(new_state['result']).to eq(6)
    end

    # #121: honor start/step. Build a loop that accumulates the iterator value.
    def start_step_loop_anf(count, start, step)
      body = {
        'kind' => 'loop', 'count' => count, 'iterVar' => 'i',
        'start' => "#{start}n", 'step' => step,
        'body' => [
          { 'name' => 'li0', 'value' => { 'kind' => 'load_prop', 'name' => 'result' } },
          { 'name' => 'li1', 'value' => { 'kind' => 'load_param', 'name' => 'i' } },
          { 'name' => 'li2', 'value' => { 'kind' => 'bin_op', 'op' => '+', 'left' => 'li0', 'right' => 'li1' } },
          { 'name' => 'li3', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 'li2' } },
        ],
      }
      {
        'contractName' => 'LoopTest',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          { 'name' => 'run', 'params' => [],
            'body' => [{ 'name' => 'lresult', 'value' => body }], 'isPublic' => true },
        ],
      }
    end

    it 'honors a non-zero start (sum of 1+2+3 = 6)' do
      new_state = mod.compute_new_state(start_step_loop_anf(3, 1, 1), 'run', { 'result' => 0 }, {})
      expect(new_state['result']).to eq(6)
    end

    it 'honors a countdown step (sum of 3+2+1 = 6)' do
      new_state = mod.compute_new_state(start_step_loop_anf(3, 3, -1), 'run', { 'result' => 0 }, {})
      expect(new_state['result']).to eq(6)
    end
  end

  # ---------------------------------------------------------------------------
  # Loop iteration cap (issue #52)
  # ---------------------------------------------------------------------------

  describe 'loop iteration cap' do
    # Build a minimal loop ANF with a configurable count.
    def loop_count_anf(count)
      {
        'contractName' => 'LoopCap',
        'properties' => [
          { 'name' => 'result', 'type' => 'bigint', 'readonly' => false },
        ],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'run',
            'params' => [],
            'body' => [
              {
                'name' => 'lresult',
                'value' => {
                  'kind' => 'loop',
                  'count' => count,
                  'iterVar' => 'i',
                  'body' => [],
                },
              },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'raises a RuntimeError when loop count exceeds MAX_LOOP_ITERATIONS (65,536)' do
      oversized_anf = loop_count_anf(65_537)
      expect do
        mod.compute_new_state(oversized_anf, 'run', { 'result' => 0 }, {})
      end.to raise_error(RuntimeError, /loop count 65537 exceeds maximum of 65536/)
    end

    it 'completes normally when loop count is within the limit (100 iterations)' do
      normal_anf = loop_count_anf(100)
      expect do
        mod.compute_new_state(normal_anf, 'run', { 'result' => 0 }, {})
      end.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # NON-MINIMAL operands reaching a UNARY op or a numeric BUILTIN
  #
  # The binary-op gate above only sees a value consumed by a BINARY numeric op.
  # A non-minimal shift result can reach a UNARY op or a numeric BUILTIN
  # without passing through one, and those opcodes decode with
  # +fRequireMinimal = true+ as well:
  #
  #   abs(n >> 1)    OP_ABS
  #   bool(n >> 1)   OP_0NOTEQUAL
  #   !(n >> 1)      OP_NOT
  #   -(n >> 1)      OP_NEGATE
  #
  # With +n = 1+ the shift leaves the 1-byte +[0x00]+. Reading only the decoded
  # value re-minimises it to 0, reports a clean spend, and the deployed script
  # aborts — the UTXO is unspendable.
  #
  # Mirrors the TS reference widening at the +toBigInt+ / +toBool+ funnels in
  # packages/runar-testing/src/interpreter/interpreter.ts.
  # ---------------------------------------------------------------------------

  describe 'non-minimal operands through a unary op or a builtin' do
    # +t2+ = +a >> 1+ (raw stack bytes [0x00] when +a+ is 1), then +tail+ as
    # the final binding, then the property write.
    def unary_builtin_anf(tail)
      {
        'contractName' => 'NonMinimalUnary',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>>', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => 0 } },
              { 'name' => 't4', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't5', 'value' => tail },
              { 'name' => 't6', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    def call_value(func, *args)
      { 'kind' => 'call', 'func' => func, 'args' => args }
    end

    {
      'abs(1>>1)'          => -> { call_value('abs', 't2') },
      'bool(1>>1)'         => -> { call_value('bool', 't2') },
      'sign(1>>1)'         => -> { call_value('sign', 't2') },
      'min(1>>1, 1)'       => -> { call_value('min', 't2', 't4') },
      'min(1, 1>>1)'       => -> { call_value('min', 't4', 't2') },
      'max(1>>1, 1)'       => -> { call_value('max', 't2', 't4') },
      'within(1>>1, 0, 1)' => -> { call_value('within', 't2', 't3', 't4') },
      'safediv(1>>1, 1)'   => -> { call_value('safediv', 't2', 't4') },
      'clamp(1>>1, 0, 1)'  => -> { call_value('clamp', 't2', 't3', 't4') },
      '-(1>>1)'            => -> { { 'kind' => 'unary_op', 'op' => '-', 'operand' => 't2' } },
      '!(1>>1)'            => -> { { 'kind' => 'unary_op', 'op' => '!', 'operand' => 't2' } },
    }.each do |label, tail|
      it "aborts #{label} — the operand decodes with fRequireMinimal" do
        expect do
          mod.compute_new_state(unary_builtin_anf(instance_exec(&tail)), 'compute', { 'result' => 0 }, { 'a' => 1 })
        end.to raise_error(/non-minimally encoded script number/)
      end
    end

    it 'aborts through a named-local alias — the shape the lowering emits' do
      anf = {
        'contractName' => 'AliasedBuiltin',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>>', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 's', 'value' => { 'kind' => 'load_const', 'value' => '@ref:t2' } },
              { 'name' => 't3', 'value' => { 'kind' => 'call', 'func' => 'abs', 'args' => ['s'] } },
              { 'name' => 't4', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
      expect do
        mod.compute_new_state(anf, 'compute', { 'result' => 0 }, { 'a' => 1 })
      end.to raise_error(/non-minimally encoded script number/)
    end
  end

  # ---------------------------------------------------------------------------
  # CONTROLS for the widened gate. Each must keep spending.
  # ---------------------------------------------------------------------------

  describe 'unary/builtin controls stay accepted' do
    # +result = abs(a >> 1)+ — with a = 2 the shift leaves [0x01], the minimal
    # encoding of 1, so OP_ABS is legal on-chain.
    def abs_shift_anf
      {
        'contractName' => 'MinimalAbs',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 1 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '>>', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'call', 'func' => 'abs', 'args' => ['t2'] } },
              { 'name' => 't4', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it 'abs(2>>1) == 1 — a MINIMAL operand through a builtin still spends' do
      new_state = mod.compute_new_state(abs_shift_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(1)
    end

    # +result = ~(a << 8) + 0+ — OP_INVERT is a byte op and must NOT be gated:
    # with a = 2 the shift leaves the NON-minimal [0x00] and the invert gives
    # [0xff] = -127.
    def invert_shift_anf
      {
        'contractName' => 'InvertShift',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 8 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '<<', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 't3', 'value' => { 'kind' => 'unary_op', 'op' => '~', 'operand' => 't2' } },
              { 'name' => 't4', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't3' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it '~(2<<8) == -127 — OP_INVERT is a byte op, never gated' do
      new_state = mod.compute_new_state(invert_shift_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(-127)
    end

    # +result = ((a << 8) | 5) === 5+ through a named-local alias — OP_OR takes
    # non-minimal bytes and only requires equal length.
    def aliased_or_anf
      {
        'contractName' => 'AliasedOr',
        'properties' => [{ 'name' => 'result', 'type' => 'bigint', 'readonly' => false }],
        'methods' => [
          { 'name' => 'constructor', 'params' => [], 'body' => [], 'isPublic' => false },
          {
            'name' => 'compute',
            'params' => [{ 'name' => 'a', 'type' => 'bigint' }],
            'body' => [
              { 'name' => 't0', 'value' => { 'kind' => 'load_param', 'name' => 'a' } },
              { 'name' => 't1', 'value' => { 'kind' => 'load_const', 'value' => 8 } },
              { 'name' => 't2', 'value' => { 'kind' => 'bin_op', 'op' => '<<', 'left' => 't0', 'right' => 't1' } },
              { 'name' => 's', 'value' => { 'kind' => 'load_const', 'value' => '@ref:t2' } },
              { 'name' => 't3', 'value' => { 'kind' => 'load_const', 'value' => 5 } },
              { 'name' => 't4', 'value' => { 'kind' => 'bin_op', 'op' => '|', 'left' => 's', 'right' => 't3' } },
              { 'name' => 't5', 'value' => { 'kind' => 'update_prop', 'name' => 'result', 'value' => 't4' } },
            ],
            'isPublic' => true,
          },
        ],
      }
    end

    it '(2<<8)|5 == 5 through a named-local alias — OP_OR takes non-minimal bytes' do
      new_state = mod.compute_new_state(aliased_or_anf, 'compute', { 'result' => 0 }, { 'a' => 2 })
      expect(new_state['result']).to eq(5)
    end
  end
  # ---------------------------------------------------------------------------
  # NEW-013 -- `num2bin` sign-bit placement
  # ---------------------------------------------------------------------------
  #
  # The ANF interpreter models what the DEPLOYED SCRIPT computes. For negative
  # values it used to set the sign bit on the last MAGNITUDE byte and pad zeros
  # AFTER it, so num2bin(-1, 2) came out 8100 where OP_NUM2BIN yields 0180.
  # Those bytes go into the call transaction, so a legal method built a
  # continuation the script rejects.
  #
  # Every expectation below is the output of OP_NUM2BIN on the real @bsv/sdk
  # Spend interpreter, derived by
  # conformance/anf-interpreter/num2bin-engine-parity.test.ts, which re-runs the
  # engine live rather than trusting a table. Do NOT re-stamp these from this
  # implementation's own output -- that is precisely how six of seven SDKs
  # agreed on the wrong answer.
  describe 'num2bin_hex' do
    # [value, width, expected, why]
    vectors = [
      # Negative, padded -- the NEW-013 corner. The sign bit belongs on the
      # byte that is most significant AFTER padding, not before it.
      [-1, 2, '0180', 'negative padded'],
      [-1, 4, '01000080', 'negative padded'],
      [-1, 8, '0100000000000080', 'negative padded'],
      [-5, 4, '05000080', 'negative padded'],
      [-1000, 4, 'e8030080', 'negative padded'],
      [-1000, 8, 'e803000000000080', 'negative padded'],
      [-255, 3, 'ff0080', 'negative padded'],
      [-256, 3, '000180', 'negative padded'],
      # Negative, exact width -- the minimal encoding already fills the field,
      # so it is pushed unchanged and the sign bit does not move.
      [-1, 1, '81', 'negative exact width'],
      [-127, 1, 'ff', 'negative exact width'],
      [-1000, 2, 'e883', 'negative exact width'],
      [-256, 2, '0081', 'negative exact width'],
      # Negative, sign-bit carry -- the top magnitude byte already uses bit 7,
      # so the minimal encoding grows a byte before any padding happens.
      [-128, 2, '8080', 'negative carry, exact width'],
      [-128, 3, '800080', 'negative carry, padded'],
      [-128, 8, '8000000000000080', 'negative carry, padded'],
      [-32_768, 3, '008080', 'negative carry, exact width'],
      [-32_768, 4, '00800080', 'negative carry, padded'],
      # Positive at the same widths -- must be untouched by the fix.
      [1, 1, '01', 'positive exact width'],
      [1, 2, '0100', 'positive padded'],
      [1, 8, '0100000000000000', 'positive padded'],
      [1000, 2, 'e803', 'positive exact width'],
      [1000, 4, 'e8030000', 'positive padded'],
      [1000, 8, 'e803000000000000', 'positive padded'],
      [127, 1, '7f', 'positive exact width'],
      [128, 2, '8000', 'positive carry, exact width'],
      [128, 3, '800000', 'positive carry, padded'],
      [255, 2, 'ff00', 'positive carry, exact width'],
      # Zero -- an all-zero field, no sign bit anywhere.
      [0, 1, '00', 'zero'],
      [0, 4, '00000000', 'zero'],
      [0, 8, '0000000000000000', 'zero']
    ]

    vectors.each do |n, width, expected, why|
      it "encodes num2bin(#{n}, #{width}) as OP_NUM2BIN does (#{why})" do
        expect(mod.num2bin_hex(n, width)).to eq(expected)
      end
    end

    # Non-vacuity: this table only earns its keep if it can see the pre-fix
    # answer. '8100' is exactly what this method used to return.
    it 'does not answer with the pre-fix sign-bit placement' do
      expect(mod.num2bin_hex(-1, 2)).not_to eq('8100')
    end

    # bin2num is this interpreter's own inverse, so a round trip proves only
    # self-consistency -- it held throughout the bug. Kept as a smoke test; the
    # vector table above is the evidence.
    it 'round-trips through bin2num (smoke test only, NOT the evidence)' do
      [-1000, -128, -1, 0, 1, 128, 1000].each do |n|
        expect(mod.bin2num_int(mod.num2bin_hex(n, 8))).to eq(n)
      end
    end
  end
end
