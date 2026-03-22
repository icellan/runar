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
      expect(mod.eval_unary_op('~', 0)).to eq(-1)
    end

    it 'applies bitwise not to bytes when result_type is bytes' do
      # ~0x00 = 0xff; ~0xff = 0x00
      expect(mod.eval_unary_op('~', '00ff', 'bytes')).to eq('ff00')
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
end
