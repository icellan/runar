# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# D12 BM-F4 / BM-F5 / reverseBytes: the SDK ANF interpreter must compute what
# the compiled script computes, or refuse -- never invent a value.
# - ByteString & | ^ returned '' (script: OP_AND/OP_OR/OP_XOR, equal lengths,
#   abort on mismatch). Now exact.
# - int2str returned nil (script: OP_NUM2BIN). Now num2bin.
# - An unmodelled builtin still yields nil (as in Go/Rust); a nil reaching
#   state fails closed at the covenant.
# - num2bin / int2str truncated a value too wide for the field and returned ''
#   for a negative width (script: OP_NUM2BIN aborts). Now refused.
# - reverseBytes reversed every byte; the script reverses only the first 520.
#   Inputs > 520 bytes are refused.
# Proves: those values / refusals at the interpreter's evaluation functions.
# Does not prove: script execution (Ruby ships no ScriptVM).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'D12: SDK ANF interpreter refuses what it cannot model' do
  # rubocop:enable RSpec/DescribeClass
  let(:mod) { Runar::SDK::ANFInterpreter }

  it 'computes ByteString & | ^ exactly' do
    expect(mod.eval_bytes_bin_op('&', 'ff', '0f')).to eq('0f')
    expect(mod.eval_bytes_bin_op('|', 'f0', '0f')).to eq('ff')
    expect(mod.eval_bytes_bin_op('^', 'ff0f', '0f0f')).to eq('f000')
  end

  it 'refuses ByteString & | ^ on a length mismatch' do
    %w[& | ^].each do |op|
      expect { mod.eval_bytes_bin_op(op, 'ff', 'ffff') }.to raise_error(/length/)
    end
  end

  it 'evaluates int2str as num2bin' do
    expect(mod.eval_call('int2str', [5, 2])).to eq('0500')
    expect(mod.eval_call('int2str', [-1, 2])).to eq('0180')
  end

  it 'yields nil for an unmodelled builtin, as Go and Rust do' do
    # Refusing broke integration StateCovenant.advanceState, whose bbFieldMul
    # only feeds an assert the SDK does not need to evaluate.
    expect(mod.eval_call('bbFieldMul', [3, 5])).to be_nil
  end

  it 'refuses num2bin / int2str with a too-narrow or negative width' do
    %w[num2bin int2str].each do |f|
      [[40_000, 2], [128, 1], [2**31, 4], [2**63, 8], [1, 0], [5, -1], [0, -1]].each do |n, w|
        expect { mod.eval_call(f, [n, w]) }.to raise_error(/OP_NUM2BIN/), "#{f}(#{n}, #{w})"
      end
    end
    expect(mod.eval_call('num2bin', [0, 0])).to eq('')
  end

  it 'refuses reverseBytes above 520 bytes' do
    expect(mod.eval_call('reverseBytes', ['01' + ('00' * 519)])).to eq(('00' * 519) + '01')
    expect { mod.eval_call('reverseBytes', ['00' * 521]) }.to raise_error(/520/)
  end
end
