# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'ShiftOps.runar'

# The caller supplies the expected shift results and the contract checks them
# (F-167: it used to assert only tautologies, so no input could fail). With
# a = 12 native Ruby agrees with the on-chain OP_LSHIFT / OP_RSHIFT; the
# on-chain verdict is pinned by conformance/witnesses/real-crypto/shift-ops.json.
RSpec.describe ShiftOps do
  it 'runs left and right shifts on a positive value' do
    c = ShiftOps.new(12)
    expect { c.test_shift(96, 3) }.not_to raise_error
  end

  it 'rejects a wrong shift result' do
    c = ShiftOps.new(12)
    expect { c.test_shift(97, 3) }.to raise_error(RuntimeError, /assertion failed/)
    expect { c.test_shift(96, 2) }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'runs shifts on zero' do
    c = ShiftOps.new(0)
    expect { c.test_shift(0, 0) }.not_to raise_error
  end
end
