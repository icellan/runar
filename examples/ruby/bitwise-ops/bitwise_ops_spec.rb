# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BitwiseOps.runar'

# The caller supplies the expected results and the contract checks them
# (F-167: it used to assert only tautologies, so no input could fail). a = 12,
# b = 10 are 1-byte operands whose results stay below 0x80, so native Ruby
# agrees with the on-chain byte-array opcodes; the on-chain verdict for the
# same values is pinned by conformance/witnesses/real-crypto/bitwise-ops.json.
RSpec.describe BitwiseOps do
  it 'runs the shift exercise' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_shift(48, 6) }.not_to raise_error
  end

  it 'rejects a wrong shift result' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_shift(49, 6) }.to raise_error(RuntimeError, /assertion failed/)
    expect { c.test_shift(48, 7) }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'runs the bitwise exercise' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_bitwise(8, 14, 6) }.not_to raise_error
  end

  it 'rejects a wrong bitwise result' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_bitwise(14, 8, 6) }.to raise_error(RuntimeError, /assertion failed/)
    expect { c.test_bitwise(8, 14, 7) }.to raise_error(RuntimeError, /assertion failed/)
  end

  it 'runs the bitwise exercise with zeros' do
    c = BitwiseOps.new(0, 0)
    expect { c.test_bitwise(0, 0, 0) }.not_to raise_error
  end
end
