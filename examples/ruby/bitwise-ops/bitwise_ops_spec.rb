# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BitwiseOps.runar'

RSpec.describe BitwiseOps do
  it 'runs the shift exercise' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_shift }.not_to raise_error
  end

  it 'runs the bitwise exercise' do
    c = BitwiseOps.new(12, 10)
    expect { c.test_bitwise }.not_to raise_error
  end

  it 'runs the bitwise exercise with zeros' do
    c = BitwiseOps.new(0, 0)
    expect { c.test_bitwise }.not_to raise_error
  end
end
