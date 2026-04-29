# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BoundedLoop.runar'

# Loop computes sum_{i=0..4} (start + i) = 5*start + (0+1+2+3+4) = 5*start + 10.
def expected_sum(start)
  5 * start + 10
end

RSpec.describe BoundedLoop do
  it 'verifies the expected sum for start = 0' do
    c = BoundedLoop.new(expected_sum(0))
    expect { c.verify(0) }.not_to raise_error
  end

  it 'verifies the expected sum for start = 7' do
    c = BoundedLoop.new(expected_sum(7))
    expect { c.verify(7) }.not_to raise_error
  end

  it 'fails when the expected sum is wrong' do
    c = BoundedLoop.new(expected_sum(7) + 1)
    expect { c.verify(7) }.to raise_error(RuntimeError)
  end
end
