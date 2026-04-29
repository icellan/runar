# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Arithmetic.runar'

# Verify computes (a+b) + (a-b) + (a*b) + (a/b) and asserts it equals @target.
def expected(a, b)
  (a + b) + (a - b) + (a * b) + (a / b)
end

RSpec.describe Arithmetic do
  it 'verifies a matching target' do
    a, b = 10, 3
    c = Arithmetic.new(expected(a, b))
    expect { c.verify(a, b) }.not_to raise_error
  end

  it 'verifies a different pair' do
    a, b = 20, 4
    c = Arithmetic.new(expected(a, b))
    expect { c.verify(a, b) }.not_to raise_error
  end

  it 'fails with the wrong target' do
    a, b = 10, 3
    c = Arithmetic.new(expected(a, b) + 1)
    expect { c.verify(a, b) }.to raise_error(RuntimeError)
  end
end
