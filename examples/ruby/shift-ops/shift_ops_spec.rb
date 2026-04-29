# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'ShiftOps.runar'

RSpec.describe ShiftOps do
  it 'runs left and right shifts on a positive value' do
    c = ShiftOps.new(64)
    expect { c.test_shift }.not_to raise_error
  end

  it 'runs shifts on zero' do
    c = ShiftOps.new(0)
    expect { c.test_shift }.not_to raise_error
  end
end
