# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'IfWithoutElse.runar'

RSpec.describe IfWithoutElse do
  it 'succeeds when both values are above the threshold' do
    c = IfWithoutElse.new(5)
    expect { c.check(10, 20) }.not_to raise_error
  end

  it 'succeeds when only one value is above the threshold' do
    c = IfWithoutElse.new(5)
    expect { c.check(10, 1) }.not_to raise_error
  end

  it 'fails when neither value is above the threshold' do
    c = IfWithoutElse.new(5)
    expect { c.check(1, 2) }.to raise_error(RuntimeError)
  end
end
