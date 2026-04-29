# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Stateful.runar'

RSpec.describe Stateful do
  it 'increments within bounds' do
    c = Stateful.new(0, 10)
    c.increment(3)
    expect(c.count).to eq(3)
    c.increment(7)
    expect(c.count).to eq(10)
  end

  it 'rejects increments that exceed max_count' do
    c = Stateful.new(0, 10)
    expect { c.increment(11) }.to raise_error(RuntimeError)
  end

  it 'reset clears the count back to zero' do
    c = Stateful.new(5, 10)
    c.reset
    expect(c.count).to eq(0)
  end
end
