# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Counter.runar'

RSpec.describe Counter do
  it 'increments' do
    c = Counter.new(0)
    c.increment
    expect(c.count).to eq(1)
  end

  it 'increments multiple times' do
    c = Counter.new(0)
    c.increment
    c.increment
    c.increment
    expect(c.count).to eq(3)
  end

  it 'decrements' do
    c = Counter.new(5)
    c.decrement
    expect(c.count).to eq(4)
  end

  it 'fails to decrement at zero' do
    c = Counter.new(0)
    expect { c.decrement }.to raise_error(RuntimeError)
  end
end
