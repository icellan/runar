# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'FunctionPatterns.runar'

RSpec.describe FunctionPatterns do
  it 'deposits funds' do
    c = FunctionPatterns.new(mock_pub_key, 1000)
    c.deposit(mock_sig, 500)
    expect(c.balance).to eq(1500)
  end

  it 'withdraws with fee' do
    c = FunctionPatterns.new(mock_pub_key, 10_000)
    # 100 bps = 1% fee on 1000 = 10
    c.withdraw(mock_sig, 1000, 100)
    expect(c.balance).to eq(8990)
  end

  it 'scales balance by ratio' do
    c = FunctionPatterns.new(mock_pub_key, 100)
    c.scale(mock_sig, 3, 2)
    expect(c.balance).to eq(150)
  end

  it 'normalizes balance with clamp and round down' do
    c = FunctionPatterns.new(mock_pub_key, 157)
    c.normalize(mock_sig, 0, 200, 10)
    expect(c.balance).to eq(150)
  end
end
