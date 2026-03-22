# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'MathDemo.runar'

RSpec.describe MathDemo do
  it 'divides by a value' do
    c = MathDemo.new(100)
    c.divide_by(4)
    expect(c.value).to eq(25)
  end

  it 'clamps value to range' do
    c = MathDemo.new(150)
    c.clamp_value(0, 100)
    expect(c.value).to eq(100)
  end

  it 'normalizes to sign' do
    c = MathDemo.new(-42)
    c.normalize
    expect(c.value).to eq(-1)
  end

  it 'exponentiates' do
    c = MathDemo.new(3)
    c.exponentiate(4)
    expect(c.value).to eq(81)
  end

  it 'computes square root' do
    c = MathDemo.new(144)
    c.square_root
    expect(c.value).to eq(12)
  end

  it 'reduces by gcd' do
    c = MathDemo.new(48)
    c.reduce_gcd(18)
    expect(c.value).to eq(6)
  end

  it 'scales by ratio' do
    c = MathDemo.new(100)
    c.scale_by_ratio(3, 4)
    expect(c.value).to eq(75)
  end

  it 'computes log2' do
    c = MathDemo.new(256)
    c.compute_log2
    expect(c.value).to eq(8)
  end
end
