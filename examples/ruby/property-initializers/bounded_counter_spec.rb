# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BoundedCounter.runar'

RSpec.describe BoundedCounter do
  describe 'property initializers' do
    it 'initializes count to 0 by default' do
      # Only max_count is passed; count and active use their default values
      c = BoundedCounter.new(10)
      expect(c.count).to eq(0)
    end

    it 'active defaults to true, allowing immediate increment' do
      c = BoundedCounter.new(10)
      expect { c.increment(1) }.not_to raise_error
    end
  end

  describe '#increment' do
    it 'increases count by the given amount' do
      c = BoundedCounter.new(10)
      c.increment(3)
      expect(c.count).to eq(3)
    end

    it 'allows incrementing up to max_count' do
      c = BoundedCounter.new(5)
      expect { c.increment(5) }.not_to raise_error
      expect(c.count).to eq(5)
    end

    it 'fails when count would exceed max_count' do
      c = BoundedCounter.new(5)
      expect { c.increment(6) }.to raise_error(RuntimeError)
    end

    it 'accumulates state across multiple increments' do
      c = BoundedCounter.new(100)
      c.increment(10)
      c.increment(20)
      c.increment(30)
      expect(c.count).to eq(60)
    end
  end

  describe '#reset' do
    it 'resets count to zero' do
      c = BoundedCounter.new(10)
      c.increment(7)
      expect(c.count).to eq(7)

      c.reset
      expect(c.count).to eq(0)
    end

    it 'allows incrementing again after reset' do
      c = BoundedCounter.new(5)
      c.increment(5)
      c.reset
      expect { c.increment(5) }.not_to raise_error
    end
  end
end
