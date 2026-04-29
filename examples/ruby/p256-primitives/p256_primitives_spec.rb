# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'P256Primitives.runar'

# Only compile-check (implicit via require_relative) is feasible: the runar
# Ruby runtime does not expose p256_mul / p256_add / p256_mul_gen /
# p256_on_curve as host methods, so the contract methods cannot be invoked
# natively. The frontend still parses, validates, and type-checks it as
# valid Runar.
RSpec.describe P256Primitives do
  it 'loads (frontend parse + class definition)' do
    expect(P256Primitives).to be_a(Class)
  end

  it 'constructs with a placeholder expected point' do
    c = P256Primitives.new('00' * 64)
    expect(c).to be_a(P256Primitives)
  end
end
