# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'P384Primitives.runar'

# Only compile-check (implicit via require_relative) is feasible: the runar
# Ruby runtime does not expose p384_mul / p384_add / p384_mul_gen /
# p384_on_curve as host methods, so the contract methods cannot be invoked
# natively. The frontend still parses, validates, and type-checks it as
# valid Runar.
RSpec.describe P384Primitives do
  it 'loads (frontend parse + class definition)' do
    expect(P384Primitives).to be_a(Class)
  end

  it 'constructs with a placeholder expected point' do
    c = P384Primitives.new('00' * 96)
    expect(c).to be_a(P384Primitives)
  end
end
