# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BabyBearExt4Demo.runar'

# Only compile-check (implicit via require_relative) is feasible: the runar
# Ruby runtime does not expose the bb_ext4_* helpers, so the contract methods
# cannot be invoked natively. The frontend still parses, validates, and
# type-checks the contract as valid Runar.
RSpec.describe BabyBearExt4Demo do
  it 'loads (frontend parse + class definition)' do
    expect(BabyBearExt4Demo).to be_a(Class)
  end

  it 'constructs without arguments' do
    expect(BabyBearExt4Demo.new).to be_a(BabyBearExt4Demo)
  end
end
