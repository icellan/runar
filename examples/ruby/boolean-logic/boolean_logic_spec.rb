# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BooleanLogic.runar'

RSpec.describe BooleanLogic do
  let(:c) { BooleanLogic.new(10) }

  it 'succeeds when both values are above the threshold' do
    expect { c.verify(20, 30, true) }.not_to raise_error
  end

  it 'succeeds when only one is above and the flag is false' do
    # not_flag => true, either_above => true
    expect { c.verify(20, 1, false) }.not_to raise_error
  end

  it 'fails when neither is above the threshold' do
    expect { c.verify(1, 2, false) }.to raise_error(RuntimeError)
  end

  it 'fails when only one is above and the flag is true' do
    # not_flag => false, both_above => false
    expect { c.verify(20, 1, true) }.to raise_error(RuntimeError)
  end
end
