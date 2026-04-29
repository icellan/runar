# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'IfElse.runar'

RSpec.describe IfElse do
  it 'takes the true branch when mode is true' do
    c = IfElse.new(5)
    expect { c.check(10, true) }.not_to raise_error
  end

  it 'takes the false branch when mode is false' do
    c = IfElse.new(5)
    expect { c.check(10, false) }.not_to raise_error
  end

  it 'fails when value - limit is non-positive' do
    c = IfElse.new(5)
    expect { c.check(2, false) }.to raise_error(RuntimeError)
  end
end
