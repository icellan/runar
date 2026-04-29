# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'DataOutputTest.runar'

RSpec.describe DataOutputTest do
  it 'increments the counter and emits a data output' do
    c = DataOutputTest.new(0)
    expect { c.publish('68656c6c6f') }.not_to raise_error
    expect(c.count).to eq(1)
  end
end
