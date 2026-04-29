# frozen_string_literal: true

require_relative '../spec_helper'
require 'runar/test_keys'
require_relative 'ECUnit.runar'

RSpec.describe ECUnit do
  it 'exercises every secp256k1 EC builtin' do
    c = ECUnit.new(Runar::TestKeys::ALICE.pub_key)
    expect { c.test_ops }.not_to raise_error
  end
end
