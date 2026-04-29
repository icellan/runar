# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'HashRegistry.runar'

RSpec.describe HashRegistry do
  let(:initial) { '01020304050607080910111213141516171819ff' }
  let(:next_hash) { 'a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4' }

  it 'overwrites the stored hash on update' do
    c = HashRegistry.new(initial)
    c.update(next_hash)
    expect(c.current_hash).to eq(next_hash)
  end
end
