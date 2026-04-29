# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'RawOutputTest.runar'

RSpec.describe RawOutputTest do
  it 'emits a raw output and bumps the counter' do
    c = RawOutputTest.new(0)
    # Standard P2PKH locking script bytes (ZeroAddr: 76a914 + 20 zero bytes + 88ac)
    script = '76a914' + ('00' * 20) + '88ac'
    expect { c.send_to_script(script) }.not_to raise_error
    expect(c.count).to eq(1)
  end
end
