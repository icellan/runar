# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Escrow.runar'

RSpec.describe Escrow do
  it 'releases funds to seller' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.release(mock_sig, mock_sig) }.not_to raise_error
  end

  it 'refunds funds to buyer' do
    c = Escrow.new(mock_pub_key, mock_pub_key, mock_pub_key)
    expect { c.refund(mock_sig, mock_sig) }.not_to raise_error
  end
end
