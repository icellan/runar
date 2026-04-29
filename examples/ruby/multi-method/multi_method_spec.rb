# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'MultiMethod.runar'

RSpec.describe MultiMethod do
  # mock_pub_key/mock_sig return ALICE's real ECDSA test pair.
  # Reusing them for both owner and backup is fine for these tests since
  # they only exercise the dispatch into each public method.

  it 'spend_with_owner succeeds when threshold is met' do
    c = MultiMethod.new(mock_pub_key, mock_pub_key)
    # amount * 2 + 1 must be > 10 → amount >= 5.
    expect { c.spend_with_owner(mock_sig, 6) }.not_to raise_error
  end

  it 'spend_with_owner rejects when threshold is not met' do
    c = MultiMethod.new(mock_pub_key, mock_pub_key)
    expect { c.spend_with_owner(mock_sig, 1) }.to raise_error(RuntimeError)
  end

  it 'spend_with_backup succeeds with the backup signature' do
    c = MultiMethod.new(mock_pub_key, mock_pub_key)
    expect { c.spend_with_backup(mock_sig) }.not_to raise_error
  end
end
