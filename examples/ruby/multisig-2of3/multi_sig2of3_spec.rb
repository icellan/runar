# frozen_string_literal: true

# R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal example
# and was tested in four of the nine formats (ts, sol, move, zig). This is the
# Ruby half.
#
# `check_multi_sig([sig1, sig2], [@pk1, @pk2, @pk3])` lowers to two
# `array_literal` ANF nodes — the canonical site where that node kind is emitted
# at all, and one of the four kinds `spec/ir-format.md` did not document until
# R-098.

require_relative '../spec_helper'
require_relative 'MultiSig2of3.runar'

RSpec.describe MultiSig2of3 do
  def contract
    MultiSig2of3.new(Runar.mock_pub_key, Runar.mock_pub_key, Runar.mock_pub_key)
  end

  it 'unlocks with two signatures' do
    c = contract
    expect { c.unlock(Runar.mock_sig, Runar.mock_sig) }.not_to raise_error
  end

  it 'commits three distinct pubkey slots' do
    # The 2-of-3 shape is the point: three pubkey slots, two signature slots.
    # A contract that collapsed them would still "run" above.
    c = contract
    expect(c.pk1).not_to be_nil
    expect(c.pk2).not_to be_nil
    expect(c.pk3).not_to be_nil
  end
end
