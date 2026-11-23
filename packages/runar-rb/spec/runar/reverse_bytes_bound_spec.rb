# frozen_string_literal: true

require 'spec_helper'

# Since D12 BM-F3 every compiler's reverseBytes ends in OP_0 OP_EQUALVERIFY, so
# the script ABORTS on an input longer than 520 bytes. The native builtin must
# refuse the same input rather than reverse it in full.
RSpec.describe 'Runar::Builtins#reverse_bytes 520-byte bound' do
  let(:ctx) { Object.new.extend(Runar::Builtins) }

  [0, 1, 520].each do |n|
    it "reverses #{n} bytes" do
      src = (0...n).map { |i| format('%02x', i % 256) }.join
      expect(ctx.reverse_bytes(src)).to eq(src.scan(/../).reverse.join)
    end
  end

  it 'refuses 521 bytes' do
    expect { ctx.reverse_bytes('00' * 521) }.to raise_error(ArgumentError, /520/)
  end
end
