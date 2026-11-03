# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-084: the num2bin state encode path fails closed.
#
# coerce_to_integer returned 0 for nil, chomp-and-to_i'd any string ending in
# 'n' (so "abcn" and "n" became 0), and fed everything else to Kernel#Integer,
# which accepts floats (1.5 -> 1), hex strings ("0x10") and underscored
# digits. A value that is not an integer was committed on chain as a number
# the caller never supplied.
#
# Proves: serialize_state raises ArgumentError naming the field and type for
# nil, true, a float, '', a hex string, a non-decimal string and an array in
# each of the four num2bin types, and valid integers / decimal integer strings
# keep their exact bytes. Does not prove anything on chain, nor the other six
# SDKs.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-084 — num2bin state fields refuse a non-integer value' do
  # rubocop:enable RSpec/DescribeClass
  %w[int bigint RabinSig RabinPubKey].each do |type|
    fields = nil
    before { fields = [Runar::SDK::StateField.new(name: 'k', type: type, index: 0)] }

    [nil, true, 1.5, 2.0, '', 'deadbeef', '0x10', 'abc', 'abcn', 'n', '1_0', ' 5', [1]].each do |bad|
      it "#{type}: refuses #{bad.inspect}" do
        expect { Runar::SDK::State.serialize_state(fields, { 'k' => bad }) }
          .to raise_error(ArgumentError, /state field 'k' \(#{type}\) must be an integer/)
      end
    end

    it "#{type}: valid integers keep their bytes" do
      { 0 => '0000000000000000', 5 => '0500000000000000', -5 => '0500000000000080',
        '5' => '0500000000000000', '5n' => '0500000000000000', '-5n' => '0500000000000080' }.each do |v, want|
        expect(Runar::SDK::State.serialize_state(fields, { 'k' => v })).to eq(want)
      end
    end
  end
end
