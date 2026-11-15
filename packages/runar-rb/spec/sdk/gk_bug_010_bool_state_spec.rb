# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# GK-BUG-010: a boolean state field accepts only true or false.
#
# encode_state_value wrote `value ? '01' : '00'`, and in Ruby 0, '' and
# 'false' are all truthy, so { flag: 0 } deployed 01 -- the opposite of what
# every other tier wrote for the same input. Each tier had its own coercion
# rule; every tier now refuses a non-boolean, as the num2bin arm (N-084)
# refuses a non-integer.
#
# Proves: serialize_state raises ArgumentError naming the field and type for
# 0, 1, 1.0, 'true', 'false', '', '01' and nil in both spellings of the type,
# and true / false keep 01 / 00. Does not prove anything on chain, nor the
# other six SDKs.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'GK-BUG-010 — boolean state fields refuse a non-boolean value' do
  # rubocop:enable RSpec/DescribeClass
  %w[bool boolean].each do |type|
    fields = nil
    before { fields = [Runar::SDK::StateField.new(name: 'flag', type: type, index: 0)] }

    [0, 1, 1.0, 'true', 'false', '', '01', nil].each do |bad|
      it "#{type}: refuses #{bad.inspect}" do
        expect { Runar::SDK::State.serialize_state(fields, { 'flag' => bad }) }
          .to raise_error(ArgumentError, /state field 'flag' \(#{type}\) must be a boolean/)
      end
    end

    it "#{type}: true / false keep their bytes" do
      expect(Runar::SDK::State.serialize_state(fields, { 'flag' => true })).to eq('01')
      expect(Runar::SDK::State.serialize_state(fields, { 'flag' => false })).to eq('00')
    end
  end
end
