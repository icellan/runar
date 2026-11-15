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

# The refusal above must not reject a boolean the SDK computed itself. The
# language declares `bool(x): boolean`, but the ANF interpreter returned
# 1 / 0, so a contract doing `this.flag = bool(this.count)` produced a
# post-state the serializer now refuses.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'GK-BUG-010 — an interpreter-computed boolean state field serializes' do
  # rubocop:enable RSpec/DescribeClass
  anf = {
    'contractName' => 'BoolProbe',
    'properties' => [
      { 'name' => 'count', 'type' => 'bigint', 'readonly' => false },
      { 'name' => 'flag', 'type' => 'bool', 'readonly' => false }
    ],
    'methods' => [{
      'name' => 'step',
      'params' => [],
      'isPublic' => true,
      'body' => [
        { 'name' => 'c', 'value' => { 'kind' => 'load_prop', 'name' => 'count' } },
        { 'name' => 'b', 'value' => { 'kind' => 'call', 'func' => 'bool', 'args' => ['c'] } },
        { 'name' => 'u', 'value' => { 'kind' => 'update_prop', 'name' => 'flag', 'value' => 'b' } }
      ]
    }]
  }

  [[5, '01'], [0, '00']].each do |count, hex|
    it "bool(#{count}) gives a native boolean that encodes as #{hex}" do
      st = Runar::SDK::ANFInterpreter.compute_new_state(anf, 'step', { 'count' => count, 'flag' => count.zero? }, {})
      expect([true, false]).to include(st['flag'])
      fields = [Runar::SDK::StateField.new(name: 'flag', type: 'bool', index: 0)]
      expect(Runar::SDK::State.serialize_state(fields, { 'flag' => st['flag'] })).to eq(hex)
    end
  end
end
