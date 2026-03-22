# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::SmartContract do
  it 'can be subclassed' do
    klass = Class.new(Runar::SmartContract) do
      prop :value, Bigint

      def initialize(value)
        super(value)
        @value = value
      end
    end

    obj = klass.new(42)
    expect(obj.value).to eq(42)
  end

  it 'includes the DSL module' do
    expect(Runar::SmartContract).to respond_to(:prop)
    expect(Runar::SmartContract).to respond_to(:runar_public)
    expect(Runar::SmartContract).to respond_to(:params)
  end
end

RSpec.describe Runar::StatefulSmartContract do
  it 'inherits from SmartContract' do
    expect(Runar::StatefulSmartContract).to be < Runar::SmartContract
  end

  it 'has add_output, outputs, and reset_outputs' do
    klass = Class.new(Runar::StatefulSmartContract) do
      prop :count, Bigint

      def initialize(count)
        super(count)
        @count = count
      end
    end

    obj = klass.new(0)
    expect(obj.outputs).to eq([])

    obj.add_output(1000, 5)
    expect(obj.outputs.length).to eq(1)
    expect(obj.outputs[0][:satoshis]).to eq(1000)
    expect(obj.outputs[0][:values]).to eq([5])

    obj.add_output(2000, 10, 20)
    expect(obj.outputs.length).to eq(2)
    expect(obj.outputs[1][:values]).to eq([10, 20])

    obj.reset_outputs
    expect(obj.outputs).to eq([])
  end

  it 'initialises tx_preimage to empty string' do
    obj = Runar::StatefulSmartContract.new
    expect(obj.tx_preimage).to eq('')
  end

  it 'passes constructor through to super' do
    klass = Class.new(Runar::StatefulSmartContract) do
      prop :balance, Bigint

      def initialize(balance)
        super(balance)
        @balance = balance
      end
    end

    obj = klass.new(100)
    expect(obj.balance).to eq(100)
    expect(obj.outputs).to eq([])
  end
end
