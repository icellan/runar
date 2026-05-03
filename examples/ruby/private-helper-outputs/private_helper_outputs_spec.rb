# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'PrivateHelperOutputs.runar'

RSpec.describe PrivateHelperOutputs do
  it 'commit invokes private state mutation and persists the change' do
    c = PrivateHelperOutputs.new(5)
    expect { c.commit }.not_to raise_error
    expect(c.counter).to eq(6)
  end

  it 'log routes a data output through a private helper' do
    c = PrivateHelperOutputs.new(0)
    expect { c.log('68656c6c6f') }.not_to raise_error
  end

  it 'partition routes a state output through a private helper' do
    c = PrivateHelperOutputs.new(100)
    expect { c.partition(30, 70) }.not_to raise_error
  end
end
