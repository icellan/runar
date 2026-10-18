# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-330: a non-String ByteString-family constructor arg must be refused with
# the N-329 typed error. Before, encode_arg's fallback did value.to_s, so nil
# became "" (a bare OP_0), a Symbol became its name, and an Integer was encoded
# as a script number -- spliced into the locking script instead of an error.
# Ruby has no distinct raw-bytes type: a binary String IS a String, so it is
# covered by N-329's hex check (raw non-hex bytes are refused).
#
# Proves: nil, Integer, Float, true, Symbol, Hash, an Array of Integers for a
# non-FixedArray param, and a nil FixedArray<Addr, 2> leaf raise
# Runar::SDK::InvalidConstructorArgError with the shared diagnostic.
# Does NOT prove: width checks, method-call args or on-chain spendability.
RSpec.describe Runar::SDK::RunarContract, 'N-330: non-String ByteString constructor arg' do
  def artifact_for(type, fixed_array: nil)
    param = { name: 'owner', type: type }
    param[:fixedArray] = fixed_array if fixed_array
    Runar::SDK::RunarArtifact.from_json(JSON.generate(
      version: '1.0', compilerVersion: '0.1.0', contractName: 'N330',
      abi: { constructor: { params: [param] },
             methods: [{ name: 'noop', params: [], isPublic: true }] },
      script: '00', asm: '', stateFields: [],
      constructorSlots: [{ paramIndex: 0, byteOffset: 0 }]
    ))
  end

  let(:message) { /constructor arg 'owner' \(ByteString\) of N330 must be an even-length hex string/ }

  [nil, 5, 1.5, true, :aabb, { a: 1 }, [1, 2, 3]].each do |arg|
    it "refuses #{arg.inspect}" do
      expect { described_class.new(artifact_for('ByteString'), [arg]) }
        .to raise_error(Runar::SDK::InvalidConstructorArgError, message)
    end
  end

  it 'refuses a nil FixedArray<Addr, 2> leaf' do
    art = artifact_for('FixedArray<Addr, 2>',
                       fixed_array: { elementType: 'Addr', length: 2,
                                      syntheticNames: %w[owner__0 owner__1] })
    expect { described_class.new(art, [['aabb', nil]]) }
      .to raise_error(Runar::SDK::InvalidConstructorArgError)
  end
end
