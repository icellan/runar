# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-329: a ByteString-family constructor arg that is not an even-length hex
# string must be refused at construction with a typed error, not spliced into
# the locking script as raw text (a push header sized for the raw bytes
# followed by non-hex characters, with no error).
#
# Proves: RunarContract.new raises Runar::SDK::InvalidConstructorArgError (the
# shared diagnostic) for raw non-hex Addr bytes, odd-length hex and a non-hex
# FixedArray<Addr, 2> leaf; valid hex (either case, empty) is accepted and
# get_locking_script is hex-only.
# Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
# spendability.
RSpec.describe Runar::SDK::RunarContract, 'N-329: non-hex ByteString constructor arg' do
  def artifact_for(type, fixed_array: nil)
    param = { name: 'owner', type: type }
    param[:fixedArray] = fixed_array if fixed_array
    Runar::SDK::RunarArtifact.from_json(JSON.generate(
      version: '1.0', compilerVersion: '0.1.0', contractName: 'N329',
      abi: { constructor: { params: [param] },
             methods: [{ name: 'noop', params: [], isPublic: true }] },
      script: '00', asm: '', stateFields: [],
      constructorSlots: [{ paramIndex: 0, byteOffset: 0 }]
    ))
  end

  let(:message) { /constructor arg 'owner' \(.*\) of N329 must be an even-length hex string/ }

  [
    ['Addr', ((0x80..0x93).map(&:chr).join).b],
    ['Addr', ((0x80..0x93).map(&:chr).join)],
    ['ByteString', 'abc'],
    ['PubKey', 'zz']
  ].each do |type, arg|
    it "refuses #{type} #{arg.inspect}" do
      expect { described_class.new(artifact_for(type), [arg]) }
        .to raise_error(Runar::SDK::InvalidConstructorArgError, message)
    end
  end

  it 'refuses a non-hex FixedArray<Addr, 2> leaf' do
    art = artifact_for('FixedArray<Addr, 2>',
                       fixed_array: { elementType: 'Addr', length: 2,
                                      syntheticNames: %w[owner__0 owner__1] })
    expect { described_class.new(art, [['aabb', 'not-hex!']]) }
      .to raise_error(Runar::SDK::InvalidConstructorArgError)
  end

  ['9a1c78a5', '9A1C78A5', ''].each do |arg|
    it "accepts hex #{arg.inspect}" do
      c = described_class.new(artifact_for('ByteString'), [arg])
      expect(Runar::SDK::ScriptUtils.hex_bytes?(c.get_locking_script)).to be(true)
    end
  end
end
