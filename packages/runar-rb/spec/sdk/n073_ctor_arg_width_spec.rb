# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-073: a fixed-width ByteString-family constructor arg must have its declared
# width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
# P384Point 96), with N-045's message. from_utxo's internal restore path is
# unaffected.
#
# Proves: a 33-byte Sha256 and a 19-byte Addr (scalar and FixedArray leaf)
# raise Runar::SDK::InvalidConstructorArgError carrying the N-045 wording;
# correct widths are accepted; ByteString takes any length; from_utxo restores.
# Does NOT prove: method-call or state value widths (N-045), on-chain
# spendability, or that the restore bypass is unreachable by user input.
RSpec.describe Runar::SDK::RunarContract, 'N-073: fixed-width constructor arg' do
  def artifact_for(type, fixed_array: nil)
    param = { name: 'owner', type: type }
    param[:fixedArray] = fixed_array if fixed_array
    Runar::SDK::RunarArtifact.from_json(JSON.generate(
      version: '1.0', compilerVersion: '0.1.0', contractName: 'N073',
      abi: { constructor: { params: [param] },
             methods: [{ name: 'noop', params: [], isPublic: true }] },
      script: '00', asm: '', stateFields: [],
      constructorSlots: [{ paramIndex: 0, byteOffset: 0 }]
    ))
  end

  def hex(n) = 'ab' * n

  it 'refuses a 33-byte Sha256 with the N-045 message' do
    expect { described_class.new(artifact_for('Sha256'), [hex(33)]) }
      .to raise_error(Runar::SDK::InvalidConstructorArgError,
                      /constructor arg 'owner' \(Sha256\) must be exactly 32 bytes of hex, got 33 bytes/)
  end

  it 'refuses a 19-byte Addr' do
    expect { described_class.new(artifact_for('Addr'), [hex(19)]) }
      .to raise_error(Runar::SDK::InvalidConstructorArgError)
  end

  it 'refuses a 19-byte Addr FixedArray leaf' do
    art = artifact_for('FixedArray<Addr, 2>',
                       fixed_array: { elementType: 'Addr', length: 2, syntheticNames: %w[owner__0 owner__1] })
    expect { described_class.new(art, [[hex(20), hex(19)]]) }
      .to raise_error(Runar::SDK::InvalidConstructorArgError)
  end

  { 'Addr' => 20, 'Ripemd160' => 20, 'Sha256' => 32, 'PubKey' => 33,
    'Point' => 64, 'P256Point' => 64, 'P384Point' => 96 }.each do |type, n|
    it "accepts #{n} bytes for #{type} and refuses one byte less" do
      expect { described_class.new(artifact_for(type), [hex(n)]).get_locking_script }.not_to raise_error
      expect { described_class.new(artifact_for(type), [hex(n - 1)]) }
        .to raise_error(Runar::SDK::InvalidConstructorArgError)
    end
  end

  it 'still accepts any length for ByteString' do
    expect { described_class.new(artifact_for('ByteString'), [hex(3)]) }.not_to raise_error
  end

  it 'from_utxo still restores a contract' do
    art = artifact_for('Addr')
    script = described_class.new(art, [hex(20)]).get_locking_script
    utxo = Runar::SDK::Utxo.new(txid: '00' * 32, output_index: 0, satoshis: 1, script: script)
    expect(described_class.from_utxo(art, utxo).get_locking_script).to eq(script)
  end
end
