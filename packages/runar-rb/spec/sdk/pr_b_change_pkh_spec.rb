# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# #213, SDK side — defence in depth only.
#
# A stateful method's unlocking script pushes the compiler-injected
# `_changePKH` (a Ripemd160, exactly 20 bytes). The consensus defence is the
# covenant's entry gate on its width (OP_SIZE 0x14 OP_NUMEQUALVERIFY).
# RunarContract derives the change PKH as hash160(pubkey), always 20 bytes;
# State.encode_change_pkh is the single encoder every change-PKH push site goes
# through, and refuses anything that is not exactly 20 bytes of hex.
# PreparedCall#change_pkh_hex is a public Struct accessor, so the refusal is
# also pinned through finalize_call. Proves nothing on chain.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe '#213 — a changePKH that is not 20 bytes is refused off chain' do
  # rubocop:enable RSpec/DescribeClass
  [19, 21, 54].each do |n|
    it "encode_change_pkh refuses #{n} bytes" do
      expect { Runar::SDK::State.encode_change_pkh('ab' * n) }
        .to raise_error(ArgumentError, /changePKH \(Ripemd160\) must be exactly 20 bytes/)
    end
  end

  it 'encode_change_pkh refuses non-hex' do
    expect { Runar::SDK::State.encode_change_pkh('zz' * 20) }
      .to raise_error(ArgumentError, /changePKH \(Ripemd160\) must be exactly 20 bytes of hex, got a non-hex string/)
  end

  it 'encode_change_pkh accepts exactly 20 bytes' do
    expect(Runar::SDK::State.encode_change_pkh('ab' * 20)).to eq('14' + ('ab' * 20))
  end

  def counter_artifact
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'contractName' => 'PrBCounter',
      'script' => '51',
      'stateFields' => [{ 'name' => 'count', 'type' => 'bigint', 'index' => 0 }],
      'codeSeparatorIndex' => 0,
      'abi' => {
        'constructor' => { 'params' => [{ 'name' => 'count', 'type' => 'bigint' }] },
        'methods' => [{
          'name' => 'increment',
          'isPublic' => true,
          'params' => [
            { 'name' => '_changePKH', 'type' => 'Ripemd160' },
            { 'name' => '_changeAmount', 'type' => 'bigint' },
            { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' }
          ]
        }]
      }
    )
  end

  [19, 21, 54].each do |n|
    it "finalize_call refuses a caller-set #{n}-byte change_pkh_hex" do
      contract = Runar::SDK::RunarContract.new(counter_artifact, [0])
      prepared = Runar::SDK::PreparedCall.new(
        method_name: 'increment', is_stateful: true, method_needs_change: true,
        change_pkh_hex: 'ab' * n
      )
      expect { contract.finalize_call(prepared, {}, Runar::SDK::MockProvider.new(network: 'testnet')) }
        .to raise_error(ArgumentError, /changePKH \(Ripemd160\) must be exactly 20 bytes/)
    end
  end
end
