# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-045 (EXT-2 WideHash), SDK side — defence in depth only.
#
# The on-chain state reader slices each fixed-width byte field at its declared
# width, so a wrong-width value in a state section shifts every later field.
# The consensus defence is the covenant's own OP_SIZE <width>
# OP_NUMEQUALVERIFY before each continuation commit (proved under strict Spend
# in packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts).
# This spec pins the off-chain refusals: serialize_state and prepare_call
# reject a wrong-width fixed-width value. (Constructor args are deliberately
# NOT checked: from_utxo builds its contract with placeholder constructor args.
# A mutable field's deploy-time value still goes through serialize_state.) It
# proves nothing on chain.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-045 — wrong-width fixed-width values are refused off chain' do
  # rubocop:enable RSpec/DescribeClass
  types = { 'PubKey' => 33, 'Sha256' => 32, 'Ripemd160' => 20, 'Addr' => 20,
            'Point' => 64, 'P256Point' => 64, 'P384Point' => 96 }

  types.each do |type, width|
    it "serialize_state refuses a #{type} of the wrong width and accepts #{width} bytes" do
      fields = [Runar::SDK::StateField.new(name: 'k', type: type, index: 0)]
      [width - 1, width + 1].each do |bad|
        expect { Runar::SDK::State.serialize_state(fields, { 'k' => 'ab' * bad }) }
          .to raise_error(ArgumentError, /must be exactly #{width} bytes/)
      end
      expect { Runar::SDK::State.serialize_state(fields, { 'k' => 'zz' * width }) }
        .to raise_error(ArgumentError, /non-hex/)
      expect(Runar::SDK::State.serialize_state(fields, { 'k' => 'ab' * width })).to eq('ab' * width)
    end
  end

  def root_artifact
    Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v0.1.0',
      'contractName' => 'N045Root',
      'script' => '51',
      'stateFields' => [{ 'name' => 'root', 'type' => 'Sha256', 'index' => 0 }],
      'codeSeparatorIndex' => 0,
      'abi' => {
        'constructor' => { 'params' => [{ 'name' => 'root', 'type' => 'Sha256' }] },
        'methods' => [{
          'name' => 'updateRoot',
          'isPublic' => true,
          'params' => [
            { 'name' => 'nextRoot', 'type' => 'Sha256' },
            { 'name' => '_changePKH', 'type' => 'Ripemd160' },
            { 'name' => '_changeAmount', 'type' => 'bigint' },
            { 'name' => 'txPreimage', 'type' => 'SigHashPreimage' }
          ]
        }]
      }
    )
  end

  [31, 33, 66].each do |bad|
    it "prepare_call refuses a #{bad}-byte Sha256 argument" do
      contract = Runar::SDK::RunarContract.new(root_artifact, ['11' * 32])
      signer   = Runar::SDK::MockSigner.new(address: '00' * 20)
      provider = Runar::SDK::MockProvider.new(network: 'testnet')
      provider.add_utxo(signer.get_address, Runar::SDK::Utxo.new(
                                              txid: 'aa' * 32, output_index: 0, satoshis: 100_000,
                                              script: "76a914#{'00' * 20}88ac"
                                            ))
      contract.deploy(provider, signer, Runar::SDK::DeployOptions.new(satoshis: 50_000))
      expect { contract.prepare_call('updateRoot', ['22' * bad], provider, signer) }
        .to raise_error(ArgumentError, /arg 'nextRoot' \(index 0\).*must be exactly 32 bytes/)
    end
  end
end
