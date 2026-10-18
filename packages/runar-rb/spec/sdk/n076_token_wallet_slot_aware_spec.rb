# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# N-076: TokenWallet#get_utxos must discover a deployed token contract with the
# slot-aware matcher (matches_artifact), not a raw prefix of the template. The
# template carries a constructor slot, a codeSepIndex slot (baked as OP_1) and
# a code_part_len_slots field (the deployed code-part length), none of which a
# literal prefix of the template can equal.
#
# Proves: a deployed instance of such a template (with a state section) is
# found, while scripts that share the pre-slot prefix but differ after it,
# carry a wrong code-part length, or are unrelated are not.
# Does NOT prove: on-chain spendability of the matched UTXO, nor that an
# artifact with only codeSepIndex slots (no constructor slots) is matched --
# matches_artifact itself compares such a template literally.
RSpec.describe 'N-076: TokenWallet#get_utxos uses the slot-aware matcher' do
  # bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
  #   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
  let(:artifact) do
    Runar::SDK::RunarArtifact.new(
      contract_name: 'FungibleToken',
      script: '76a9' + '00' + '88' + '00' + '75' + '04' + '00000000' + 'ac',
      state_fields: [Runar::SDK::StateField.new(name: 'balance', type: 'bigint', index: 1)],
      constructor_slots: [Runar::SDK::ConstructorSlot.new(param_index: 0, byte_offset: 2)],
      code_sep_index_slots: [Runar::SDK::CodeSepIndexSlot.new(byte_offset: 4, code_sep_index: 0)],
      code_part_len_slots: [Runar::SDK::CodePartLenSlot.new(byte_offset: 7)]
    )
  end

  # supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes.
  def deployed(tail = 'ac', length = '0e000000')
    '76a9' + '02aabb' + '88' + '51' + '75' + '04' + length + tail + '6a' + '0100'
  end

  def discover(*scripts)
    provider = Runar::SDK::MockProvider.new
    signer = Runar::SDK::MockSigner.new
    scripts.each_with_index do |script, i|
      provider.add_utxo(signer.get_address,
                        Runar::SDK::Utxo.new(txid: i.to_s * 64, output_index: 0, satoshis: 1000, script: script))
    end
    Runar::SDK::TokenWallet.new(artifact, provider, signer).get_utxos.map { |u| u.txid[0] }
  end

  it 'finds a deployed instance with constructor, codeSepIndex and code-part-length slots' do
    expect(discover(deployed)).to eq(['0'])
  end

  it 'does not match scripts that share the pre-slot prefix but differ after it' do
    expect(discover(deployed('ad'))).to eq([])
  end

  it 'does not match a script with a wrong code-part length field' do
    expect(discover(deployed('ac', '0f000000'))).to eq([])
  end

  it 'does not match an unrelated script' do
    expect(discover('76a914' + '11' * 20 + '88ac')).to eq([])
  end
end
