# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-051 (TaffyTail) — deploy-time code-part length pins.
#
# A stateful contract with a variable-length state section pins
# SIZE(_codePart) with the nine-byte run
#
#     76 | 04 LL LL LL LL | 81 | 9c | 69
#     OP_DUP  <len LE32>    OP_BIN2NUM  OP_NUMEQUAL  OP_VERIFY
#
# When a readonly constructor arg of variable width (TaffyTailVault's 256-byte
# `tag`) is baked into the code, the compiler cannot know the deployed length,
# so it records the field as an artifact `codePartLenSlots` entry and the SDK
# writes the deployed code-part length (inscription envelope included) into it.
#
# Fixtures: the TS-compiled TaffyTailVault artifact (fold OFF;
# codePartLenSlots = [{byteOffset: 959}]) and the TS SDK's output for the same
# constructor args. The Ruby SDK must reproduce those bytes exactly.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-051 codePartLenSlots deploy-time patch' do
  # rubocop:enable RSpec/DescribeClass

  def n051_fixture(name)
    File.read(File.expand_path("../fixtures/#{name}", __dir__))
  end

  def n051_expected
    @n051_expected ||= JSON.parse(n051_fixture('n051-taffytail-expected.json'))
  end

  def n051_artifact_hash
    JSON.parse(n051_fixture('n051-taffytail-artifact.json'))
  end

  def n051_contract(hash = n051_artifact_hash)
    artifact = Runar::SDK::RunarArtifact.from_hash(hash)
    Runar::SDK::RunarContract.new(artifact, n051_expected['constructorArgs'])
  end

  def n051_inscription
    insc = n051_expected['inscription']
    Runar::SDK::Inscription.new(content_type: insc['contentType'], data: insc['data'])
  end

  it 'parses codePartLenSlots from the artifact JSON' do
    artifact = Runar::SDK::RunarArtifact.from_hash(n051_artifact_hash)
    expect(artifact.code_part_len_slots.map(&:byte_offset)).to eq([959])
  end

  it 'patches the deployed code-part length into the pin field' do
    contract = n051_contract
    code = contract.send(:get_code_part_hex)

    expect(code).to eq(n051_expected['codePartHex'])
    expect(code.length / 2).to eq(n051_expected['codePartLen'])
    expect(contract.get_locking_script).to eq(n051_expected['lockingScriptHex'])
  end

  it 'accepts an inscription and patches the pin to the inscribed length' do
    contract = n051_contract

    expect { contract.with_inscription(n051_inscription) }.not_to raise_error
    expect(contract.inscription).not_to be_nil

    code = contract.send(:get_code_part_hex)
    expect(code).to eq(n051_expected['inscribedCodePartHex'])
    expect(code.length / 2).to eq(n051_expected['inscribedCodePartLen'])
  end

  it 'refuses a codePartLenSlots entry that does not point at a pin length field' do
    hash = n051_artifact_hash
    hash['codePartLenSlots'] = [{ 'byteOffset' => 958 }]
    contract = n051_contract(hash)

    expect { contract.get_locking_script }
      .to raise_error(/does not point at a verify_code_part_len length field/)
  end

  it 'still refuses an inscription that breaks an exact compile-time pin' do
    hash = n051_artifact_hash
    hash.delete('codePartLenSlots')
    # Without the slot the pin is an exact compile-time value that no envelope
    # was accounted for in, so attaching one must be refused.
    contract = n051_contract(hash)
    expect { contract.with_inscription(n051_inscription) }.to raise_error(ArgumentError, /pins SIZE\(_codePart\)/)
    expect(contract.inscription).to be_nil
  end

  describe 'matches_artifact' do
    # The real artifact: matches_artifact treats the codeSepIndex placeholder
    # (byte 1061, deployed as OP_1) as a variable element, like a constructor slot.
    def matcher_artifact
      Runar::SDK::RunarArtifact.from_hash(n051_artifact_hash)
    end

    it 'matches the deployed locking script (length field = deployed code-part length)' do
      artifact = matcher_artifact
      expect(Runar::SDK::ScriptUtils.matches_artifact(artifact, n051_expected['lockingScriptHex'])).to be(true)
    end

    it 'rejects a script whose length field does not equal its code-part length' do
      artifact = matcher_artifact
      script = n051_expected['lockingScriptHex'].dup
      # The owner slot (template byte 465) is the only substitution before the
      # pin; its 34-byte push replaces a 1-byte placeholder (+33 bytes).
      off = (959 + 33) * 2
      expect(script[off - 2, 2]).to eq('04')
      script[off, 8] = '00000000'
      expect(Runar::SDK::ScriptUtils.matches_artifact(artifact, script)).to be(false)
    end
  end
end
