# frozen_string_literal: true

# matches_artifact must check what sits at each constructor slot, not only the
# template bytes between slots: a push or small-integer opcode, the same bytes
# at every reference of one param, and exactly fixedValueByteLength bytes where
# the slot declares it. A stateful artifact's script must carry an OP_RETURN
# after its code part.
#
# Replays the shared cross-tier vector
# conformance/sdk-matches-artifact/slot-values.json (also replayed by the TS,
# Go, Rust, Python, Zig and Java SDKs), plus the TS unit cases for hex case,
# extract_constructor_args refusing a non-push opcode, and
# extract_constructor_args after a codeSepIndex slot wider than one byte.
#
# Proves: honest deployments match; the forgeries in the vector do not;
# extract_constructor_args raises MalformedScriptError on a non-push opcode at
# any reference of a param and reads an arg after a wide codeSep slot from its
# deployed position.
# Does NOT prove: that a slot push is minimally encoded, nor anything about
# the length of the state after the OP_RETURN.

require 'spec_helper'
require 'json'
require 'runar/sdk'

SLOT_VALUES_FIXTURE = JSON.parse(
  File.read(File.expand_path('../../../../../conformance/sdk-matches-artifact/slot-values.json', __FILE__))
)
SLOT_VALUES_G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

RSpec.describe 'matches_artifact checks the element at every constructor slot (slot-values.json)' do
  def artifact(key)
    Runar::SDK::RunarArtifact.from_hash(SLOT_VALUES_FIXTURE['artifacts'][key])
  end

  g = SLOT_VALUES_G

  SLOT_VALUES_FIXTURE['cases'].each do |c|
    it c['name'] do
      expect(Runar::SDK::ScriptUtils.matches_artifact(artifact(c['artifact']), c['script_hex'])).to eq(c['expected'])
    end
  end

  it 'compares slot values without regard to hex case' do
    expect(Runar::SDK::ScriptUtils.matches_artifact(artifact('owner2'), "21#{g}ad21#{g.upcase}ac")).to be(true)
  end

  {
    'at the first reference of a param' => ['owner2', "acad21#{g}ac"],
    'at a later reference of a param' => ['owner2', "21#{g}adacac"],
    'on SlotMatrix' => ['slotMatrix', "ac7b880111" + "7c9dac" + "21#{g}879169" + "21#{g}ac"]
  }.each do |name, (key, script)|
    it "extract_constructor_args refuses a non-push opcode #{name}" do
      expect { Runar::SDK::ScriptUtils.extract_constructor_args(artifact(key), script) }
        .to raise_error(Runar::SDK::MalformedScriptError)
    end
  end

  it 'extract_constructor_args still reads honest deployments' do
    SLOT_VALUES_FIXTURE['cases'].select { |c| c['expected'] && c['artifact'] == 'slotMatrix' }.each do |c|
      args = Runar::SDK::ScriptUtils.extract_constructor_args(artifact('slotMatrix'), c['script_hex'])
      expect(args).to include('count' => 17, 'owner' => g)
    end
    honest = SLOT_VALUES_FIXTURE['cases'].find { |c| c['name'] == 'owner2-honest' }
    expect(Runar::SDK::ScriptUtils.extract_constructor_args(artifact('owner2'), honest['script_hex']))
      .to eq('owner' => g)
  end

  it 'extract_constructor_args reads an arg after a codeSepIndex slot wider than one byte' do
    # Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked as
    # 143 (`02 8f00`), then a constructor slot at byte 3. Script pinned by the
    # TS SDK's RunarContract.getLockingScript().
    art = Runar::SDK::RunarArtifact.from_hash(
      'version' => 'runar-v1.0.0-rc.1',
      'compilerVersion' => '1.0.0-rc.1',
      'contractName' => 'CodeSepBeforeSlot',
      'abi' => { 'constructor' => { 'params' => [{ 'name' => 'x', 'type' => 'ByteString' }] }, 'methods' => [] },
      'script' => '5100520053',
      'constructorSlots' => [{ 'paramIndex' => 0, 'byteOffset' => 3 }],
      'codeSepIndexSlots' => [{ 'byteOffset' => 1, 'codeSepIndex' => 140 }]
    )
    script = '51028f005203aabbcc53'
    expect(Runar::SDK::ScriptUtils.matches_artifact(art, script)).to be(true)
    expect(Runar::SDK::ScriptUtils.extract_constructor_args(art, script)).to eq('x' => 'aabbcc')
  end
end
