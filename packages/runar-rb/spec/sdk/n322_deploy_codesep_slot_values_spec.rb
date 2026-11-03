# frozen_string_literal: true

# N-322: the Ruby deploy path must bake the same codeSepIndex slot values as
# the TS SDK. resolved_code_sep_slot_values used to add only constructor-slot
# expansion, so when an earlier codeSep slot baked a value > 16 (a 2+ byte
# push instead of the 1-byte OP_0 placeholder) a later slot's value was too
# small by that growth; it also did not process slots in byte-offset order.
#
# Replays every honest case of the shared cross-tier vector
# conformance/sdk-matches-artifact/codesep.json. Those script_hex values are
# TS RunarContract#getLockingScript output (N-318 generator,
# remediation-logs/N-318/gen.mts.txt); the constructor args below are the ones
# that generator passed, keyed by case name. Each artifact is also deployed with
# its codeSepIndexSlots listed in reverse order (TS sorts them, so the bytes
# must not change), and Ruby's own matches_artifact must accept what Ruby
# deploys.
#
# Proves: Ruby RunarContract#get_locking_script is byte-identical to TS for
# every honest case, including shift-tag20/tag200 where the first codeSep value
# (22 / 203) grows its slot and precedes the second slot's codeSepIndex.
# Does NOT prove: on-chain spendability, signing-time codesep offsets
# (get_code_sep_index), or two codeSep slots at the same byte offset.

require 'spec_helper'
require 'json'
require 'runar/sdk'

N322_FIXTURE = JSON.parse(
  File.read(File.expand_path('../../../../../conformance/sdk-matches-artifact/codesep.json', __FILE__))
)

N322_ARGS = {
  'real-cap0-honest' => [0, ''],
  'real-cap5-honest' => [5, 'abcd'],
  'real-cap1000-honest' => [1000, ''],
  'real-cap2pow200-honest' => [(1 << 200) + 7, '00'],
  'shift-tag0-honest' => [''],
  'shift-tag2-honest' => ['0511'],
  'shift-tag20-honest' => ['11' * 20],
  'shift-tag200-honest' => ['22' * 200]
}.freeze

RSpec.describe 'N-322: Ruby deploy bakes the TS codeSepIndex slot values' do
  honest = N322_FIXTURE['cases'].select { |c| c['expected'] }

  it 'covers every honest case of codesep.json' do
    expect(honest.map { |c| c['name'] }).to match_array(N322_ARGS.keys)
  end

  honest.each do |c|
    [false, true].each do |reverse|
      it "#{c['name']}#{reverse ? ' (codeSepIndexSlots reversed)' : ''}" do
        h = JSON.parse(JSON.generate(N322_FIXTURE['artifacts'][c['artifact']]))
        h['codeSepIndexSlots'] = h['codeSepIndexSlots'].reverse if reverse
        artifact = Runar::SDK::RunarArtifact.from_hash(h)
        script = Runar::SDK::RunarContract.new(artifact, N322_ARGS.fetch(c['name'])).get_locking_script
        expect(script).to eq(c['script_hex'])
        expect(Runar::SDK::ScriptUtils.matches_artifact(artifact, script)).to be(true)
      end
    end
  end
end
