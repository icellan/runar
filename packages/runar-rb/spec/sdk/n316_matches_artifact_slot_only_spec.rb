# frozen_string_literal: true

# N-316: matches_artifact must treat code_sep_index_slots and code_part_len_slots
# as variable script elements even when constructor_slots is empty.
#
# Replays the shared cross-tier fixture
# conformance/sdk-matches-artifact/fixtures.json (also replayed by the TS, Go,
# Rust, Python, Zig and Java SDKs). Its first artifact is real compiler output
# for a stateful contract with no constructor args.
#
# Proves: an honest deployment of such an artifact matches it, and a script
# differing in one code byte before/after the slot does not.
# Does NOT prove: on-chain spendability, or slot layouts beyond the fixture.

require 'spec_helper'
require 'json'
require 'runar/sdk'

N316_FIXTURE_PATH = File.expand_path('../../../../../conformance/sdk-matches-artifact/fixtures.json', __FILE__)

RSpec.describe 'N-316: matches_artifact with only codeSepIndex / codePartLen slots' do
  JSON.parse(File.read(N316_FIXTURE_PATH))['cases'].each do |c|
    it c['name'] do
      artifact = Runar::SDK::RunarArtifact.from_hash(c['artifact'])
      expect(Runar::SDK::ScriptUtils.matches_artifact(artifact, c['script_hex'])).to eq(c['expected'])
    end
  end
end
