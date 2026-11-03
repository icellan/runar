# frozen_string_literal: true

# N-318: matches_artifact must check the VALUE at every codeSepIndex slot.
# Deploy bakes encode_script_int(code_sep_index + shift) there (shift = growth
# of every constructor slot, and every earlier codeSep slot, before
# code_sep_index); the matcher used to accept any element at the slot.
#
# Replays the shared cross-tier vector
# conformance/sdk-matches-artifact/codesep.json (also replayed by the TS, Go,
# Rust, Python, Zig and Java SDKs): honest TS-SDK deployments of a real
# compiled artifact and of a synthetic artifact whose baked values depend on a
# variable-length constructor arg, plus forgeries differing only in the number
# pushed at a codeSep slot.
#
# Proves: honest deployments match whatever the constructor-arg width, and a
# forged separator index (OP_0, off by one, non-minimal, unshifted) does not.
# Does NOT prove: on-chain spendability of the honest scripts, nor that the
# Ruby deploy side bakes the same value (see resolved_code_sep_slot_values).

require 'spec_helper'
require 'json'
require 'runar/sdk'

N318_FIXTURE = JSON.parse(
  File.read(File.expand_path('../../../../../conformance/sdk-matches-artifact/codesep.json', __FILE__))
)

RSpec.describe 'N-318: matches_artifact checks the value baked at codeSepIndex slots' do
  N318_FIXTURE['cases'].each do |c|
    it c['name'] do
      artifact = Runar::SDK::RunarArtifact.from_hash(N318_FIXTURE['artifacts'][c['artifact']])
      expect(Runar::SDK::ScriptUtils.matches_artifact(artifact, c['script_hex'])).to eq(c['expected'])
    end
  end
end
