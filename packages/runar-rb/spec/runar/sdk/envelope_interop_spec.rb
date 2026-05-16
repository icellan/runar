# frozen_string_literal: true

# Cross-tier interop test for the signed-envelope wire protocol.
# Loads `conformance/sdk-envelope/fixtures.json` (TS reference) and asserts
# canonical_json byte-parity + verify ok/reason parity.
#
# See CLAUDE.md §"Seven SDKs Must Stay in Sync".

require 'spec_helper'
require 'json'
require 'runar/sdk'

FIXTURE_PATH = File.expand_path('../../../../../../conformance/sdk-envelope/fixtures.json', __FILE__)

RSpec.describe 'Runar::SDK::Envelope cross-tier interop' do
  let(:fixture) { JSON.parse(File.read(FIXTURE_PATH)) }

  it 'canonical_json byte-parity across every vector' do
    fixture['canonical_json_vectors'].each_with_index do |v, i|
      got = Runar::SDK::Envelope.canonical_json(v['input'])
      expect(got).to eq(v['expected']), "vector #{i}: got #{got.inspect}, want #{v['expected'].inspect}"
    end
  end

  it 'verifies the valid envelope at verify_now_ms' do
    env = Runar::SDK::Envelope::SignedEnvelope.from_h(fixture['valid_envelope'])
    r = Runar::SDK::Envelope.verify_envelope(envelope: env, now_ms: fixture['verify_now_ms'])
    expect(r[:ok]).to be(true), "reason: #{r[:reason]}"
  end

  it 'returns the listed reason for every rejection vector' do
    fixture['rejection_vectors'].each do |v|
      env = Runar::SDK::Envelope::SignedEnvelope.from_h(v['envelope'])
      r = Runar::SDK::Envelope.verify_envelope(envelope: env, now_ms: fixture['verify_now_ms'])
      expect(r[:ok]).to be(false), "rejection #{v['reason']} should be ok=false"
      expect(r[:reason]).to eq(v['reason']), "rejection #{v['reason']}: got #{r[:reason]}"
    end
  end
end
