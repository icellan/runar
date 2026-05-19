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

  # RFC 8785 rejection vectors: canonical_json MUST raise/error for malformed
  # Unicode input. See audits/canonical-json-rfc8785-parity.md §3 rec 6 (D6).
  it 'rejects every canonical_json_rejection_vector' do
    fixture['canonical_json_rejection_vectors'].each do |v|
      units = v['input_value_utf16_units']
      # Pack as UTF-16BE bytes and force the encoding so Ruby preserves the
      # lone surrogate without trying to transcode at construction time.
      bytes = units.flat_map { |u| [(u >> 8) & 0xff, u & 0xff] }
      bad_str = bytes.pack('C*').force_encoding('UTF-16BE')
      input = { v['input_object_key'] => bad_str }
      expect { Runar::SDK::Envelope.canonical_json(input) }.to(
        raise_error(StandardError),
        "vector #{v['_vector_id']}: canonical_json MUST reject lone surrogate"
      )
    end
  end
end
