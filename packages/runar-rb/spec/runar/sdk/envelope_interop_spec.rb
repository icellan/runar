# frozen_string_literal: true

# Cross-tier interop test for the signed-envelope wire protocol.
# Loads `conformance/sdk-envelope/fixtures.json` (TS reference) and asserts
# canonical_json byte-parity + verify ok/reason parity.
#
# See CLAUDE.md §"Seven SDKs Must Stay in Sync".

require 'spec_helper'
require 'digest'
require 'json'
require 'runar/sdk'
require 'runar/ecdsa'

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

  # GAP-064 cross-tier signing reproduction. Signing the SAME payload with the
  # SAME key (priv=1) via RFC 6979 deterministic ECDSA (plain-SHA-256 nonce,
  # low-S) MUST yield the byte-identical DER signature the TS reference
  # committed. ecdsa_sign signs the 32-byte digest directly.
  it 'reproduces every signing vector byte-identically' do
    alice_priv = 1
    fixture['signing_vectors'].each do |v|
      vid = v['_vector_id'] || '?'
      # Drift guard: re-derive the canonical payload from data + lifetime.
      merged = v['data'].merge('nonce' => v['nonce'], 'expiresAt' => v['expiresAt'])
      payload = Runar::SDK::Envelope.canonical_json(merged)
      expect(payload).to eq(v['expected_payload']), "vector #{vid}: payload"

      digest = Digest::SHA256.digest(payload)
      der = Runar::ECDSA.ecdsa_sign(alice_priv, digest).unpack1('H*')
      expect(der).to eq(v['expected_sig']), "vector #{vid}: signature divergence"
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
  # R-260. verify_envelope must bound payload nesting ITSELF rather than
  # inherit whatever cap JSON.parse happens to impose, because that cap differs
  # per tier (THIS tier 100, rust 127, ts/go/python/zig none, java a
  # StackOverflowError whose threshold is the JVM's -Xss flag). All seven tiers
  # enforce MAX_ENVELOPE_PAYLOAD_DEPTH on the payload TEXT, so the same bytes
  # get the same VerifyEnvelopeReason everywhere.
  it 'applies the shared payload depth bound to every depth vector' do
    vectors = fixture['depth_vectors']
    expect(vectors).not_to be_empty
    vectors.each do |v|
      vid = v['_vector_id']
      env = Runar::SDK::Envelope::SignedEnvelope.from_h(v['envelope'])
      r = Runar::SDK::Envelope.verify_envelope(envelope: env, now_ms: fixture['verify_now_ms'])
      if v['expect_ok']
        expect(r[:ok]).to be(true), "#{vid}: expected ok=true, got reason=#{r[:reason]}"
      else
        expect(r[:ok]).to be(false), "#{vid}: expected ok=false"
        expect(r[:reason]).to eq(v['reason']), "#{vid}: got reason=#{r[:reason]}"
      end
    end
  end

  # This tier needs an assertion the end-to-end vectors cannot give it. Ruby's
  # JSON.parse default (max_nesting: 100) already rejects the over-limit vector
  # on its own, so weakening payload_exceeds_max_depth? does NOT redden the
  # depth_vectors example here — the library masks it. Assert the guard
  # directly so it has a test that fails when the guard stops working, rather
  # than one that passes because the stdlib happens to agree today.
  it 'payload_exceeds_max_depth? fires at exactly one past the bound' do
    limit = Runar::SDK::Envelope::MAX_ENVELOPE_PAYLOAD_DEPTH
    at_limit = ('[' * limit) + '0' + (']' * limit)
    over_limit = ('[' * (limit + 1)) + '0' + (']' * (limit + 1))
    expect(Runar::SDK::Envelope.payload_exceeds_max_depth?(at_limit)).to be(false)
    expect(Runar::SDK::Envelope.payload_exceeds_max_depth?(over_limit)).to be(true)
    # Brackets inside a string are text, not nesting.
    expect(Runar::SDK::Envelope.payload_exceeds_max_depth?(%({"m":"#{'[' * (limit + 50)}"}))).to be(false)
  end

  # The bound is part of the wire contract, so the fixture pins it and every
  # tier asserts its own constant against the fixture's number.
  it 'pins MAX_ENVELOPE_PAYLOAD_DEPTH to the fixture' do
    expect(fixture['payload_depth_limit']).to eq(Runar::SDK::Envelope::MAX_ENVELOPE_PAYLOAD_DEPTH)
  end

end
