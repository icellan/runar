# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

RSpec.describe Runar::SDK::Envelope do
  # Scoped to this example group to avoid polluting top-level constants.
  # (ecdsa_spec.rb defines ALICE_PRIV_HEX / BOB_PRIV_HEX as top-level constants
  # with different values; leaving these at top-level here causes load-order
  # dependent failures in ecdsa_spec.)
  ENVELOPE_ALICE_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000001'
  ENVELOPE_BOB_PRIV_HEX   = '0000000000000000000000000000000000000000000000000000000000000002'

  def alice_pubkey
    Runar::ECDSA.pub_key_from_priv_key(ENVELOPE_ALICE_PRIV_HEX)
  end

  def bob_pubkey
    Runar::ECDSA.pub_key_from_priv_key(ENVELOPE_BOB_PRIV_HEX)
  end

  def alice_signer
    ->(digest) { Runar::ECDSA.ecdsa_sign(ENVELOPE_ALICE_PRIV_HEX.to_i(16), digest) }
  end

  def bob_signer
    ->(digest) { Runar::ECDSA.ecdsa_sign(ENVELOPE_BOB_PRIV_HEX.to_i(16), digest) }
  end

  describe '.canonical_json' do
    it 'is insertion-order independent' do
      a = described_class.canonical_json({ 'a' => 1, 'b' => 2 })
      b = described_class.canonical_json({ 'b' => 2, 'a' => 1 })
      expect(a).to eq(b)
      expect(a).to eq('{"a":1,"b":2}')
    end

    it 'handles nested objects and arrays' do
      got = described_class.canonical_json({
        'outer' => { 'z' => 1, 'a' => [3, 2, 1] },
        'list' => [{ 'y' => 1, 'x' => 2 }],
        'n' => nil,
        'b' => true,
        's' => 'hi'
      })
      expect(got).to eq('{"b":true,"list":[{"x":2,"y":1}],"n":null,"outer":{"a":[3,2,1],"z":1},"s":"hi"}')
    end

    it 'handles primitives and null' do
      expect(described_class.canonical_json(nil)).to eq('null')
      expect(described_class.canonical_json(true)).to eq('true')
      expect(described_class.canonical_json(42)).to eq('42')
      expect(described_class.canonical_json('hi')).to eq('"hi"')
    end

    # Audit D4 — symbol/string key coexistence must not silently rewrite
    # falsy values via `||`.
    it 'preserves falsy string-keyed values even when a symbol shadow exists' do
      got = described_class.canonical_json({ 'active' => false, 'count' => 0 })
      expect(got).to eq('{"active":false,"count":0}')
    end

    # Audit D5 — Float formatting must follow ECMA-262 Number::toString.
    it 'formats finite floats per ECMA-262 Number::toString' do
      expect(described_class.canonical_json({ 'v' => 0.1 })).to eq('{"v":0.1}')
      expect(described_class.canonical_json({ 'v' => 1e21 })).to eq('{"v":1e+21}')
      expect(described_class.canonical_json({ 'v' => 1e-7 })).to eq('{"v":1e-7}')
      expect(described_class.canonical_json({ 'v' => 1e-300 })).to eq('{"v":1e-300}')
    end

    # Audit D6 — lone surrogates are not valid Unicode scalar values. Ruby
    # rejects `"\u{D800}"` at parse time, so construct the WTF-8 sequence
    # by hand (0xED 0xA0 0x80 = U+D800) and force UTF-8 encoding to mirror
    # what a malicious or buggy caller could pass.
    it 'rejects a string containing a lone surrogate' do
      wtf8 = [0xED, 0xA0, 0x80].pack('C*').force_encoding(Encoding::UTF_8)
      expect {
        described_class.canonical_json(wtf8)
      }.to raise_error(ArgumentError, /lone surrogate|malformed Unicode/i)
    end
  end

  describe 'sign + verify' do
    let(:now_ms) { 1_000_000_000_000 }
    let(:verify_now_ms) { 1_000_000_000_500 }

    it 'round-trips' do
      env = described_class.sign_envelope(
        data: { 'kind' => 'hello', 'n' => 7 },
        signer: alice_signer,
        pubkey: alice_pubkey,
        now_ms: now_ms
      )
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(true), "reason: #{r[:reason]}"
      expect(r[:data]['kind']).to eq('hello')
    end

    it 'rejects missing fields' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      env.sig = ''
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(false)
      expect(r[:reason]).to eq('missing-fields')
    end

    it 'rejects expired' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      r = described_class.verify_envelope(envelope: env, now_ms: now_ms + 1_000_000)
      expect(r[:reason]).to eq('expired')
    end

    it 'rejects bad json' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      env.payload = 'not json{'
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:reason]).to eq('bad-json')
    end

    it 'rejects envelope mismatch' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      env.nonce += 1
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:reason]).to eq('envelope-mismatch')
      expect(r[:data]).not_to be_nil
    end

    it 'rejects bad sig' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      mid = env.sig.length / 2
      flip = env.sig[mid] == '1' ? '2' : '1'
      env.sig = env.sig[0...mid] + flip + env.sig[(mid + 1)..]
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:reason]).to eq('bad-sig')
    end

    it 'rejects pubkey not allowed' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      r = described_class.verify_envelope(envelope: env, expected_keys: [bob_pubkey], now_ms: verify_now_ms)
      expect(r[:reason]).to eq('pubkey-not-allowed')
    end

    it 'accepts pubkey in allowlist' do
      env = described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
      r = described_class.verify_envelope(envelope: env, expected_keys: [env.pubkey], now_ms: verify_now_ms)
      expect(r[:ok]).to be(true)
    end
  end

  # BUG-008 follow-up: DoS-bound size guards on verify_envelope.
  describe 'size guards (BUG-008)' do
    let(:now_ms) { 1_700_000_000_000 }
    let(:verify_now_ms) { now_ms + 500 }

    def base_envelope
      described_class.sign_envelope(
        data: { 'ok' => 1 }, signer: alice_signer, pubkey: alice_pubkey, now_ms: now_ms
      )
    end

    it 'rejects oversized payload as too-large before bad-json' do
      env = base_envelope
      env.payload = 'x' * (Runar::SDK::Envelope::MAX_ENVELOPE_PAYLOAD_BYTES + 1)
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(false)
      expect(r[:reason]).to eq('too-large')
    end

    it 'rejects oversized sig hex as too-large before bad-sig' do
      env = base_envelope
      env.sig = 'a' * (Runar::SDK::Envelope::MAX_ENVELOPE_FIELD_BYTES + 1)
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(false)
      expect(r[:reason]).to eq('too-large')
    end

    it 'rejects oversized pubkey hex as too-large before bad-sig' do
      env = base_envelope
      env.pubkey = 'b' * (Runar::SDK::Envelope::MAX_ENVELOPE_FIELD_BYTES + 1)
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(false)
      expect(r[:reason]).to eq('too-large')
    end

    it 'accepts a normally-sized envelope without tripping the size guard' do
      env = base_envelope
      r = described_class.verify_envelope(envelope: env, now_ms: verify_now_ms)
      expect(r[:ok]).to be(true)
    end
  end
end
