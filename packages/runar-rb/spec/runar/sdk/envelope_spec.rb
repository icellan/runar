# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

ALICE_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000001'
BOB_PRIV_HEX   = '0000000000000000000000000000000000000000000000000000000000000002'

def alice_pubkey
  Runar::ECDSA.pub_key_from_priv_key(ALICE_PRIV_HEX)
end

def bob_pubkey
  Runar::ECDSA.pub_key_from_priv_key(BOB_PRIV_HEX)
end

def alice_signer
  ->(digest) { Runar::ECDSA.ecdsa_sign(ALICE_PRIV_HEX.to_i(16), digest) }
end

def bob_signer
  ->(digest) { Runar::ECDSA.ecdsa_sign(BOB_PRIV_HEX.to_i(16), digest) }
end

RSpec.describe Runar::SDK::Envelope do
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
end
