# frozen_string_literal: true

# GK-BUG-009: inner nonce/expiresAt must be a JSON integer token in i64 range.
#
# The cross-tier vectors (it1..it8) live in conformance/sdk-envelope/fixtures.json
# and are replayed by envelope_interop_spec.rb. This file pins the i64 boundary,
# which only Ruby and Python (unbounded integers) must check explicitly: an
# outer nonce of 2**63 equals an inner token of 2**63 by value, so only the
# range check rejects it. Every envelope is validly signed for its exact
# payload text, so a wrong accept shows as ok, not bad-sig.

require 'spec_helper'
require 'digest'
require 'runar/sdk'
require 'runar/ecdsa'

RSpec.describe 'GK-BUG-009 envelope integer tokens' do
  exp = 1_700_000_030_000
  now = 1_700_000_000_500
  pub = Runar::ECDSA.pub_key_from_priv_key(('00' * 31) + '01')

  signed = lambda do |payload, nonce, expires_at|
    sig = Runar::ECDSA.ecdsa_sign(1, Digest::SHA256.digest(payload)).unpack1('H*')
    Runar::SDK::Envelope::SignedEnvelope.new(payload, sig, pub, nonce, expires_at)
  end

  it 'accepts an integer token at the i64 maximum' do
    n = (2**63) - 1
    r = Runar::SDK::Envelope.verify_envelope(envelope: signed.call(%({"expiresAt":#{exp},"nonce":#{n}}), n, exp),
                                             now_ms: now)
    expect(r[:ok]).to be(true), "reason: #{r[:reason]}"
  end

  it 'rejects an integer token one past the i64 maximum' do
    n = 2**63
    r = Runar::SDK::Envelope.verify_envelope(envelope: signed.call(%({"expiresAt":#{exp},"nonce":#{n}}), n, exp),
                                             now_ms: now)
    expect(r[:ok]).to be(false)
    expect(r[:reason]).to eq('envelope-mismatch')
  end

  it 'rejects an integer token one below the i64 minimum' do
    n = -(2**63) - 1
    r = Runar::SDK::Envelope.verify_envelope(envelope: signed.call(%({"expiresAt":#{exp},"nonce":#{n}}), n, exp),
                                             now_ms: now)
    expect(r[:ok]).to be(false)
    expect(r[:reason]).to eq('envelope-mismatch')
  end
end
