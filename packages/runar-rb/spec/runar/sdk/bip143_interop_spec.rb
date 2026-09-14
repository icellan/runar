# frozen_string_literal: true

# Cross-tier BIP-143 sighash interop test (GAP-003).
#
# Loads `conformance/sdk-bip143/fixtures.json` (TS reference, generated via
# @bsv/sdk TransactionSignature.format) and asserts, for every scenario, that
# this tier's hand-written BIP-143 implementation:
#
#   1. recomputes the full preimage byte-identically from (unsignedTxHex,
#      inputIndex, prevScriptHex, prevValueSats) — the core node-free
#      cross-tier correctness check;
#   2. produces sha256d(preimage) == the fixture digestHex; and
#   3. verifies the TS-produced sigHex against pubkeyHex over that digest.
#
# Any failure here is a cross-tier BIP-143 protocol divergence (a real
# consensus bug). See CLAUDE.md §"Seven SDKs Must Stay in Sync".

require 'spec_helper'
require 'digest'
require 'json'
require 'runar/sdk'
require 'runar/ecdsa'

BIP143_FIXTURE_PATH = File.expand_path('../../../../../../conformance/sdk-bip143/fixtures.json', __FILE__)

RSpec.describe 'Runar::SDK BIP-143 cross-tier interop' do
  let(:fixture) { JSON.parse(File.read(BIP143_FIXTURE_PATH)) }

  def sha256d(bytes)
    Digest::SHA256.digest(Digest::SHA256.digest(bytes))
  end

  it 'recomputes preimage + digest and verifies the TS signature for every scenario' do
    scenarios = fixture['scenarios']
    expect(scenarios).not_to be_empty

    scenarios.each do |s|
      name = s['scenario']
      # 1. Independently recompute the BIP-143 preimage (hand-written impl)
      #    under the scenario's OWN sighash flags.
      #
      #    R-206: this used to reject anything but 0x41, and every scenario in
      #    the fixture was ALL|FORKID — so the per-mode zeroing rules were
      #    implemented seven times and compared zero times.
      _sig_hex, got_preimage = Runar::SDK.compute_op_push_tx(
        s['unsignedTxHex'], s['inputIndex'], s['prevScriptHex'], s['prevValueSats'],
        -1, s['sighashFlags']
      )
      expect(got_preimage).to eq(s['preimageHex']),
                              "#{name}: BIP-143 PREIMAGE DIVERGENCE from TS reference\n" \
                              "  want #{s['preimageHex']}\n  got  #{got_preimage}"

      # 2. sha256d(preimage) must equal the published digest.
      preimage_bytes = [got_preimage].pack('H*')
      got_digest = sha256d(preimage_bytes).unpack1('H*')
      expect(got_digest).to eq(s['digestHex']), "#{name}: sighash digest divergence"

      # 3. The TS-produced signature must verify over this tier's digest.
      sig_full = [s['sigHex']].pack('H*')
      der = sig_full[0...-1] # strip trailing sighash byte
      pk_bytes = [s['pubkeyHex']].pack('H*')
      ok = Runar::ECDSA.ecdsa_verify(der, pk_bytes, sha256d(preimage_bytes))
      expect(ok).to be(true),
                    "#{name}: TS reference signature does not verify under this tier's digest"
    end
  end
end
