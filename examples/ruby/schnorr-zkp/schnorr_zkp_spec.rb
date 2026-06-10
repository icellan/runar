# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'SchnorrZKP.runar'

RSpec.describe SchnorrZKP do
  it 'verifies a Schnorr zero-knowledge proof' do
    # Private key k, public key P = k*G
    k = 12_345
    pub_key = ec_mul_gen(k)

    # Prover: pick random r, compute R = r*G
    r = 67_890
    r_point = ec_mul_gen(r)

    # Derive challenge via Fiat-Shamir (must match the contract's internal computation)
    e = bin2num(hash256(cat(r_point, pub_key)))

    # Response s = r + e*k (mod n)
    s = (r + e * k) % EC_N

    c = SchnorrZKP.new(pub_key)
    expect { c.verify(r_point, s) }.not_to raise_error
  end

  # BUG-001 adversarial tests — see examples/ts/schnorr-zkp/SchnorrZKP.test.ts
  # for the canonical commentary; this is the .runar.rb mirror.
  it 'rejects_s_at_n: s = secp256k1 group order is rejected' do
    k = 12_345
    pub_key = ec_mul_gen(k)
    r = 67_890
    r_point = ec_mul_gen(r)
    c = SchnorrZKP.new(pub_key)
    expect { c.verify(r_point, EC_N) }.to raise_error(StandardError)
  end

  it 'rejects_s_zero: s = 0 is rejected' do
    k = 12_345
    pub_key = ec_mul_gen(k)
    r = 67_890
    r_point = ec_mul_gen(r)
    c = SchnorrZKP.new(pub_key)
    expect { c.verify(r_point, 0) }.to raise_error(StandardError)
  end

  it 'nonce_reuse_recovers_key: reusing r across proofs leaks the private key off-chain' do
    k = 0xC0FFEE
    pub_key = ec_mul_gen(k)
    r = 12_345
    r_point = ec_mul_gen(r)
    e1 = bin2num(hash256(cat(r_point, pub_key)))
    s1 = (r + e1 * k) % EC_N
    e2 = (e1 + 1) % EC_N
    s2 = (r + e2 * k) % EC_N
    # Off-chain key recovery — Schnorr leaks k when r is reused.
    # Compute modular inverse via extended GCD (Ruby's Integer#pow rejects
    # negative bases with a modulus argument, so we can't write pow(-1, n)).
    def mod_inv(a, m)
      a = a % m
      old_r, rr = a, m
      old_s, ss = 1, 0
      while rr != 0
        q = old_r / rr
        old_r, rr = rr, old_r - q * rr
        old_s, ss = ss, old_s - q * ss
      end
      old_s % m
    end
    e_diff = (e1 - e2) % EC_N
    recovered = ((s1 - s2) * mod_inv(e_diff, EC_N)) % EC_N
    expect(recovered).to eq(k)
    # Each proof verifies individually (the on-chain gate cannot detect r reuse).
    c = SchnorrZKP.new(pub_key)
    expect { c.verify(r_point, s1) }.not_to raise_error
  end
end
