# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Runar::EC do
  describe 'constants' do
    it 'EC_G is a 128-char hex string (64 bytes)' do
      expect(Runar::EC::EC_G.length).to eq(128)
    end

    it 'EC_G matches the known secp256k1 generator point' do
      gx = Runar::EC::EC_G[0, 64].to_i(16)
      gy = Runar::EC::EC_G[64, 64].to_i(16)
      expect(gx).to eq(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
      expect(gy).to eq(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    end

    it 'top-level EC_G constant matches' do
      expect(::EC_G).to eq(Runar::EC::EC_G)
    end
  end

  describe 'ec_make_point / ec_point_x / ec_point_y round-trip' do
    it 'round-trips coordinates through make and extract' do
      x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
      y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

      p = ec_make_point(x, y)
      expect(ec_point_x(p)).to eq(x)
      expect(ec_point_y(p)).to eq(y)
    end
  end

  describe 'ec_on_curve' do
    it 'validates the generator point is on the curve' do
      expect(ec_on_curve(EC_G)).to be true
    end

    it 'rejects a point that is not on the curve' do
      bad_point = ec_make_point(1, 2)
      expect(ec_on_curve(bad_point)).to be false
    end
  end

  describe 'ec_negate' do
    it 'produces a valid point on the curve' do
      neg = ec_negate(EC_G)
      expect(ec_on_curve(neg)).to be true
    end

    it 'preserves the x-coordinate' do
      neg = ec_negate(EC_G)
      expect(ec_point_x(neg)).to eq(ec_point_x(EC_G))
    end

    it 'negates the y-coordinate modulo p' do
      neg = ec_negate(EC_G)
      y_sum = (ec_point_y(EC_G) + ec_point_y(neg)) % EC_P
      expect(y_sum).to eq(0)
    end
  end

  describe 'ec_add' do
    it 'adding a point to its negation yields the point at infinity' do
      neg = ec_negate(EC_G)
      result = ec_add(EC_G, neg)
      # Point at infinity is (0, 0)
      expect(ec_point_x(result)).to eq(0)
      expect(ec_point_y(result)).to eq(0)
    end

    it 'adding G + G produces a point on the curve' do
      result = ec_add(EC_G, EC_G)
      expect(ec_on_curve(result)).to be true
    end
  end

  describe 'ec_mul_gen' do
    it 'ec_mul_gen(1) equals EC_G' do
      expect(ec_mul_gen(1)).to eq(EC_G)
    end

    it 'ec_mul_gen(2) equals ec_add(G, G)' do
      two_g = ec_mul_gen(2)
      g_plus_g = ec_add(EC_G, EC_G)
      expect(two_g).to eq(g_plus_g)
    end

    it 'ec_mul_gen(2) is on the curve' do
      expect(ec_on_curve(ec_mul_gen(2))).to be true
    end
  end

  describe 'ec_mul' do
    it 'ec_mul(G, 1) equals EC_G' do
      expect(ec_mul(EC_G, 1)).to eq(EC_G)
    end

    it 'ec_mul(G, 2) equals ec_mul_gen(2)' do
      expect(ec_mul(EC_G, 2)).to eq(ec_mul_gen(2))
    end
  end

  describe 'ec_encode_compressed' do
    it 'produces a 66-char hex string (33 bytes)' do
      result = ec_encode_compressed(EC_G)
      expect(result.length).to eq(66)
    end

    it 'starts with 02 or 03' do
      result = ec_encode_compressed(EC_G)
      expect(%w[02 03]).to include(result[0, 2])
    end

    it 'contains the x-coordinate' do
      result = ec_encode_compressed(EC_G)
      x_hex = result[2, 64]
      expect(x_hex.to_i(16)).to eq(ec_point_x(EC_G))
    end
  end

  describe 'ec_mod_reduce' do
    it 'reduces a value modulo a modulus' do
      expect(ec_mod_reduce(10, 3)).to eq(1)
      expect(ec_mod_reduce(EC_P + 1, EC_P)).to eq(1)
    end
  end
end
