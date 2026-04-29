# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'ECDemo.runar'

# ECDemo tests exercise every EC primitive using real secp256k1 math.
#
# We use k=7 (a small scalar) as the test point so computations are fast
# but the point is a genuine curve point. A second point (k=13) is used
# for addition tests.
RSpec.describe ECDemo do
  # Build test points from small scalars so values are deterministic.
  let(:k)    { 7 }
  let(:pt)   { ec_mul_gen(k) }
  let(:pt_x) { ec_point_x(pt) }
  let(:pt_y) { ec_point_y(pt) }

  let(:k2)    { 13 }
  let(:pt2)   { ec_mul_gen(k2) }
  let(:pt2_x) { ec_point_x(pt2) }
  let(:pt2_y) { ec_point_y(pt2) }

  # -----------------------------------------------------------------
  # Coordinate extraction and construction
  # -----------------------------------------------------------------

  describe 'check_x (ec_point_x)' do
    it 'extracts the x-coordinate from the stored point' do
      c = ECDemo.new(pt)
      expect { c.check_x(pt_x) }.not_to raise_error
    end

    it 'fails with wrong x-coordinate' do
      c = ECDemo.new(pt)
      expect { c.check_x(pt_x + 1) }.to raise_error(RuntimeError)
    end
  end

  describe 'check_y (ec_point_y)' do
    it 'extracts the y-coordinate from the stored point' do
      c = ECDemo.new(pt)
      expect { c.check_y(pt_y) }.not_to raise_error
    end
  end

  describe 'check_make_point (ec_make_point)' do
    it 'constructs a point from coordinates and verifies them' do
      c = ECDemo.new(pt)
      expect { c.check_make_point(pt_x, pt_y, pt_x, pt_y) }.not_to raise_error
    end

    it 'constructs a different point from different coordinates' do
      c = ECDemo.new(pt)
      expect { c.check_make_point(pt2_x, pt2_y, pt2_x, pt2_y) }.not_to raise_error
    end
  end

  # -----------------------------------------------------------------
  # Curve membership
  # -----------------------------------------------------------------

  describe 'check_on_curve (ec_on_curve)' do
    it 'accepts a valid curve point' do
      c = ECDemo.new(pt)
      expect { c.check_on_curve }.not_to raise_error
    end

    it 'accepts the generator point G itself' do
      g = ec_mul_gen(1)
      c = ECDemo.new(g)
      expect { c.check_on_curve }.not_to raise_error
    end
  end

  # -----------------------------------------------------------------
  # Point arithmetic
  # -----------------------------------------------------------------

  describe 'check_add (ec_add)' do
    it 'adds two curve points and verifies the result' do
      expected   = ec_add(pt, pt2)
      expected_x = ec_point_x(expected)
      expected_y = ec_point_y(expected)

      c = ECDemo.new(pt)
      expect { c.check_add(pt2, expected_x, expected_y) }.not_to raise_error
    end
  end

  describe 'check_mul (ec_mul)' do
    it 'multiplies a point by a scalar and verifies the result' do
      scalar     = 42
      expected   = ec_mul(pt, scalar)
      expected_x = ec_point_x(expected)
      expected_y = ec_point_y(expected)

      c = ECDemo.new(pt)
      expect { c.check_mul(scalar, expected_x, expected_y) }.not_to raise_error
    end
  end

  describe 'check_mul_gen (ec_mul_gen)' do
    it 'multiplies the generator by a scalar and verifies the result' do
      scalar     = 99
      expected   = ec_mul_gen(scalar)
      expected_x = ec_point_x(expected)
      expected_y = ec_point_y(expected)

      c = ECDemo.new(pt)
      expect { c.check_mul_gen(scalar, expected_x, expected_y) }.not_to raise_error
    end

    it 'ec_mul_gen(k) equals ec_mul(G, k)' do
      scalar   = 55
      from_gen = ec_mul_gen(scalar)
      g        = ec_mul_gen(1)
      from_mul = ec_mul(g, scalar)
      expect(from_gen).to eq(from_mul)
    end
  end

  # -----------------------------------------------------------------
  # Point negation
  # -----------------------------------------------------------------

  describe 'check_negate (ec_negate)' do
    it 'negates the stored point and verifies the y-coordinate' do
      neg       = ec_negate(pt)
      expected_y = ec_point_y(neg)

      c = ECDemo.new(pt)
      expect { c.check_negate(expected_y) }.not_to raise_error
    end

    it 'negated y equals EC_P - original y' do
      neg   = ec_negate(pt)
      neg_y = ec_point_y(neg)
      expect(neg_y).to eq((EC_P - pt_y) % EC_P)
    end
  end

  describe 'check_negate_roundtrip' do
    it 'double negation returns the original point' do
      c = ECDemo.new(pt)
      expect { c.check_negate_roundtrip }.not_to raise_error
    end
  end

  # -----------------------------------------------------------------
  # Modular arithmetic
  # -----------------------------------------------------------------

  describe 'check_mod_reduce (ec_mod_reduce)' do
    it 'reduces a positive value' do
      c = ECDemo.new(pt)
      expect { c.check_mod_reduce(17, 5, 2) }.not_to raise_error
    end

    it 'reduces a negative value to a non-negative result' do
      c = ECDemo.new(pt)
      expect { c.check_mod_reduce(-3, 5, 2) }.not_to raise_error
    end

    it 'reduces a value larger than EC_N using the curve order' do
      large = EC_N + 42
      c = ECDemo.new(pt)
      expect { c.check_mod_reduce(large, EC_N, 42) }.not_to raise_error
    end
  end

  # -----------------------------------------------------------------
  # Compressed encoding
  # -----------------------------------------------------------------

  describe 'check_encode_compressed (ec_encode_compressed)' do
    it 'compresses the stored point to 33-byte public key format' do
      expected = ec_encode_compressed(pt)
      c = ECDemo.new(pt)
      expect { c.check_encode_compressed(expected) }.not_to raise_error
    end

    it 'compressed encoding starts with 02 (even y) or 03 (odd y) prefix byte' do
      # ec_encode_compressed returns a hex string (66 chars = 33 bytes encoded).
      compressed = ec_encode_compressed(pt)
      expect(%w[02 03]).to include(compressed[0, 2])
      expect(compressed.length).to eq(66)
    end
  end

  # -----------------------------------------------------------------
  # Algebraic properties
  # -----------------------------------------------------------------

  describe 'check_mul_identity' do
    it '1 * P equals P' do
      c = ECDemo.new(pt)
      expect { c.check_mul_identity }.not_to raise_error
    end
  end

  describe 'check_add_on_curve' do
    it 'sum of two valid points lies on the curve' do
      c = ECDemo.new(pt)
      expect { c.check_add_on_curve(pt2) }.not_to raise_error
    end
  end

  describe 'check_mul_gen_on_curve' do
    it 'any scalar multiple of G lies on the curve' do
      c = ECDemo.new(pt)
      expect { c.check_mul_gen_on_curve(12_345) }.not_to raise_error
    end

    it 'large scalar multiples of G also lie on the curve' do
      c = ECDemo.new(pt)
      expect { c.check_mul_gen_on_curve(EC_N - 1) }.not_to raise_error
    end
  end
end
