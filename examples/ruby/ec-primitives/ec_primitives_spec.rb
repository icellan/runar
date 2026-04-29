# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'ECPrimitives.runar'

RSpec.describe ECPrimitives do
  let(:k)    { 7 }
  let(:pt)   { ec_mul_gen(k) }
  let(:pt_x) { ec_point_x(pt) }
  let(:pt_y) { ec_point_y(pt) }

  let(:k2)  { 13 }
  let(:pt2) { ec_mul_gen(k2) }

  it 'extracts x' do
    c = ECPrimitives.new(pt)
    expect { c.check_x(pt_x) }.not_to raise_error
  end

  it 'extracts y' do
    c = ECPrimitives.new(pt)
    expect { c.check_y(pt_y) }.not_to raise_error
  end

  it 'verifies on-curve membership' do
    c = ECPrimitives.new(pt)
    expect { c.check_on_curve }.not_to raise_error
  end

  it 'verifies negate on y' do
    expected_neg_y = (EC_P - pt_y) % EC_P
    c = ECPrimitives.new(pt)
    expect { c.check_negate_y(expected_neg_y) }.not_to raise_error
  end

  it 'reduces values modulo a modulus' do
    c = ECPrimitives.new(pt)
    expect { c.check_mod_reduce(17, 5, 2) }.not_to raise_error
  end

  it 'adds two points' do
    s = ec_add(pt, pt2)
    c = ECPrimitives.new(pt)
    expect { c.check_add(pt2, ec_point_x(s), ec_point_y(s)) }.not_to raise_error
  end

  it 'multiplies a point by a scalar' do
    r = ec_mul(pt, 11)
    c = ECPrimitives.new(pt)
    expect { c.check_mul(11, ec_point_x(r), ec_point_y(r)) }.not_to raise_error
  end

  it 'multiplies the generator' do
    r = ec_mul_gen(99)
    c = ECPrimitives.new(pt)
    expect { c.check_mul_gen(99, ec_point_x(r), ec_point_y(r)) }.not_to raise_error
  end

  it 'rebuilds a point from coordinates' do
    c = ECPrimitives.new(pt)
    expect { c.check_make_point(pt_x, pt_y, pt_x, pt_y) }.not_to raise_error
  end

  it 'compresses the stored point' do
    expected = ec_encode_compressed(pt)
    c = ECPrimitives.new(pt)
    expect { c.check_encode_compressed(expected) }.not_to raise_error
  end

  it 'verifies multiplication identity' do
    c = ECPrimitives.new(pt)
    expect { c.check_mul_identity }.not_to raise_error
  end

  it 'verifies double-negate roundtrip' do
    c = ECPrimitives.new(pt)
    expect { c.check_negate_roundtrip }.not_to raise_error
  end

  it 'verifies that the sum lies on the curve' do
    c = ECPrimitives.new(pt)
    expect { c.check_add_on_curve(pt2) }.not_to raise_error
  end

  it 'verifies that any scalar multiple of G lies on the curve' do
    c = ECPrimitives.new(pt)
    expect { c.check_mul_gen_on_curve(12_345) }.not_to raise_error
  end

  it 'fails when the wrong x coordinate is supplied' do
    c = ECPrimitives.new(pt)
    expect { c.check_x(pt_x + 1) }.to raise_error(RuntimeError)
  end
end
