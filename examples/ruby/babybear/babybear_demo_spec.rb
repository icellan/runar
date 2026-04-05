# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BabyBearDemo.runar'

# Baby Bear field: p = 2013265921 = 2^31 - 2^27 + 1
BB_P = 2013265921

RSpec.describe BabyBearDemo do
  describe 'check_add (bb_field_add)' do
    it 'adds two small values' do
      c = BabyBearDemo.new
      expect { c.check_add(5, 7, 12) }.not_to raise_error
    end

    it 'wraps around the field prime' do
      c = BabyBearDemo.new
      expect { c.check_add(BB_P - 1, 1, 0) }.not_to raise_error
    end

    it 'adds zero' do
      c = BabyBearDemo.new
      expect { c.check_add(42, 0, 42) }.not_to raise_error
    end
  end

  describe 'check_sub (bb_field_sub)' do
    it 'subtracts two values' do
      c = BabyBearDemo.new
      expect { c.check_sub(10, 3, 7) }.not_to raise_error
    end

    it 'wraps to field prime when result would be negative' do
      c = BabyBearDemo.new
      # 0 - 1 = p - 1
      expect { c.check_sub(0, 1, BB_P - 1) }.not_to raise_error
    end
  end

  describe 'check_mul (bb_field_mul)' do
    it 'multiplies two values' do
      c = BabyBearDemo.new
      expect { c.check_mul(6, 7, 42) }.not_to raise_error
    end

    it 'multiplies large values with wrap' do
      c = BabyBearDemo.new
      # (p-1) * 2 mod p = p - 2
      expect { c.check_mul(BB_P - 1, 2, BB_P - 2) }.not_to raise_error
    end

    it 'multiplies by zero' do
      c = BabyBearDemo.new
      expect { c.check_mul(12345, 0, 0) }.not_to raise_error
    end
  end

  describe 'check_inv (bb_field_inv)' do
    it 'inverts 1 (should return 1)' do
      c = BabyBearDemo.new
      expect { c.check_inv(1) }.not_to raise_error
    end

    it 'inverts 2' do
      c = BabyBearDemo.new
      expect { c.check_inv(2) }.not_to raise_error
    end

    it 'inverts a large value' do
      c = BabyBearDemo.new
      expect { c.check_inv(1000000007) }.not_to raise_error
    end
  end

  describe 'check_add_sub_roundtrip' do
    it 'verifies add-sub roundtrip' do
      c = BabyBearDemo.new
      expect { c.check_add_sub_roundtrip(42, 99) }.not_to raise_error
    end
  end

  describe 'check_distributive' do
    it 'verifies distributive law' do
      c = BabyBearDemo.new
      expect { c.check_distributive(5, 7, 11) }.not_to raise_error
    end
  end
end
