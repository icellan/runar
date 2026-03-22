# frozen_string_literal: true

# Raw secp256k1 arithmetic on integer coordinates.
#
# This module exposes the low-level building blocks used by both the
# OP_PUSH_TX helper (k=1 ECDSA) and the ECDSA signing/verification module.
# Points are represented as two-element Integer arrays [x, y].
# The point at infinity is represented by +nil+.
#
# All methods are pure functions — no state, no side effects.

module Runar
  module ECPrimitives
    # secp256k1 curve parameters.
    SECP256K1_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    SECP256K1_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    module_function

    # rubocop:disable Naming/MethodParameterName

    # Extended Euclidean algorithm.
    #
    # Returns +[gcd, x, y]+ such that +a*x + b*y = gcd+.
    #
    # @param a [Integer]
    # @param b [Integer]
    # @return [Array(Integer, Integer, Integer)]
    def extended_gcd(a, b)
      return [b, 0, 1] if a.zero?

      g, x, y = extended_gcd(b % a, a)
      [g, y - (b / a) * x, x]
    end

    # Modular multiplicative inverse.
    #
    # Returns +x+ such that +a * x ≡ 1 (mod m)+.
    # Handles negative +a+ by reducing modulo +m+ first.
    #
    # @param a [Integer] value to invert
    # @param m [Integer] modulus
    # @return [Integer]
    # @raise [ArgumentError] if the inverse does not exist
    def mod_inv(a, m)
      a %= m if a.negative?
      g, x, = extended_gcd(a, m)
      raise ArgumentError, 'no modular inverse' unless g == 1

      x % m
    end

    # rubocop:enable Naming/MethodParameterName

    # secp256k1 point addition.
    #
    # +nil+ represents the point at infinity (additive identity).
    #
    # @param p1 [Array(Integer, Integer), nil]
    # @param p2 [Array(Integer, Integer), nil]
    # @return [Array(Integer, Integer), nil]
    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Naming/MethodParameterName
    def point_add(p1, p2)
      return p2 if p1.nil?
      return p1 if p2.nil?

      x1, y1 = p1
      x2, y2 = p2

      if x1 == x2
        return nil if y1 != y2 # p1 == -p2 → point at infinity

        lam = 3 * x1 * x1 * mod_inv(2 * y1, SECP256K1_P) % SECP256K1_P
      else
        lam = (y2 - y1) * mod_inv(x2 - x1, SECP256K1_P) % SECP256K1_P
      end

      x3 = (lam * lam - x1 - x2) % SECP256K1_P
      y3 = (lam * (x1 - x3) - y1) % SECP256K1_P
      [x3, y3]
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Naming/MethodParameterName

    # secp256k1 scalar multiplication (double-and-add).
    #
    # Returns +k * point+, or +nil+ (point at infinity) when +k+ is zero.
    #
    # WARNING: This implementation uses a simple double-and-add algorithm that is
    # NOT constant-time. Execution time leaks information about the scalar via
    # branch timing on each bit. This is acceptable for test/verification use
    # (e.g., ECDSA verify, OP_PUSH_TX with k=1) but MUST NOT be used with real
    # private keys in a networked/production context. For production signing,
    # use a constant-time implementation (e.g., Montgomery ladder).
    #
    # @param k     [Integer]                        scalar
    # @param point [Array(Integer, Integer), nil]   base point
    # @return [Array(Integer, Integer), nil]
    # rubocop:disable Naming/MethodParameterName
    def point_mul(k, point)
      result = nil
      addend = point

      while k.positive?
        result = point_add(result, addend) if k.odd?
        addend = point_add(addend, addend)
        k >>= 1
      end

      result
    end
    # rubocop:enable Naming/MethodParameterName
  end
end
