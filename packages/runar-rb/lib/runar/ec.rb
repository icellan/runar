# frozen_string_literal: true

# Real secp256k1 elliptic curve operations.
#
# Pure Ruby implementation using Integer arithmetic with the secp256k1
# curve parameters. No external dependencies required.
# Points are 64-byte hex strings (x[32] || y[32], big-endian, no prefix byte).

module Runar
  module EC
    # secp256k1 curve parameters
    EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    EC_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    EC_G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    EC_G = format('%064x', EC_G_X) + format('%064x', EC_G_Y)

    class << self
      # -- Internal helpers ----------------------------------------------------

      private

      def decode_point(p)
        raise ArgumentError, "Point must be 128 hex chars (64 bytes), got #{p.length}" unless p.length == 128

        x = p[0, 64].to_i(16)
        y = p[64, 64].to_i(16)
        [x, y]
      end

      def encode_point(x, y)
        format('%064x', x) + format('%064x', y)
      end

      def extended_gcd(a, b)
        return [b, 0, 1] if a == 0

        g, x, y = extended_gcd(b % a, a)
        [g, y - (b / a) * x, x]
      end

      def modinv(a, m)
        a = a % m if a < 0
        g, x, = extended_gcd(a, m)
        raise ArgumentError, 'Modular inverse does not exist' unless g == 1

        x % m
      end

      def point_add(x1, y1, x2, y2)
        return [x2, y2] if x1 == 0 && y1 == 0
        return [x1, y1] if x2 == 0 && y2 == 0

        if x1 == x2
          return [0, 0] if y1 != y2

          # Point doubling
          lam = (3 * x1 * x1 * modinv(2 * y1, EC_P)) % EC_P
        else
          lam = ((y2 - y1) * modinv(x2 - x1, EC_P)) % EC_P
        end

        x3 = (lam * lam - x1 - x2) % EC_P
        y3 = (lam * (x1 - x3) - y1) % EC_P
        [x3, y3]
      end

      def point_mul(x, y, k)
        k = k % EC_N
        return [0, 0] if k == 0

        rx = 0
        ry = 0
        qx = x
        qy = y

        while k > 0
          rx, ry = point_add(rx, ry, qx, qy) if (k & 1) == 1
          qx, qy = point_add(qx, qy, qx, qy)
          k >>= 1
        end

        [rx, ry]
      end

      public

      # -- Public API ----------------------------------------------------------

      # Extract x-coordinate from Point as integer.
      def ec_point_x(p)
        x, = decode_point(p)
        x
      end

      # Extract y-coordinate from Point as integer.
      def ec_point_y(p)
        _, y = decode_point(p)
        y
      end

      # Check if point is on the secp256k1 curve.
      def ec_on_curve(p)
        x, y = decode_point(p)
        return true if x == 0 && y == 0 # Point at infinity

        lhs = (y * y) % EC_P
        rhs = (x * x * x + 7) % EC_P
        lhs == rhs
      end

      # Negate a point (reflect over x-axis).
      def ec_negate(p)
        x, y = decode_point(p)
        encode_point(x, (EC_P - y) % EC_P)
      end

      # Modular reduction.
      def ec_mod_reduce(value, m)
        value % m
      end

      # Add two points.
      def ec_add(a, b)
        x1, y1 = decode_point(a)
        x2, y2 = decode_point(b)
        rx, ry = point_add(x1, y1, x2, y2)
        encode_point(rx, ry)
      end

      # Scalar multiplication.
      def ec_mul(p, k)
        x, y = decode_point(p)
        rx, ry = point_mul(x, y, k)
        encode_point(rx, ry)
      end

      # Scalar multiplication with generator point.
      def ec_mul_gen(k)
        rx, ry = point_mul(EC_G_X, EC_G_Y, k)
        encode_point(rx, ry)
      end

      # Create a Point from x, y integer coordinates.
      def ec_make_point(x, y)
        encode_point(x, y)
      end

      # Encode point in compressed format (33 bytes = 66 hex chars).
      def ec_encode_compressed(p)
        x, y = decode_point(p)
        prefix = y.even? ? '02' : '03'
        prefix + format('%064x', x)
      end
    end
  end
end
