# frozen_string_literal: true

# Fixed-base comb: compile-time table, and the soundness check that decides
# where the cheap incomplete addition may be used.
#
# Port of packages/runar-compiler/src/passes/comb.ts. The binary ladders in
# ec.rb / p256_p384.rb use the cheap mixed add at every step but the last,
# justified by an interval argument over c_i mod n. That comment is emphatic
# that the argument must be RE-DERIVED, not assumed, by anything which changes
# the offset, the iteration count, or the reduce -- and a comb changes all
# three. comb_safe_rounds below is that re-derivation, written as executable
# interval arithmetic rather than prose, so a round only gets the cheap add when
# the exception is proved unreachable. Rounds it cannot prove fall back to the
# complete add-or-double form.
#
# Nothing here emits Script. It is pure integer arithmetic, run once per
# compilation, and unit-tested against published curve vectors.

module RunarCompiler
  module Codegen
    module Comb
      # An affine point. nil is the point at infinity.
      Point = Struct.new(:x, :y)

      # A short-Weierstrass curve, for the compile-time table.
      #
      # p: field prime. a: curve coefficient (-3 on the NIST curves, 0 on
      # secp256k1). b: curve coefficient. n: group order. g: base point.
      Curve = Struct.new(:p, :a, :b, :n, :g)

      # Comb geometry for one window width, chosen so the top digit is never
      # zero.
      #
      # The binary ladder hardcodes k + 3n, which puts the scalar's top bit at a
      # fixed position and so keeps the accumulator off the point at infinity. A
      # comb needs the same guarantee, but its first round reads bit w*d - 1, so
      # the offset has to be chosen against w*d rather than assumed.
      # offset_multiple is the smallest m for which every k + m*n has bit
      # w*d - 1 set:
      #
      #   m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
      #
      # m*n == 0 (mod n) so the result is unchanged. For P-256 at w=3 the search
      # returns m=3, d=86 -- i.e. exactly the +3n the binary ladder already
      # uses. For P-384 at w=3 it returns m=5, d=129; assuming +3n there would
      # have left the top digit free to be zero.
      #
      # d is the round count and the block width: digit i reads bits
      # i, i+d, ..., i+(w-1)d. lo/hi are the inclusive scalar domain after the
      # offset.
      Params = Struct.new(:w, :d, :offset_multiple, :lo, :hi)

      P256_COMB_CURVE = Curve.new(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        Point.new(
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        )
      ).freeze

      P384_COMB_CURVE = Curve.new(
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        -3,
        0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        Point.new(
          0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
          0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
        )
      ).freeze

      # secp256k1. NOT built from the NIST template: it is y^2 = x^3 + 7, so
      # a = 0. Getting `a` wrong here does not produce an obviously broken table
      # -- it produces a table of points on a DIFFERENT curve, which that other
      # curve's on-curve check would happily accept. Hence the published 2G
      # vectors pinned in the tests.
      SECP256K1_COMB_CURVE = Curve.new(
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        0,
        7,
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        Point.new(
          0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        )
      ).freeze

      # Geometry for window width w, or nil if no offset in the search range
      # puts a guaranteed set bit at the top of the first digit. Returning nil
      # rather than guessing keeps the caller from silently combing a scalar
      # whose leading digit can vanish.
      #
      # @param w [Integer]
      # @param c [Curve]
      # @return [Params, nil]
      def self.comb_geometry(w, c)
        base = (c.n.bit_length + w - 1) / w
        (base..base + 2).each do |d|
          bits = w * d
          top = 1 << (bits - 1)
          cap = 1 << bits
          (1..16).each do |m|
            lo = m * c.n
            hi = (m + 1) * c.n - 1
            return Params.new(w, d, m, lo, hi) if lo >= top && hi < cap
          end
        end
        nil
      end

      # ---------------------------------------------------------------
      # Affine arithmetic (compile time only)
      # ---------------------------------------------------------------

      # Modular inverse by extended Euclid.
      #
      # Ruby's Integer#pow rejects a negative exponent, so there is no
      # `x.pow(-1, m)` shortcut here as there is in Python.
      #
      # @param v [Integer]
      # @param m [Integer]
      # @return [Integer]
      def self.mod_inverse(v, m)
        old_r = v % m
        r = m
        old_s = 1
        s = 0
        while r != 0
          q = old_r / r
          old_r, r = r, old_r - q * r
          old_s, s = s, old_s - q * s
        end
        old_s % m
      end
      private_class_method :mod_inverse

      # Affine addition. nil is the point at infinity.
      #
      # @param p [Point, nil]
      # @param q [Point, nil]
      # @param c [Curve]
      # @return [Point, nil]
      def self.comb_affine_add(p, q, c)
        return q if p.nil?
        return p if q.nil?

        if p.x == q.x
          return nil if (p.y + q.y) % c.p == 0 # P == -Q

          # Tangent.
          num = (3 * p.x * p.x + c.a) % c.p
          lam = (num * mod_inverse((2 * p.y) % c.p, c.p)) % c.p
          x = (lam * lam - 2 * p.x) % c.p
          return Point.new(x, (lam * (p.x - x) - p.y) % c.p)
        end

        lam = (((q.y - p.y) % c.p) * mod_inverse((q.x - p.x) % c.p, c.p)) % c.p
        x = (lam * lam - p.x - q.x) % c.p
        Point.new(x, (lam * (p.x - x) - p.y) % c.p)
      end

      # Compile-time double-and-add. nil is the point at infinity.
      #
      # @param k [Integer]
      # @param p [Point]
      # @param c [Curve]
      # @return [Point, nil]
      def self.comb_scalar_mul(k, p, c)
        r = nil
        base = p
        e = k % c.n
        while e > 0
          r = comb_affine_add(r, base, c) if e.odd?
          base = comb_affine_add(base, base, c)
          e >>= 1
        end
        r
      end

      # ---------------------------------------------------------------
      # Comb table
      # ---------------------------------------------------------------

      # The multiple of G that table entry j represents.
      #
      # Comb round i consumes bits {i, i+d, i+2d, ...} of the scalar -- one from
      # each block -- so entry j stands for the sum of 2^(t*d) over the set bits
      # t of j.
      #
      # @param j [Integer]
      # @param d [Integer]
      # @return [Integer]
      def self.comb_value(j, d)
        v = 0
        t = 0
        while (j >> t) != 0
          v += 1 << (t * d) if ((j >> t) & 1) == 1
          t += 1
        end
        v
      end

      # T[j] = comb_value(j)*G. Index 0 is infinity and is never added.
      #
      # @return [Array<Point, nil>]
      def self.comb_table(w, d, c)
        (0...(1 << w)).map { |j| j.zero? ? nil : comb_scalar_mul(comb_value(j, d), c.g, c) }
      end

      # ---------------------------------------------------------------
      # Soundness: where may the cheap incomplete addition be used?
      # ---------------------------------------------------------------

      # Bounds on the comb accumulator's multiplier before round i's doubling.
      #
      # After processing rounds d-1 .. i, the accumulator is c_i*G with
      #
      #   c_i = sum_m 2^(m*d) * floor(K_m / 2^i)
      #
      # where K_m is the m-th d-bit block of the expanded scalar. Each floor
      # discards less than one unit of its block, so
      #
      #   k/2^i - sum_m 2^(m*d)  <  c_i  <=  k/2^i
      #
      # and with k confined to [lo, hi] that gives a contiguous interval. The
      # slack term is bounded by 2^(w*d)/(2^d - 1), far below n, which is why the
      # interval stays narrower than the group order for all but the last few
      # rounds -- exactly the property the binary ladder's argument relies on.
      def self.accumulator_interval(i, params)
        slack = (0...params.w).sum { |m| 1 << (m * params.d) }
        hi = params.hi >> i
        lo = (params.lo >> i) - slack
        [lo.negative? ? 0 : lo, hi]
      end
      private_class_method :accumulator_interval

      # Does [lo, hi] contain an integer congruent to target modulo n?
      def self.interval_hits_residue(lo, hi, target, n)
        return false if hi < lo
        return true if hi - lo + 1 >= n # wraps a full residue class

        t = target % n
        # Smallest value >= lo that is congruent to t (mod n).
        first = lo + ((t - lo) % n)
        first <= hi
      end
      private_class_method :interval_hits_residue

      # Per-round verdict: may round i use the cheap incomplete mixed add?
      #
      # The exception the cheap formula cannot represent is a pre-add
      # accumulator equal to the addend, its negation, or the point at infinity.
      # After round i's doubling the accumulator is 2*c_{i+1}*G, and the addend
      # is comb_value(j)*G for whichever digit j the scalar selects -- so the
      # round is safe exactly when, for every j,
      #
      #   2*c_{i+1} != 0, +comb_value(j), -comb_value(j)   (mod n)
      #
      # over the whole interval of c_{i+1}. Both G and every table entry are
      # compile-time constants and the curves have cofactor 1, so ord(G) = n and
      # this is decidable here. Anything the checker cannot prove gets the
      # complete add-or-double form instead; true is never assumed.
      #
      # Index d-1 is false by construction: that round initialises the
      # accumulator from the table and performs no addition at all.
      #
      # @return [Array<Boolean>]
      def self.comb_safe_rounds(params, c)
        values = (1...(1 << params.w)).map { |j| comb_value(j, params.d) }

        safe = Array.new(params.d, false)
        (0...params.d).each do |i|
          next if i == params.d - 1

          lo, hi = accumulator_interval(i + 1, params)
          d_lo = 2 * lo
          d_hi = 2 * hi
          ok = !interval_hits_residue(d_lo, d_hi, 0, c.n)
          values.each do |v|
            break unless ok

            ok = !interval_hits_residue(d_lo, d_hi, v, c.n) &&
                 !interval_hits_residue(d_lo, d_hi, -v, c.n)
          end
          safe[i] = ok
        end
        safe
      end
    end
  end
end
