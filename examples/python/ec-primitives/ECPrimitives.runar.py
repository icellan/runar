from runar import (
    SmartContract, Point, Bigint, ByteString, public, assert_,
    ec_point_x, ec_point_y, ec_on_curve, ec_negate, ec_mod_reduce,
    ec_add, ec_mul, ec_mul_gen, ec_make_point, ec_encode_compressed,
)

class ECPrimitives(SmartContract):
    pt: Point

    def __init__(self, pt: Point):
        super().__init__(pt)
        self.pt = pt

    @public
    def check_x(self, expected_x: Bigint):
        assert_(ec_point_x(self.pt) == expected_x)

    @public
    def check_y(self, expected_y: Bigint):
        assert_(ec_point_y(self.pt) == expected_y)

    @public
    def check_on_curve(self):
        assert_(ec_on_curve(self.pt))

    @public
    def check_negate_y(self, expected_neg_y: Bigint):
        negated = ec_negate(self.pt)
        assert_(ec_point_y(negated) == expected_neg_y)

    @public
    def check_mod_reduce(self, value: Bigint, modulus: Bigint, expected: Bigint):
        assert_(ec_mod_reduce(value, modulus) == expected)

    @public
    def check_add(self, other: Point, expected_x: Bigint, expected_y: Bigint):
        result = ec_add(self.pt, other)
        assert_(ec_point_x(result) == expected_x)
        assert_(ec_point_y(result) == expected_y)

    @public
    def check_mul(self, scalar: Bigint, expected_x: Bigint, expected_y: Bigint):
        result = ec_mul(self.pt, scalar)
        assert_(ec_point_x(result) == expected_x)
        assert_(ec_point_y(result) == expected_y)

    @public
    def check_mul_gen(self, scalar: Bigint, expected_x: Bigint, expected_y: Bigint):
        result = ec_mul_gen(scalar)
        assert_(ec_point_x(result) == expected_x)
        assert_(ec_point_y(result) == expected_y)

    @public
    def check_make_point(self, x: Bigint, y: Bigint, expected_x: Bigint, expected_y: Bigint):
        pt = ec_make_point(x, y)
        assert_(ec_point_x(pt) == expected_x)
        assert_(ec_point_y(pt) == expected_y)

    @public
    def check_encode_compressed(self, expected: ByteString):
        compressed = ec_encode_compressed(self.pt)
        assert_(compressed == expected)

    @public
    def check_mul_identity(self):
        result = ec_mul(self.pt, 1)
        assert_(ec_point_x(result) == ec_point_x(self.pt))
        assert_(ec_point_y(result) == ec_point_y(self.pt))

    @public
    def check_negate_roundtrip(self):
        neg1 = ec_negate(self.pt)
        neg2 = ec_negate(neg1)
        assert_(ec_point_x(neg2) == ec_point_x(self.pt))
        assert_(ec_point_y(neg2) == ec_point_y(self.pt))

    @public
    def check_add_on_curve(self, other: Point):
        result = ec_add(self.pt, other)
        assert_(ec_on_curve(result))

    @public
    def check_mul_gen_on_curve(self, scalar: Bigint):
        result = ec_mul_gen(scalar)
        assert_(ec_on_curve(result))
