"""ECUnit -- Unit-style exercises for the secp256k1 EC built-ins."""

from runar import (
    SmartContract, ByteString, public, assert_, len_,
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_on_curve,
    ec_encode_compressed, ec_make_point, ec_point_x, ec_point_y,
)


class ECUnit(SmartContract):
    """Unit-style exercises for the secp256k1 EC built-ins."""

    pub_key: ByteString

    def __init__(self, pub_key: ByteString):
        super().__init__(pub_key)
        self.pub_key = pub_key

    @public
    def test_ops(self):
        """Exercise ecMulGen, ecOnCurve, ecNegate, ecMul, ecAdd, ecPointX,
        ecPointY, ecMakePoint, and ecEncodeCompressed."""
        g = ec_mul_gen(1)
        assert_(ec_on_curve(g))
        neg = ec_negate(g)
        assert_(ec_on_curve(neg))
        doubled = ec_mul(g, 2)
        assert_(ec_on_curve(doubled))
        sum_ = ec_add(g, g)
        assert_(ec_on_curve(sum_))
        x = ec_point_x(g)
        y = ec_point_y(g)
        rebuilt = ec_make_point(x, y)
        assert_(ec_on_curve(rebuilt))
        compressed = ec_encode_compressed(g)
        assert_(len_(compressed) == 33)
        assert_(True)
