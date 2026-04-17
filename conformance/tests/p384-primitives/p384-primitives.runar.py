from runar import SmartContract, ByteString, Bigint, public, assert_, p384_mul, p384_add, p384_mul_gen, p384_on_curve

class P384Primitives(SmartContract):
    expected_point: P384Point

    def __init__(self, expected_point: P384Point):
        super().__init__(expected_point)
        self.expected_point = expected_point

    @public
    def verify(self, k: Bigint, base_point: P384Point):
        result = p384_mul(base_point, k)
        assert_(p384_on_curve(result))
        assert_(result == self.expected_point)

    @public
    def verify_add(self, a: P384Point, b: P384Point):
        result = p384_add(a, b)
        assert_(p384_on_curve(result))
        assert_(result == self.expected_point)

    @public
    def verify_mul_gen(self, k: Bigint):
        result = p384_mul_gen(k)
        assert_(p384_on_curve(result))
        assert_(result == self.expected_point)
