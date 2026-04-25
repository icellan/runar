from runar import SmartContract, ByteString, Bigint, public, assert_, p256_mul, p256_add, p256_mul_gen, p256_on_curve

class P256Primitives(SmartContract):
    expected_point: P256Point

    def __init__(self, expected_point: P256Point):
        super().__init__(expected_point)
        self.expected_point = expected_point

    @public
    def verify(self, k: Bigint, base_point: P256Point):
        result = p256_mul(base_point, k)
        assert_(p256_on_curve(result))
        assert_(result == self.expected_point)

    @public
    def verify_add(self, a: P256Point, b: P256Point):
        result = p256_add(a, b)
        assert_(p256_on_curve(result))
        assert_(result == self.expected_point)

    @public
    def verify_mul_gen(self, k: Bigint):
        result = p256_mul_gen(k)
        assert_(p256_on_curve(result))
        assert_(result == self.expected_point)
