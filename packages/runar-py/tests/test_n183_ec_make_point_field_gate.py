"""N-183: ec_make_point applies the compiled script's R-156 field gate.

The script requires 0 <= v < p for each coordinate (OP_WITHIN + OP_VERIFY).
Before the fix Python raised only OverflowError for negative / >= 2^256 values
through int.to_bytes and happily built x = p, x = p + 1, y = p.

Proves: boundary operands (p, p+1, -1, 2^256 on either half) raise ValueError,
and p - 1 / 0 / a real curve point still build.
Does not prove: the script itself (the runar-testing r156 test pins it).
"""
import pytest

from runar.ec import ec_make_point

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GY = 0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE


@pytest.mark.parametrize("why,x,y", [
    ("x = p", P, GY),
    ("x = p + 1", P + 1, GY),
    ("y = p", 1, P),
    ("y = p + 1", 1, P + 1),
    ("x = -1", -1, GY),
    ("y = -1", 1, -1),
    ("x = 2^256", 1 << 256, GY),
    ("y = 2^256 + 1", 1, (1 << 256) + 1),
])
def test_ec_make_point_refuses_non_field_element(why, x, y):
    with pytest.raises(ValueError, match="field element"):
        ec_make_point(x, y)


def test_ec_make_point_accepts_field_elements():
    assert ec_make_point(P - 1, P - 1) == (P - 1).to_bytes(32, "big") * 2
    assert ec_make_point(0, 0) == bytes(64)
    assert ec_make_point(1, GY) == (1).to_bytes(32, "big") + GY.to_bytes(32, "big")
