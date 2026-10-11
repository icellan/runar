"""N-111: the Python native EC builtins (``runar.ec``, what a .runar.py
contract calls under pytest) must apply the compiled script's operand gates --
ec_add / ec_negate: 64 bytes and x, y < p (R-117); ec_mul: on-curve or the
all-zero identity O (R-157); ec_point_x / ec_point_y / ec_encode_compressed:
width only -- and its addition law (inv(0) = 0, so an (x, 0) doubling is a
value, not an error).

Oracle: ``packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json``,
every row executed on @bsv/sdk Spend.validate by
``packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts``.

What this proves: for every row, each builtin returns the on-chain value, or
raises where the script aborts (never a value).
What it does not prove: inputs outside the file, or the script itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar.ec import (
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_point_x, ec_point_y,
    ec_encode_compressed,
)


def _vectors_path() -> Path:
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = (ancestor / 'packages' / 'runar-zig' / 'src' / 'fixtures'
                     / 'n111-ec-operand-gates-onchain.json')
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f'could not locate n111-ec-operand-gates-onchain.json walking up from {here}')


ROWS = json.loads(_vectors_path().read_text())['cases']


def _run(row):
    p = bytes.fromhex(row['p']) if 'p' in row else None
    q = bytes.fromhex(row['q']) if 'q' in row else None
    k = int(row['k']) if 'k' in row else None
    fn = row['fn']
    if fn == 'ecAdd':
        return ec_add(p, q).hex()
    if fn == 'ecMul':
        return ec_mul(p, k).hex()
    if fn == 'ecMulGen':
        return ec_mul_gen(k).hex()
    if fn == 'ecNegate':
        return ec_negate(p).hex()
    if fn == 'ecPointX':
        return str(ec_point_x(p))
    if fn == 'ecPointY':
        return str(ec_point_y(p))
    if fn == 'ecEncodeCompressed':
        return ec_encode_compressed(p).hex()
    raise AssertionError(f'unknown fn {fn}')


@pytest.mark.parametrize('row', ROWS, ids=[f"{r['fn']}-{i}" for i, r in enumerate(ROWS)])
def test_n111_ec_builtin_matches_onchain_operand_gates(row):
    if row['expect'] == 'abort':
        with pytest.raises(Exception):
            _run(row)
        return
    assert _run(row) == row['expect'], row['why']
