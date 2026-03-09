"""
EC isolation integration tests -- inline contracts testing individual EC functions.

Each test compiles a minimal stateless contract that exercises a single EC
built-in, deploys it on regtest, and spends via contract.call().

NOTE: These tests compile inline source via compile_from_source, which
requires writing a temporary file since the Python compiler reads from disk.
"""

import json
import os
import tempfile

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
    ec_mul_gen, encode_point, EC_N, EC_P,
)
from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RunarContract, DeployOptions


def _compile_source(source: str, file_name: str) -> RunarArtifact:
    """Compile inline source to an SDK artifact by writing a temp file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file_name, delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(source)
        tmp_path = f.name
    try:
        compiler_artifact = compile_from_source(tmp_path)
        artifact_dict = json.loads(artifact_to_json(compiler_artifact))
        return RunarArtifact.from_dict(artifact_dict)
    finally:
        os.unlink(tmp_path)


class TestEcIsolation:

    def test_ec_on_curve(self):
        """ecOnCurve: compile and deploy a contract checking point validity."""
        source = """\
import { SmartContract, assert, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcOnCurveTest extends SmartContract {
  readonly p: Point;

  constructor(p: Point) {
    super(p);
    this.p = p;
  }

  public verify() {
    assert(ecOnCurve(this.p));
  }
}
"""
        artifact = _compile_source(source, "EcOnCurveTest.runar.ts")
        assert artifact.contract_name == "EcOnCurveTest"

        gx, gy = ec_mul_gen(42)
        point_hex = encode_point(gx, gy)

        contract = RunarContract(artifact, [point_hex])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [], provider, wallet["signer"])
        assert call_txid

    def test_ec_mul_gen(self):
        """ecMulGen: compile and deploy a scalar-multiply-generator contract."""
        source = """\
import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expected: Point;

  constructor(expected: Point) {
    super(expected);
    this.expected = expected;
  }

  public verify(k: bigint) {
    const result = ecMulGen(k);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
"""
        artifact = _compile_source(source, "EcMulGenTest.runar.ts")
        assert artifact.contract_name == "EcMulGenTest"

        k = 7
        ex, ey = ec_mul_gen(k)
        expected_hex = encode_point(ex, ey)

        contract = RunarContract(artifact, [expected_hex])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [k], provider, wallet["signer"])
        assert call_txid

    def test_ec_add(self):
        """ecAdd: compile and deploy a point addition contract."""
        source = """\
import { SmartContract, assert, ecAdd, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcAddTest extends SmartContract {
  readonly a: Point;
  readonly b: Point;
  readonly expected: Point;

  constructor(a: Point, b: Point, expected: Point) {
    super(a, b, expected);
    this.a = a;
    this.b = b;
    this.expected = expected;
  }

  public verify() {
    const result = ecAdd(this.a, this.b);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
"""
        artifact = _compile_source(source, "EcAddTest.runar.ts")
        assert artifact.contract_name == "EcAddTest"

        ax, ay = ec_mul_gen(3)
        bx, by = ec_mul_gen(5)
        # 3G + 5G = 8G
        ex, ey = ec_mul_gen(8)

        contract = RunarContract(artifact, [
            encode_point(ax, ay),
            encode_point(bx, by),
            encode_point(ex, ey),
        ])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [], provider, wallet["signer"])
        assert call_txid

    def test_ec_negate(self):
        """ecNegate: compile, deploy, and spend a point negation contract."""
        source = """\
import { SmartContract, assert, ecNegate, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcNegateTest extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public check(expectedNegY: bigint) {
    assert(ecPointY(ecNegate(this.pt)) === expectedNegY);
  }
}
"""
        artifact = _compile_source(source, "EcNegateTest.runar.ts")
        assert artifact.contract_name == "EcNegateTest"

        px, py = ec_mul_gen(10)
        contract = RunarContract(artifact, [encode_point(px, py)])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        neg_y = EC_P - py
        call_txid, _ = contract.call("check", [neg_y], provider, wallet["signer"])
        assert call_txid

    def test_ec_point_x(self):
        """ecPointX: extract the X coordinate of a point."""
        source = """\
import { SmartContract, assert, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcPointXTest extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expectedX: bigint) { assert(ecPointX(this.pt) === expectedX); }
}
"""
        artifact = _compile_source(source, "EcPointXTest.runar.ts")

        # Use generator point
        gx, gy = ec_mul_gen(1)
        point_hex = encode_point(gx, gy)

        contract = RunarContract(artifact, [point_hex])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        # Pass Gx as expected value
        call_txid, _ = contract.call("check", [gx], provider, wallet["signer"])
        assert call_txid

    def test_ec_on_curve_then_point_x(self):
        """ecOnCurve + ecPointX: verify point and extract X."""
        source = """\
import { SmartContract, assert, ecOnCurve, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcOnCurveTwice extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expectedX: bigint) {
    assert(ecOnCurve(this.pt));
    assert(ecPointX(this.pt) === expectedX);
  }
}
"""
        artifact = _compile_source(source, "EcOnCurveTwice.runar.ts")

        gx, gy = ec_mul_gen(1)
        point_hex = encode_point(gx, gy)

        contract = RunarContract(artifact, [point_hex])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        call_txid, _ = contract.call("check", [gx], provider, wallet["signer"])
        assert call_txid

    def test_ec_convergence_pattern(self):
        """Full EC convergence proof pattern."""
        source = """\
import { SmartContract, assert, ecOnCurve, ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class ConvergencePattern extends SmartContract {
  readonly rA: Point;
  readonly rB: Point;
  constructor(rA: Point, rB: Point) { super(rA, rB); this.rA = rA; this.rB = rB; }
  public proveConvergence(deltaO: bigint) {
    assert(ecOnCurve(this.rA));
    assert(ecOnCurve(this.rB));
    const diff = ecAdd(this.rA, ecNegate(this.rB));
    const expected = ecMulGen(deltaO);
    assert(ecPointX(diff) === ecPointX(expected));
    assert(ecPointY(diff) === ecPointY(expected));
  }
}
"""
        artifact = _compile_source(source, "ConvergencePattern.runar.ts")

        a, b = 142, 37
        delta_o = a - b
        rax, ray = ec_mul_gen(a)
        rbx, rby = ec_mul_gen(b)

        contract = RunarContract(artifact, [
            encode_point(rax, ray),
            encode_point(rbx, rby),
        ])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=500000))

        call_txid, _ = contract.call("proveConvergence", [delta_o], provider, wallet["signer"])
        assert call_txid

    def test_ec_mul_gen_large_scalar(self):
        """ecMulGen with large scalar near curve order."""
        source = """\
import { SmartContract, assert, ecMulGen, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expected: Point;
  constructor(expected: Point) { super(expected); this.expected = expected; }
  public verify(k: bigint) {
    const result = ecMulGen(k);
    assert(ecPointX(result) === ecPointX(this.expected));
    assert(ecPointY(result) === ecPointY(this.expected));
  }
}
"""
        artifact = _compile_source(source, "EcMulGenTest.runar.ts")

        k = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364100
        ex, ey = ec_mul_gen(k)

        contract = RunarContract(artifact, [encode_point(ex, ey)])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        call_txid, _ = contract.call("verify", [k], provider, wallet["signer"])
        assert call_txid
