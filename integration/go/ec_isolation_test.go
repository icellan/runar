//go:build integration

package integration

import (
	"fmt"
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// compileDeployAndSpendSDK compiles an inline contract, deploys and calls it
// via the SDK's RunarContract.Deploy/Call path.
func compileDeployAndSpendSDK(t *testing.T, source, fileName string, ctorVals []interface{}, methodName string, methodArgs []interface{}) {
	t.Helper()
	artifact, err := helpers.CompileSourceStringToSDKArtifact(source, fileName, map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("script: %d bytes", len(artifact.Script)/2)

	contract := runar.NewRunarContract(artifact, ctorVals)

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewRPCProvider()
	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	txid, _, err := contract.Call(methodName, methodArgs, provider, signer, nil)
	if err != nil {
		t.Fatalf("call %s: %v", methodName, err)
	}
	t.Logf("%s TX confirmed: %s", methodName, txid)
}

// ---------------------------------------------------------------------------
// Test: ecOnCurve only (1 property, no method params)
// ---------------------------------------------------------------------------

const ecOnCurveSource = `
import { SmartContract, assert, ecOnCurve } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcOnCurveTest extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check() { assert(ecOnCurve(this.pt)); }
}
`

func TestEC_OnCurve(t *testing.T) {
	ptHex := fmt.Sprintf("%064x%064x", ecGx, ecGy)
	compileDeployAndSpendSDK(t, ecOnCurveSource, "EcOnCurveTest.runar.ts",
		[]interface{}{ptHex}, "check", []interface{}{})
}

// ---------------------------------------------------------------------------
// Test: ecPointX (1 property, 1 param)
// ---------------------------------------------------------------------------

const ecPointXSource = `
import { SmartContract, assert, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcPointXTest extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expectedX: bigint) { assert(ecPointX(this.pt) === expectedX); }
}
`

func TestEC_PointX(t *testing.T) {
	ptHex := fmt.Sprintf("%064x%064x", ecGx, ecGy)
	compileDeployAndSpendSDK(t, ecPointXSource, "EcPointXTest.runar.ts",
		[]interface{}{ptHex}, "check", []interface{}{ecGx})
}

// ---------------------------------------------------------------------------
// Test: ecMulGen (1 property for expected, 1 param scalar)
// ---------------------------------------------------------------------------

const ecMulGenSource = `
import { SmartContract, assert, ecMulGen, ecPointX } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expectedX: bigint;
  constructor(expectedX: bigint) { super(expectedX); this.expectedX = expectedX; }
  public check(k: bigint) { assert(ecPointX(ecMulGen(k)) === this.expectedX); }
}
`

func TestEC_MulGen(t *testing.T) {
	k := big.NewInt(7)
	rx, _ := ecMul(ecGx, ecGy, k)
	compileDeployAndSpendSDK(t, ecMulGenSource, "EcMulGenTest.runar.ts",
		[]interface{}{rx}, "check", []interface{}{k})
}

// ---------------------------------------------------------------------------
// Test: ecNegate (1 property, 1 param)
// ---------------------------------------------------------------------------

const ecNegateSource = `
import { SmartContract, assert, ecNegate, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcNegateTest extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expectedNegY: bigint) { assert(ecPointY(ecNegate(this.pt)) === expectedNegY); }
}
`

func TestEC_Negate(t *testing.T) {
	ptHex := fmt.Sprintf("%064x%064x", ecGx, ecGy)
	negGy := new(big.Int).Sub(ecP, ecGy)
	compileDeployAndSpendSDK(t, ecNegateSource, "EcNegateTest.runar.ts",
		[]interface{}{ptHex}, "check", []interface{}{negGy})
}

// ---------------------------------------------------------------------------
// Test: ecAdd (2 properties, 1 param)
// ---------------------------------------------------------------------------

const ecAddSource = `
import { SmartContract, assert, ecAdd, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcAddTest extends SmartContract {
  readonly pa: Point;
  readonly pb: Point;
  constructor(pa: Point, pb: Point) { super(pa, pb); this.pa = pa; this.pb = pb; }
  public check(expectedX: bigint) { assert(ecPointX(ecAdd(this.pa, this.pb)) === expectedX); }
}
`

func TestEC_Add(t *testing.T) {
	pax, pay := ecMul(ecGx, ecGy, big.NewInt(3))
	pbx, pby := ecMul(ecGx, ecGy, big.NewInt(5))
	rx, _ := ecMul(ecGx, ecGy, big.NewInt(8))

	paHex := fmt.Sprintf("%064x%064x", pax, pay)
	pbHex := fmt.Sprintf("%064x%064x", pbx, pby)

	compileDeployAndSpendSDK(t, ecAddSource, "EcAddTest.runar.ts",
		[]interface{}{paHex, pbHex}, "check", []interface{}{rx})
}

// ---------------------------------------------------------------------------
// Test: ecOnCurve + ecPointX on same property (used twice)
// ---------------------------------------------------------------------------

const ecOnCurveThenPointXSource = `
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
`

func TestEC_OnCurveThenPointX(t *testing.T) {
	ptHex := fmt.Sprintf("%064x%064x", ecGx, ecGy)
	compileDeployAndSpendSDK(t, ecOnCurveThenPointXSource, "EcOnCurveTwice.runar.ts",
		[]interface{}{ptHex}, "check", []interface{}{ecGx})
}

// ---------------------------------------------------------------------------
// Test: Full ConvergenceProof pattern (2 props used twice each)
// ---------------------------------------------------------------------------

const convergencePatternSource = `
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
`

func TestEC_ConvergencePattern(t *testing.T) {
	a := big.NewInt(142)
	b := big.NewInt(37)
	deltaO := new(big.Int).Sub(a, b)

	rAx, rAy := ecMul(ecGx, ecGy, a)
	rBx, rBy := ecMul(ecGx, ecGy, b)

	rAHex := fmt.Sprintf("%064x%064x", rAx, rAy)
	rBHex := fmt.Sprintf("%064x%064x", rBx, rBy)

	compileDeployAndSpendSDK(t, convergencePatternSource, "ConvergencePattern.runar.ts",
		[]interface{}{rAHex, rBHex}, "proveConvergence", []interface{}{deltaO})
}

// ---------------------------------------------------------------------------
// Test: ecMulGen with large scalar (exercises k+3n fix)
// ---------------------------------------------------------------------------

func TestEC_MulGen_LargeScalar(t *testing.T) {
	k, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364100", 16)
	rx, _ := ecMul(ecGx, ecGy, k)
	compileDeployAndSpendSDK(t, ecMulGenSource, "EcMulGenTest.runar.ts",
		[]interface{}{rx}, "check", []interface{}{k})
}
