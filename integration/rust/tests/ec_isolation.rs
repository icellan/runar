//! EC isolation integration tests — inline contracts testing individual EC functions.
//!
//! Each test compiles a minimal stateless contract that exercises a single EC
//! built-in, deploys it on regtest, and verifies the deployment succeeds.
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use crate::helpers::crypto::{ec_mul_gen_point, ec_mul_gen, encode_point, bigint_to_script_num_hex};
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use num_bigint::BigInt;

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_on_curve_deploy() {
    skip_if_no_node();

    let source = r#"
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
"#;
    let artifact = compile_source(source, "EcOnCurveTest.runar.ts");
    assert_eq!(artifact.contract_name, "EcOnCurveTest");

    let point_hex = ec_mul_gen_point(42);

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(point_hex)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_mul_gen_deploy() {
    skip_if_no_node();

    let source = r#"
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
"#;
    let artifact = compile_source(source, "EcMulGenTest.runar.ts");
    assert_eq!(artifact.contract_name, "EcMulGenTest");

    let expected_hex = ec_mul_gen_point(7);

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(expected_hex)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[SdkValue::Int(7)], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_add_deploy() {
    skip_if_no_node();

    let source = r#"
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
"#;
    let artifact = compile_source(source, "EcAddTest.runar.ts");
    assert_eq!(artifact.contract_name, "EcAddTest");

    let (ax, ay) = ec_mul_gen(3);
    let (bx, by) = ec_mul_gen(5);
    // 3G + 5G = 8G
    let (ex, ey) = ec_mul_gen(8);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(encode_point(&ax, &ay)),
        SdkValue::Bytes(encode_point(&bx, &by)),
        SdkValue::Bytes(encode_point(&ex, &ey)),
    ]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("verify", &[], &mut provider, &*signer, None)
        .expect("call verify failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_negate_deploy() {
    skip_if_no_node();

    // Verify ecNegate by comparing against the expected negated Point (both as Point type).
    let source = r#"
import { SmartContract, assert, ecNegate, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcNegateTest extends SmartContract {
  readonly pt: Point;
  readonly negPt: Point;

  constructor(pt: Point, negPt: Point) {
    super(pt, negPt);
    this.pt = pt;
    this.negPt = negPt;
  }

  public check() {
    const neg = ecNegate(this.pt);
    assert(ecPointX(neg) === ecPointX(this.negPt));
    assert(ecPointY(neg) === ecPointY(this.negPt));
  }
}
"#;
    let artifact = compile_source(source, "EcNegateTest.runar.ts");
    assert_eq!(artifact.contract_name, "EcNegateTest");

    // Compute negated point using k256
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    let scalar = Scalar::from(10u64);
    let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let neg_point = (-ProjectivePoint::from(point)).to_affine();
    let neg_enc = neg_point.to_encoded_point(false);
    let neg_x_hex: String = neg_enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let neg_y_hex: String = neg_enc.y().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let neg_point_hex = encode_point(&neg_x_hex, &neg_y_hex);

    let point_hex = ec_mul_gen_point(10);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(point_hex),
        SdkValue::Bytes(neg_point_hex),
    ]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("check", &[], &mut provider, &*signer, None)
        .expect("call check failed");
    assert!(!spend_txid.is_empty());
}

/// Parse a big-endian hex coordinate string into a BigInt.
fn hex_to_bigint(hex: &str) -> BigInt {
    BigInt::parse_bytes(hex.as_bytes(), 16).expect("invalid hex for BigInt")
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_point_x_deploy() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class EcPointXTest extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expectedX: bigint) { assert(ecPointX(this.pt) === expectedX); }
}
"#;
    let artifact = compile_source(source, "EcPointXTest.runar.ts");

    // Use generator point G
    let (gx_hex, _gy_hex) = ec_mul_gen(1);
    let point_hex = ec_mul_gen_point(1);
    let gx = hex_to_bigint(&gx_hex);
    let gx_script = bigint_to_script_num_hex(&gx);

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(point_hex)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("check", &[SdkValue::Bytes(gx_script)], &mut provider, &*signer, None)
        .expect("call check failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_on_curve_then_point_x() {
    skip_if_no_node();

    let source = r#"
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
"#;
    let artifact = compile_source(source, "EcOnCurveTwice.runar.ts");

    let (gx_hex, _gy_hex) = ec_mul_gen(1);
    let point_hex = ec_mul_gen_point(1);
    let gx = hex_to_bigint(&gx_hex);
    let gx_script = bigint_to_script_num_hex(&gx);

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(point_hex)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("check", &[SdkValue::Bytes(gx_script)], &mut provider, &*signer, None)
        .expect("call check failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_convergence_pattern() {
    skip_if_no_node();

    let source = r#"
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
"#;
    let artifact = compile_source(source, "ConvergencePattern.runar.ts");

    // 142*G and 37*G, delta = 105
    let (ra_x, ra_y) = ec_mul_gen(142);
    let (rb_x, rb_y) = ec_mul_gen(37);
    let ra_hex = encode_point(&ra_x, &ra_y);
    let rb_hex = encode_point(&rb_x, &rb_y);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(ra_hex),
        SdkValue::Bytes(rb_hex),
    ]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 500000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    // deltaO = 142 - 37 = 105
    let (spend_txid, _tx) = contract
        .call("proveConvergence", &[SdkValue::Int(105)], &mut provider, &*signer, None)
        .expect("call proveConvergence failed");
    assert!(!spend_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_ec_mul_gen_large_scalar() {
    skip_if_no_node();

    let source = r#"
import { SmartContract, assert, ecMulGen, ecPointX } from 'runar-lang';

class EcMulGenTest extends SmartContract {
  readonly expectedX: bigint;
  constructor(expectedX: bigint) { super(expectedX); this.expectedX = expectedX; }
  public check(k: bigint) { assert(ecPointX(ecMulGen(k)) === this.expectedX); }
}
"#;
    let artifact = compile_source(source, "EcMulGenTest.runar.ts");

    // Large scalar near the curve order (exercises k+3n fix)
    let k = hex_to_bigint("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364100");

    // Compute k*G using k256
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;

    // k is near N, reduce mod N to get scalar
    let k_bytes = {
        let (_, be_bytes) = k.to_bytes_be();
        let mut arr = [0u8; 32];
        let start = 32usize.saturating_sub(be_bytes.len());
        arr[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);
        arr
    };
    let k_u256 = U256::from_be_slice(&k_bytes);
    let k_scalar = <Scalar as Reduce<U256>>::reduce(k_u256);
    let point = (ProjectivePoint::GENERATOR * k_scalar).to_affine();
    let enc = point.to_encoded_point(false);
    let rx_hex: String = enc.x().unwrap().iter().map(|b| format!("{:02x}", b)).collect();
    let rx = hex_to_bigint(&rx_hex);
    let rx_script = bigint_to_script_num_hex(&rx);

    // k as script num hex for the method arg
    let k_script = bigint_to_script_num_hex(&k);

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(rx_script)]);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 500000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());

    let (spend_txid, _tx) = contract
        .call("check", &[SdkValue::Bytes(k_script)], &mut provider, &*signer, None)
        .expect("call check failed");
    assert!(!spend_txid.is_empty());
}
