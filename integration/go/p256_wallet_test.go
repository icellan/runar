//go:build integration

package integration

// P-256 (NIST P-256 / secp256r1) on-chain integration tests.
//
// These tests deploy minimal contracts that exercise verifyECDSA_P256 and the
// P-256 curve built-ins on the BSV regtest node, confirming that the compiled
// Bitcoin Script actually executes correctly and that the off-chain Go helpers
// (P256Keygen, P256Sign, etc.) produce values the on-chain verifier accepts.
//
// # Test Contracts
//
// P256Verify — verifyECDSA_P256 with known message baked into the constructor.
//   The locking script commits to (p256PubKeyHash, msgHash). Spending supplies
//   (p256Sig, p256PubKey) as method parameters. This avoids baking a random
//   signature into the constructor (signatures change each run because they
//   include a random nonce from a freshly generated keypair).
//
// P256OnCurveTest — verifies the p256OnCurve built-in compiles and runs on-chain.
//   A 64-byte P-256 uncompressed point is baked into the constructor and the
//   spending method asserts the point is on the curve.
//
// P256MulGenTest — verifies p256MulGen + p256EncodeCompressed by computing k*G
//   off-chain and asserting the on-chain result matches.
//
// # Signing Model
//
// verifyECDSA_P256(msg, sig, pubKey):
//   - msg: the raw message bytes (SHA-256 hashed internally by the Script verifier)
//   - sig: 64-byte raw r||s (NOT DER-encoded)
//   - pubKey: 33-byte compressed public key (02/03 prefix + 32-byte x-coord)
//
// P256Sign in runar-go produces a 64-byte r||s signature over SHA-256(msg),
// matching what the on-chain Script verifier expects.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// ---------------------------------------------------------------------------
// P256Verify: verifyECDSA_P256 with known message baked into constructor
// ---------------------------------------------------------------------------

const p256VerifySource = `
import { SmartContract, assert, hash160, verifyECDSA_P256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P256Verify extends SmartContract {
  readonly p256PubKeyHash: ByteString;
  readonly msg: ByteString;

  constructor(p256PubKeyHash: ByteString, msg: ByteString) {
    super(p256PubKeyHash, msg);
    this.p256PubKeyHash = p256PubKeyHash;
    this.msg = msg;
  }

  public spend(p256Sig: ByteString, p256PubKey: ByteString) {
    assert(hash160(p256PubKey) == this.p256PubKeyHash);
    assert(verifyECDSA_P256(this.msg, p256Sig, p256PubKey));
  }
}
`

// TestP256Verify_SpendSuccess generates a P-256 keypair off-chain, signs a known
// test message, deploys a contract that commits to the pubKeyHash and the raw
// message bytes, then spends it by supplying the signature and pubKey.
//
// verifyECDSA_P256(msg, sig, pubkey) SHA-256 hashes `msg` internally before
// verification. P256Sign also SHA-256 hashes `msg` before signing. So both
// sides operate on the same digest — the raw message is passed to both.
func TestP256Verify_SpendSuccess(t *testing.T) {
	// Fixed test message — baked into the locking script as a constructor arg.
	// verifyECDSA_P256 SHA-256 hashes this internally before verifying.
	testMsg := []byte("runar p-256 integration test message")
	testMsgHex := hex.EncodeToString(testMsg)

	// Generate a fresh P-256 keypair for this test run.
	kp := runar.P256Keygen()
	p256PubKeyCompressed := runar.P256EncodeCompressed(kp.PK) // 33-byte ByteString
	p256PubKeyHash := runar.Hash160(runar.PubKey(p256PubKeyCompressed))
	p256PubKeyHashHex := hex.EncodeToString([]byte(p256PubKeyHash))

	// Sign the raw test message. P256Sign SHA-256 hashes internally — this
	// matches the on-chain verifier which also hashes the msg before verifying.
	sig := runar.P256Sign(testMsg, kp.SK) // 64-byte r||s
	sigHex := hex.EncodeToString(sig)
	pubKeyHex := hex.EncodeToString([]byte(p256PubKeyCompressed))

	t.Logf("msg (hex): %s", testMsgHex)
	t.Logf("p256PubKeyHash: %s", p256PubKeyHashHex)
	t.Logf("p256Sig (64 bytes): %s", sigHex)

	compileDeployAndSpendSDK(t,
		p256VerifySource, "P256Verify.runar.ts",
		// Constructor: (p256PubKeyHash, msg)
		[]interface{}{p256PubKeyHashHex, testMsgHex},
		"spend",
		// Method args: (p256Sig, p256PubKey)
		[]interface{}{sigHex, pubKeyHex},
	)
}

// TestP256Verify_WrongSigFails confirms the contract rejects an invalid P-256
// signature (produced by a different keypair).
func TestP256Verify_WrongSigFails(t *testing.T) {
	testMsg := []byte("runar p-256 wrong-sig test")
	testMsgHex := hex.EncodeToString(testMsg)

	// Commit to kp1's pubkey in the constructor…
	kp1 := runar.P256Keygen()
	p256PubKey1 := runar.P256EncodeCompressed(kp1.PK)
	p256PubKeyHash := runar.Hash160(runar.PubKey(p256PubKey1))
	p256PubKeyHashHex := hex.EncodeToString([]byte(p256PubKeyHash))

	// …but sign with kp2 (different keypair). hash160(p256PubKey1) check passes
	// (we still present kp1's pubkey), but the ECDSA verification will fail.
	kp2 := runar.P256Keygen()
	badSig := runar.P256Sign(testMsg, kp2.SK)
	badSigHex := hex.EncodeToString(badSig)
	pubKey1Hex := hex.EncodeToString([]byte(p256PubKey1))

	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		p256VerifySource, "P256Verify.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{p256PubKeyHashHex, testMsgHex})

	wallet := helpers.NewWallet()
	helpers.RPCCall("importaddress", wallet.Address, "", false)
	_, err = helpers.FundWallet(wallet, 1.0)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}

	provider := helpers.NewBatchRPCProvider()
	defer provider.MineAll()

	signer, err := helpers.SDKSignerFromWallet(wallet)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 500000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// Call must fail because the P-256 signature is from a different keypair.
	_, _, callErr := contract.Call("spend", []interface{}{badSigHex, pubKey1Hex}, provider, signer, nil)
	if callErr == nil {
		t.Fatal("expected call to fail with wrong P-256 signature, but it succeeded")
	}
	t.Logf("correctly rejected bad P-256 signature: %v", callErr)
}

// ---------------------------------------------------------------------------
// P256OnCurve: p256OnCurve built-in
// ---------------------------------------------------------------------------

const p256OnCurveSource = `
import { SmartContract, assert, p256OnCurve } from 'runar-lang';
import type { P256Point } from 'runar-lang';

class P256OnCurveTest extends SmartContract {
  readonly pt: P256Point;

  constructor(pt: P256Point) {
    super(pt);
    this.pt = pt;
  }

  public check() {
    assert(p256OnCurve(this.pt));
  }
}
`

// TestP256OnCurve_ValidPoint generates a random P-256 key and verifies the
// corresponding 64-byte uncompressed public key point is accepted by the
// on-chain p256OnCurve check.
func TestP256OnCurve_ValidPoint(t *testing.T) {
	kp := runar.P256Keygen()
	// kp.PK is the 64-byte uncompressed encoding (x[32] || y[32]) — this is P256Point.
	ptHex := fmt.Sprintf("%x", []byte(kp.PK))

	compileDeployAndSpendSDK(t,
		p256OnCurveSource, "P256OnCurveTest.runar.ts",
		[]interface{}{ptHex},
		"check",
		[]interface{}{},
	)
}

// ---------------------------------------------------------------------------
// P256MulGen: p256MulGen + p256EncodeCompressed
// ---------------------------------------------------------------------------

const p256MulGenSource = `
import { SmartContract, assert, p256MulGen, p256EncodeCompressed } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P256MulGenTest extends SmartContract {
  readonly expectedCompressed: ByteString;

  constructor(expectedCompressed: ByteString) {
    super(expectedCompressed);
    this.expectedCompressed = expectedCompressed;
  }

  public check(k: bigint) {
    assert(p256EncodeCompressed(p256MulGen(k)) == this.expectedCompressed);
  }
}
`

// TestP256MulGen_KTimesG computes 7*G off-chain and verifies the on-chain
// p256MulGen(7) produces the same compressed point encoding.
func TestP256MulGen_KTimesG(t *testing.T) {
	k := big.NewInt(7)
	ptHex := runar.P256MulGen(k)
	expectedCompressed := runar.P256EncodeCompressed(ptHex)
	expectedHex := hex.EncodeToString([]byte(expectedCompressed))

	compileDeployAndSpendSDK(t,
		p256MulGenSource, "P256MulGenTest.runar.ts",
		[]interface{}{expectedHex},
		"check",
		[]interface{}{k},
	)
}
