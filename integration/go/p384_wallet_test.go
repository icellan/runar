//go:build integration

package integration

// P-384 (NIST P-384 / secp384r1) on-chain integration tests.
//
// These tests deploy minimal contracts that exercise verifyECDSA_P384 and the
// P-384 curve built-ins on the BSV regtest node, confirming that the compiled
// Bitcoin Script actually executes correctly and that the off-chain Go helpers
// (P384Keygen, P384Sign, etc.) produce values the on-chain verifier accepts.
//
// # Test Contracts
//
// P384Verify — verifyECDSA_P384 with known message baked into the constructor.
//   The locking script commits to (p384PubKeyHash, msgHash). Spending supplies
//   (p384Sig, p384PubKey) as method parameters. This avoids baking a random
//   signature into the constructor (signatures change each run because they
//   include a random nonce from a freshly generated keypair).
//
// P384OnCurveTest — verifies the p384OnCurve built-in compiles and runs on-chain.
//   A 96-byte P-384 uncompressed point is baked into the constructor and the
//   spending method asserts the point is on the curve.
//
// P384MulGenTest — verifies p384MulGen + p384EncodeCompressed by computing k*G
//   off-chain and asserting the on-chain result matches.
//
// # Signing Model
//
// verifyECDSA_P384(msg, sig, pubKey):
//   - msg: the raw message bytes (SHA-256 hashed internally by the Script verifier;
//     the codegen uses OP_SHA256 for both P-256 and P-384)
//   - sig: 96-byte raw r||s (NOT DER-encoded, 48 bytes each)
//   - pubKey: 49-byte compressed public key (02/03 prefix + 48-byte x-coord)
//
// P384Sign in runar-go produces a 96-byte r||s signature over SHA-256(msg),
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
// P384Verify: verifyECDSA_P384 with known message baked into constructor
// ---------------------------------------------------------------------------

const p384VerifySource = `
import { SmartContract, assert, hash160, verifyECDSA_P384 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P384Verify extends SmartContract {
  readonly p384PubKeyHash: ByteString;
  readonly msg: ByteString;

  constructor(p384PubKeyHash: ByteString, msg: ByteString) {
    super(p384PubKeyHash, msg);
    this.p384PubKeyHash = p384PubKeyHash;
    this.msg = msg;
  }

  public spend(p384Sig: ByteString, p384PubKey: ByteString) {
    assert(hash160(p384PubKey) == this.p384PubKeyHash);
    assert(verifyECDSA_P384(this.msg, p384Sig, p384PubKey));
  }
}
`

// TestP384Verify_SpendSuccess generates a P-384 keypair off-chain, signs a known
// test message, deploys a contract that commits to the pubKeyHash and the raw
// message bytes, then spends it by supplying the signature and pubKey.
//
// verifyECDSA_P384(msg, sig, pubkey) SHA-256 hashes `msg` internally before
// verification. P384Sign also SHA-256 hashes `msg` before signing. So both
// sides operate on the same digest — the raw message is passed to both.
func TestP384Verify_SpendSuccess(t *testing.T) {
	// Fixed test message — baked into the locking script as a constructor arg.
	// verifyECDSA_P384 SHA-256 hashes this internally before verifying.
	testMsg := []byte("runar p-384 integration test message")
	testMsgHex := hex.EncodeToString(testMsg)

	// Generate a fresh P-384 keypair for this test run.
	kp := runar.P384Keygen()
	p384PubKeyCompressed := runar.P384EncodeCompressed(kp.PK) // 49-byte ByteString
	p384PubKeyHash := runar.Hash160(runar.PubKey(p384PubKeyCompressed))
	p384PubKeyHashHex := hex.EncodeToString([]byte(p384PubKeyHash))

	// Sign the raw test message. P384Sign SHA-256 hashes internally — this
	// matches the on-chain verifier which also hashes the msg before verifying.
	sig := runar.P384Sign(testMsg, kp.SK) // 96-byte r||s
	sigHex := hex.EncodeToString(sig)
	pubKeyHex := hex.EncodeToString([]byte(p384PubKeyCompressed))

	t.Logf("msg (hex): %s", testMsgHex)
	t.Logf("p384PubKeyHash: %s", p384PubKeyHashHex)
	t.Logf("p384Sig (96 bytes): %s", sigHex)

	compileDeployAndSpendSDK(t,
		p384VerifySource, "P384Verify.runar.ts",
		// Constructor: (p384PubKeyHash, msg)
		[]interface{}{p384PubKeyHashHex, testMsgHex},
		"spend",
		// Method args: (p384Sig, p384PubKey)
		[]interface{}{sigHex, pubKeyHex},
	)
}

// TestP384Verify_WrongSigFails confirms the contract rejects an invalid P-384
// signature (produced by a different keypair).
func TestP384Verify_WrongSigFails(t *testing.T) {
	testMsg := []byte("runar p-384 wrong-sig test")
	testMsgHex := hex.EncodeToString(testMsg)

	// Commit to kp1's pubkey in the constructor…
	kp1 := runar.P384Keygen()
	p384PubKey1 := runar.P384EncodeCompressed(kp1.PK)
	p384PubKeyHash := runar.Hash160(runar.PubKey(p384PubKey1))
	p384PubKeyHashHex := hex.EncodeToString([]byte(p384PubKeyHash))

	// …but sign with kp2 (different keypair). hash160(p384PubKey1) check passes
	// (we still present kp1's pubkey), but the ECDSA verification will fail.
	kp2 := runar.P384Keygen()
	badSig := runar.P384Sign(testMsg, kp2.SK)
	badSigHex := hex.EncodeToString(badSig)
	pubKey1Hex := hex.EncodeToString([]byte(p384PubKey1))

	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		p384VerifySource, "P384Verify.runar.ts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{p384PubKeyHashHex, testMsgHex})

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

	// Call must fail because the P-384 signature is from a different keypair.
	_, _, callErr := contract.Call("spend", []interface{}{badSigHex, pubKey1Hex}, provider, signer, nil)
	if callErr == nil {
		t.Fatal("expected call to fail with wrong P-384 signature, but it succeeded")
	}
	t.Logf("correctly rejected bad P-384 signature: %v", callErr)
}

// ---------------------------------------------------------------------------
// P384OnCurve: p384OnCurve built-in
// ---------------------------------------------------------------------------

const p384OnCurveSource = `
import { SmartContract, assert, p384OnCurve } from 'runar-lang';
import type { P384Point } from 'runar-lang';

class P384OnCurveTest extends SmartContract {
  readonly pt: P384Point;

  constructor(pt: P384Point) {
    super(pt);
    this.pt = pt;
  }

  public check() {
    assert(p384OnCurve(this.pt));
  }
}
`

// TestP384OnCurve_ValidPoint generates a random P-384 key and verifies the
// corresponding 96-byte uncompressed public key point is accepted by the
// on-chain p384OnCurve check.
func TestP384OnCurve_ValidPoint(t *testing.T) {
	kp := runar.P384Keygen()
	// kp.PK is the 96-byte uncompressed encoding (x[48] || y[48]) — this is P384Point.
	ptHex := fmt.Sprintf("%x", []byte(kp.PK))

	compileDeployAndSpendSDK(t,
		p384OnCurveSource, "P384OnCurveTest.runar.ts",
		[]interface{}{ptHex},
		"check",
		[]interface{}{},
	)
}

// ---------------------------------------------------------------------------
// P384MulGen: p384MulGen + p384EncodeCompressed
// ---------------------------------------------------------------------------

const p384MulGenSource = `
import { SmartContract, assert, p384MulGen, p384EncodeCompressed } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P384MulGenTest extends SmartContract {
  readonly expectedCompressed: ByteString;

  constructor(expectedCompressed: ByteString) {
    super(expectedCompressed);
    this.expectedCompressed = expectedCompressed;
  }

  public check(k: bigint) {
    assert(p384EncodeCompressed(p384MulGen(k)) == this.expectedCompressed);
  }
}
`

// TestP384MulGen_KTimesG computes 7*G off-chain and verifies the on-chain
// p384MulGen(7) produces the same compressed point encoding.
func TestP384MulGen_KTimesG(t *testing.T) {
	k := big.NewInt(7)
	ptHex := runar.P384MulGen(k)
	expectedCompressed := runar.P384EncodeCompressed(ptHex)
	expectedHex := hex.EncodeToString([]byte(expectedCompressed))

	compileDeployAndSpendSDK(t,
		p384MulGenSource, "P384MulGenTest.runar.ts",
		[]interface{}{expectedHex},
		"check",
		[]interface{}{k},
	)
}
