package compiler

// Port of the TypeScript reference test
// packages/runar-compiler/src/__tests__/constructor-args-validation.test.ts.
//
// applyConstructorArgs must reject inputs that would silently bake nothing and
// emit placeholder scripts that fail opaquely at runtime:
//
//	(a) positional arrays — N/A for the Go tier: ConstructorArgs is a typed
//	    map[string]interface{}, so a positional array cannot reach the API.
//	    (The dynamically-typed tiers guard this explicitly.)
//	(b) keys that match no contract property (typos)
//	(c) referenced readonly properties left unbaked after applying the args
//
// The placeholder path (no ConstructorArgs) stays unchecked / byte-identical.

import (
	"math/big"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

const hashLockSource = `import { SmartContract, assert, sha256 } from 'runar-lang';
import type { ByteString, Sha256 } from 'runar-lang';

class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`

const twoPropSource = `import { SmartContract, assert } from 'runar-lang';

class TwoProp extends SmartContract {
  readonly target: bigint;
  readonly unused: bigint;

  constructor(target: bigint, unused: bigint) {
    super(target, unused);
    this.target = target;
    this.unused = unused;
  }

  public check(x: bigint) {
    assert(x === this.target);
  }
}
`

const hashHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // "aa" * 32

func errorMessages(result *CompileResult) string {
	var msgs []string
	for _, d := range result.Diagnostics {
		if d.Severity == frontend.SeverityError {
			msgs = append(msgs, d.Message)
		}
	}
	return strings.Join(msgs, "\n")
}

func TestConstructorArgs_RejectsUnknownKey(t *testing.T) {
	result := CompileFromSourceStrWithResult(hashLockSource, "HashLock.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"hashVal": hashHex}, // typo: hashValue
	})

	if result.Success {
		t.Fatalf("expected compilation to fail for an unknown constructorArgs key")
	}
	msgs := errorMessages(result)
	if !strings.Contains(msgs, "'hashVal'") {
		t.Errorf("error should name the offending key 'hashVal'; got:\n%s", msgs)
	}
	if !strings.Contains(msgs, "hashValue") {
		t.Errorf("error should list the valid property 'hashValue'; got:\n%s", msgs)
	}
}

func TestConstructorArgs_RejectsUnbakedReferencedReadonly(t *testing.T) {
	// 'target' is referenced by check() but not provided; only 'unused' is baked.
	result := CompileFromSourceStrWithResult(twoPropSource, "TwoProp.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"unused": big.NewInt(1)},
	})

	if result.Success {
		t.Fatalf("expected compilation to fail when a referenced readonly stays unbaked")
	}
	msgs := errorMessages(result)
	if !strings.Contains(msgs, "'target'") {
		t.Errorf("error should name the unbaked referenced property 'target'; got:\n%s", msgs)
	}
	if !strings.Contains(msgs, "placeholder") {
		t.Errorf("error should mention the OP_0 placeholder hazard; got:\n%s", msgs)
	}
}

func TestConstructorArgs_AcceptsUnreferencedUnbakedReadonly(t *testing.T) {
	// 'unused' is never referenced by a method — DCE eliminates it, so leaving
	// it unbaked is fine.
	result := CompileFromSourceStrWithResult(twoPropSource, "TwoProp.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"target": big.NewInt(42)},
	})

	if !result.Success {
		t.Fatalf("expected success (unused readonly is unreferenced); diagnostics:\n%s", errorMessages(result))
	}
	if result.Artifact == nil || result.Artifact.Script == "" {
		t.Errorf("expected a compiled artifact with a script")
	}
}

func TestConstructorArgs_AcceptsCompleteRecord(t *testing.T) {
	result := CompileFromSourceStrWithResult(hashLockSource, "HashLock.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"hashValue": hashHex},
	})

	if !result.Success {
		t.Fatalf("expected success for a complete named record; diagnostics:\n%s", errorMessages(result))
	}
	if result.Artifact == nil {
		t.Fatal("expected a compiled artifact")
	}
	if !strings.Contains(result.Artifact.Script, hashHex) {
		t.Errorf("baked script should contain the hash bytes %s; got script:\n%s", hashHex, result.Artifact.Script)
	}
	if len(result.Artifact.ConstructorSlots) != 0 {
		t.Errorf("a fully baked contract should carry no constructor slots; got %d", len(result.Artifact.ConstructorSlots))
	}
}

func TestConstructorArgs_NoArgsStillProducesPlaceholderSlots(t *testing.T) {
	// The no-args placeholder path stays unchecked and byte-identical to before.
	result := CompileFromSourceStrWithResult(hashLockSource, "HashLock.runar.ts", CompileOptions{})

	if !result.Success {
		t.Fatalf("expected success for placeholder compilation; diagnostics:\n%s", errorMessages(result))
	}
	if result.Artifact == nil || len(result.Artifact.ConstructorSlots) < 1 {
		t.Errorf("placeholder compilation should carry at least one constructor slot")
	}
}

// F-101 — (d) value kind / byte-width check.
//
// Before the fix applyConstructorArgs baked any interface{} into the property:
// `true` against a 20-byte hash pushed OP_1, a 6-byte hex string a 6-byte
// push, and a plain Go `int` fell through pushPropertyValue's default arm and
// baked OP_0 — every one compiled with Success == true and is unspendable.
// Proves: each mismatch is refused with the TypeScript reference's diagnostic,
// naming the property, its declared type and the expected shape. Does NOT
// prove anything about the SDK's deploy-time constructorSlots path.

func f101P2PKH(t string) string {
	return `class P2PKH extends SmartContract {
  readonly pubKeyHash: ` + t + `;
  constructor(pubKeyHash: ` + t + `) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`
}

func TestConstructorArgs_F101_RejectsValueNotMatchingPropertyType(t *testing.T) {
	cases := []struct {
		typ  string
		val  interface{}
		want string
	}{
		{"ByteString", true, "must be a hex string, got a boolean"},
		{"Addr", true, "must be exactly 20 bytes of hex, got a boolean"},
		{"Addr", big.NewInt(42), "must be exactly 20 bytes of hex, got an integer"},
		{"Addr", "aabbccddeeff", "must be exactly 20 bytes of hex, got 6 bytes of hex"},
		{"Addr", "zzzz-not-hex", "must be exactly 20 bytes of hex, got a non-hex string"},
		{"ByteString", "abc", "must be a hex string, got a non-hex string"},
		{"ByteString", nil, "must be a hex string, got an unsupported value"},
	}
	for _, c := range cases {
		result := CompileFromSourceStrWithResult(f101P2PKH(c.typ), "P2PKH.runar.ts", CompileOptions{
			ConstructorArgs: map[string]interface{}{"pubKeyHash": c.val},
		})
		msgs := errorMessages(result)
		if result.Success {
			t.Errorf("%s <- %#v: expected rejection, compiled to %s", c.typ, c.val, result.Artifact.Script)
			continue
		}
		if !strings.Contains(msgs, "property 'pubKeyHash' ("+c.typ+")") || !strings.Contains(msgs, c.want) {
			t.Errorf("%s <- %#v: expected %q; got:\n%s", c.typ, c.val, c.want, msgs)
		}
	}
}

func TestConstructorArgs_F101_RejectsBigintAndBooleanMismatches(t *testing.T) {
	src := `class Flagged extends SmartContract {
  readonly target: bigint;
  readonly on: boolean;
  constructor(target: bigint, on: boolean) { super(target, on); this.target = target; this.on = on; }
  public check(x: bigint) { assert(this.on); assert(x === this.target); }
}
`
	result := CompileFromSourceStrWithResult(src, "Flagged.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"target": "2a", "on": big.NewInt(1)},
	})
	if result.Success {
		t.Fatalf("expected rejection, compiled to %s", result.Artifact.Script)
	}
	msgs := errorMessages(result)
	for _, want := range []string{
		"property 'target' (bigint) must be an integer, got 1 bytes of hex",
		"property 'on' (boolean) must be a boolean, got an integer",
	} {
		if !strings.Contains(msgs, want) {
			t.Errorf("expected %q; got:\n%s", want, msgs)
		}
	}
}

func TestConstructorArgs_F101_AcceptsCorrectlyTypedValues(t *testing.T) {
	ok := CompileFromSourceStrWithResult(f101P2PKH("Addr"), "P2PKH.runar.ts", CompileOptions{
		ConstructorArgs: map[string]interface{}{"pubKeyHash": strings.Repeat("ab", 20)},
	})
	if !ok.Success {
		t.Fatalf("20-byte hex Addr should compile:\n%s", errorMessages(ok))
	}
	// A plain Go int is an integer and must bake as that integer — before the
	// fix it fell through pushPropertyValue's default arm and baked OP_0.
	for _, v := range []interface{}{42, int64(42), big.NewInt(42), float64(42)} {
		r := CompileFromSourceStrWithResult(twoPropSource, "TwoProp.runar.ts", CompileOptions{
			ConstructorArgs: map[string]interface{}{"target": v},
		})
		if !r.Success {
			t.Fatalf("%T(42) should compile:\n%s", v, errorMessages(r))
		}
		if !strings.Contains(r.Artifact.Script, "012a") {
			t.Errorf("%T(42) should bake the push 012a; got %s", v, r.Artifact.Script)
		}
	}
}
