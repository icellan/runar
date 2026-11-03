package frontend

// N-205 (a): a stateful method must not write a spender-supplied value into a
// MUTABLE property that verifyRabinSig uses as its public key (the next spend
// would verify against the spender's modulus; n = 1, sig = 0 forges anything).
//
// What this proves: the Go tier's validator refuses the write shapes below
// (parameter, alias of a parameter, compound assignment, ++, if-arm write,
// addOutput slot, private setter fed a parameter, key reached through a
// helper, a property feeding the key written from a parameter) with the one
// shared diagnostic, and still accepts literal / readonly-property / literal-
// only-property writes, non-key writes and the key in its own addOutput slot,
// on the TS surface, the .runar.go surface and the bare-name .runar.sol form.
// What it does NOT prove: the other six tiers, or --ir input (that is
// compilers/go/ir/rabin_key_provenance_test.go and
// conformance/negatives/ir-rabin-key-provenance.test.ts).

import (
	"strings"
	"testing"
)

func n205Msg(prop string) string {
	return "verifyRabinSig public key property '" + prop + "' may only be assigned a contract property or a literal " +
		"outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
}

func n205Wrap(rotateBody, extraMethods, settleCheck string) string {
	if settleCheck == "" {
		settleCheck = "verifyRabinSig(msg, sig, padding, this.key)"
	}
	return `
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class C extends StatefulSmartContract {
  key: RabinPubKey;
  other: RabinPubKey;
  count: bigint;
  readonly backup: RabinPubKey;

  constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {
    super(key, other, count, backup);
    this.key = key;
    this.other = other;
    this.count = count;
    this.backup = backup;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(` + settleCheck + `);
  }

  public rotate(newKey: RabinPubKey, n: bigint) {
` + rotateBody + `
    assert(true);
  }
` + extraMethods + `
}
`
}

const n205Setter = `
  private setKey(v: RabinPubKey): void {
    this.key = v;
  }`

const n205Check = `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`

func n205Has(errs []string, prop string) bool {
	for _, e := range errs {
		if strings.Contains(e, n205Msg(prop)) {
			return true
		}
	}
	return false
}

func TestN205_RabinKeyWrite_Refused(t *testing.T) {
	cases := []struct{ name, src, prop string }{
		{"public parameter", n205Wrap("    this.key = newKey;", "", ""), "key"},
		{"const alias of a parameter", n205Wrap("    const k = newKey;\n    this.key = k;", "", ""), "key"},
		{"compound assignment", n205Wrap("    this.key += n;", "", ""), "key"},
		{"incremented", n205Wrap("    this.key++;", "", ""), "key"},
		{"inside an if", n205Wrap("    if (n > 0n) {\n      this.key = newKey;\n    }", "", ""), "key"},
		{"addOutput slot", n205Wrap("    this.addOutput(1000n, newKey, this.other, this.count);", "", ""), "key"},
		{"private setter fed a parameter", n205Wrap("    this.setKey(newKey);", n205Setter, ""), "key"},
		{"key via helper then written", n205Wrap("    this.key = newKey;", n205Check, "this.check(msg, sig, padding, this.key)"), "key"},
		{"feeding property written from a parameter", n205Wrap("    this.key = this.other;\n    this.other = newKey;", "", ""), "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := f286Errors(t, c.src, "C.runar.ts")
			if !n205Has(errs, c.prop) {
				t.Fatalf("expected N-205 refusal for %q, got %v", c.prop, errs)
			}
		})
	}
}

func TestN205_RabinKeyWrite_Accepted(t *testing.T) {
	cases := []struct{ name, src string }{
		{"bigint literal", n205Wrap("    this.key = 1000003n;", "", "")},
		{"readonly property", n205Wrap("    this.key = this.backup;", "", "")},
		{"literal-only property", n205Wrap("    this.key = this.other;\n    this.other = 7n;", "", "")},
		{"non-key state from a parameter", n205Wrap("    this.count = this.count + n;", "", "")},
		{"non-Rabin property from a parameter", n205Wrap("    this.other = newKey;", "", "")},
		{"key in its own addOutput slot", n205Wrap("    this.addOutput(1000n, this.key, this.other, n);", "", "")},
		{"setter fed a property", n205Wrap("    this.setKey(this.backup);", n205Setter, "")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if errs := f286Errors(t, c.src, "C.runar.ts"); len(errs) > 0 {
				t.Fatalf("expected no errors, got %v", errs)
			}
		})
	}
}

func TestN205_RabinKeyWrite_Surfaces(t *testing.T) {
	goSrc := `package c

import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.StatefulSmartContract
	Key runar.RabinPubKey
}

func (c *C) Settle(msg runar.ByteString, sig runar.RabinSig, padding runar.ByteString) {
	runar.Assert(runar.VerifyRabinSig(msg, sig, padding, c.Key))
}

func (c *C) Rotate(newKey runar.RabinPubKey) {
	c.Key = $V
	runar.Assert(true)
}
`
	solSrc := `pragma runar ^0.1.0;
contract C is StatefulSmartContract {
    RabinPubKey key;
    constructor(RabinPubKey _key) { key = _key; }
    function settle(bytes msg, RabinSig sig, bytes padding) public {
        require(verifyRabinSig(msg, sig, padding, this.key));
    }
    function rotate(RabinPubKey newKey) public {
        key = $V;
        require(true);
    }
}`
	for _, s := range []struct{ file, src string }{{"C.runar.go", goSrc}, {"C.runar.sol", solSrc}} {
		t.Run(s.file+" literal", func(t *testing.T) {
			if errs := f286Errors(t, strings.ReplaceAll(s.src, "$V", "1000003"), s.file); len(errs) > 0 {
				t.Fatalf("expected no errors, got %v", errs)
			}
		})
		t.Run(s.file+" parameter", func(t *testing.T) {
			if errs := f286Errors(t, strings.ReplaceAll(s.src, "$V", "newKey"), s.file); !n205Has(errs, "key") {
				t.Fatalf("expected N-205 refusal, got %v", errs)
			}
		})
	}
}
