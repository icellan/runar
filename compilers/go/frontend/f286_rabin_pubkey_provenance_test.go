package frontend

// F-286: verifyRabinSig's public key (4th argument) must come from the
// contract, not the spender. A spending-method argument lets the spender pick
// the modulus n and forge any message (n = 1, sig = 0 passes real Spend).
//
// What this proves: the Go tier's validator refuses the spender-chosen
// modulus shapes below (public param, alias of a param, helper fed a param,
// alias reassigned from a param, ternary, arithmetic, nested loop) and still
// accepts the property / literal / alias / helper shapes, with the one shared
// diagnostic, on the TS surface and on the .runar.go surface.
// What it does NOT prove: the other six tiers (conformance/negatives
// N220-N228), or a hostile --ir JSON (--ir skips the frontend).

import (
	"strings"
	"testing"
)

const f286Msg = "verifyRabinSig public key (4th argument) must be a contract property or a literal; " +
	"a spender-supplied Rabin modulus lets anyone forge a signature"

func f286Wrap(extraParams, body, extraMethods string) string {
	return `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class C extends SmartContract {
  readonly pk: RabinPubKey;
  readonly pk2: RabinPubKey;

  constructor(pk: RabinPubKey, pk2: RabinPubKey) {
    super(pk, pk2);
    this.pk = pk;
    this.pk2 = pk2;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString` + extraParams + `) {
` + body + `
  }
` + extraMethods + `
}
`
}

const f286Helper = `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`

const f286Chain = `
  private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    const kk = k;
    return this.inner(m, s, p, kk);
  }
  private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`

func f286Errors(t *testing.T, source, fileName string) []string {
	t.Helper()
	res := ParseSource([]byte(source), fileName)
	if len(res.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(res.ErrorStrings(), "; "))
	}
	if res.Contract == nil {
		t.Fatal("parse returned nil contract")
	}
	return Validate(res.Contract).ErrorStrings()
}

func f286Has(errs []string) bool {
	for _, e := range errs {
		if strings.Contains(e, f286Msg) {
			return true
		}
	}
	return false
}

func TestF286_RabinPubKeyProvenance_Refused(t *testing.T) {
	cases := []struct{ name, src string }{
		{"public method parameter", f286Wrap(", n: RabinPubKey", "    assert(verifyRabinSig(msg, sig, padding, n));", "")},
		{"const alias of a parameter", f286Wrap(", n: RabinPubKey", "    const k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", "")},
		{"let alias reassigned from a parameter", f286Wrap(", n: RabinPubKey", "    let k = this.pk;\n    k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));", "")},
		{"private helper bound to a parameter", f286Wrap(", n: RabinPubKey", "    assert(this.check(msg, sig, padding, n));", f286Helper)},
		{"private helper with mixed call sites", f286Wrap(", n: RabinPubKey", "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, n));", f286Helper)},
		{"ternary", f286Wrap(", n: RabinPubKey", "    assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", "")},
		{"arithmetic on a property", f286Wrap("", "    assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));", "")},
		{"parameter in a for nested in an if", f286Wrap(", n: RabinPubKey", "    if (sig > 0n) {\n      for (let i = 0n; i < 2n; i++) {\n        assert(verifyRabinSig(msg, sig, padding, n));\n      }\n    }\n    assert(true);", "")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if errs := f286Errors(t, c.src, "C.runar.ts"); !f286Has(errs) {
				t.Errorf("expected F-286 refusal, got errors: %v", errs)
			}
		})
	}
}

func TestF286_RabinPubKeyProvenance_Accepted(t *testing.T) {
	cases := []struct{ name, src string }{
		{"this.prop", f286Wrap("", "    assert(verifyRabinSig(msg, sig, padding, this.pk));", "")},
		{"bigint literal", f286Wrap("", "    assert(verifyRabinSig(msg, sig, padding, 1000003n));", "")},
		{"const alias of a property", f286Wrap("", "    const k = this.pk;\n    assert(verifyRabinSig(msg, sig, padding, k));", "")},
		{"let reassigned only from properties", f286Wrap("", "    let k = this.pk;\n    if (sig > 0n) {\n      k = this.pk2;\n    }\n    assert(verifyRabinSig(msg, sig, padding, k));", "")},
		{"helper bound to a property at every site", f286Wrap("", "    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, this.pk2));", f286Helper)},
		{"two-level helper chain", f286Wrap("", "    assert(this.outer(msg, sig, padding, this.pk));", f286Chain)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if errs := f286Errors(t, c.src, "C.runar.ts"); len(errs) != 0 {
				t.Errorf("expected no errors, got: %v", errs)
			}
		})
	}
}

const f286GoSurface = `package c

import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	Pk runar.RabinPubKey ` + "`runar:\"readonly\"`" + `
}

func (c *C) Settle(msg runar.ByteString, sig runar.RabinSig, padding runar.ByteString$P) {
	runar.Assert(runar.VerifyRabinSig(msg, sig, padding, $K))
}
`

func TestF286_RabinPubKeyProvenance_GoSurface(t *testing.T) {
	accept := strings.NewReplacer("$P", "", "$K", "c.Pk").Replace(f286GoSurface)
	if errs := f286Errors(t, accept, "C.runar.go"); len(errs) != 0 {
		t.Errorf("c.Pk: expected no errors, got: %v", errs)
	}
	refuse := strings.NewReplacer("$P", ", n runar.RabinPubKey", "$K", "n").Replace(f286GoSurface)
	if errs := f286Errors(t, refuse, "C.runar.go"); !f286Has(errs) {
		t.Errorf("parameter: expected F-286 refusal, got: %v", errs)
	}
}
