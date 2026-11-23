package compiler

import (
	"encoding/json"
	"strings"
	"testing"
)

// PQ-F1: the artifact lists every constructor param passed directly as the
// public key of verifyWOTS / verifySLHDSA_SHA2_*, with the exact byte length
// that verifier needs, so every SDK can refuse a wrong-length key before
// deploying (stateless artifacts carry no ANF to walk).
//
// Proves: the exact JSON text of `pqPubKeyParams` (key order included) for a
// stateless WOTS contract, an SLH-DSA-192f contract, and a contract with a key
// behind a local alias plus a key read in a private helper; and that the key
// is absent with no PQ verifier and for a key passed as a method argument.
// Does not prove: cross-tier equality (conformance/negatives/artifact-flag-parity.test.ts).

func pqArtifactJSON(t *testing.T, src string) map[string]json.RawMessage {
	t.Helper()
	r := CompileFromSourceStrWithResult(src, "C.runar.ts")
	for _, d := range r.Diagnostics {
		if d.Severity == "error" {
			t.Fatalf("compile error: %s", d.Message)
		}
	}
	if r.Artifact == nil {
		t.Fatal("no artifact")
	}
	raw, err := json.Marshal(r.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPQF1_PqPubKeyParams(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"stateless-wots", `import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
}`, `[{"index":0,"name":"pk","scheme":"verifyWOTS","length":64}]`},
		{"slh-192f", `import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }
}`, `[{"index":0,"name":"pk","scheme":"verifySLHDSA_SHA2_192f","length":48}]`},
		{"alias-and-helper", `import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly tag: bigint;
  readonly a: ByteString;
  readonly b: ByteString;
  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
    assert(this.checkB(msg, sig2));
    const k = this.a;
    assert(verifyWOTS(msg, sig, k));
    assert(this.tag > 0n);
  }
}`, `[{"index":1,"name":"a","scheme":"verifyWOTS","length":64},{"index":2,"name":"b","scheme":"verifyWOTS","length":64}]`},
		{"key-as-method-arg", `import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly h: Sha256;
  constructor(h: Sha256) { super(h); this.h = h; }
  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := pqArtifactJSON(t, c.src)
			got, ok := m["pqPubKeyParams"]
			if c.want == "" {
				if ok {
					t.Fatalf("pqPubKeyParams present: %s", got)
				}
				return
			}
			if !ok || strings.TrimSpace(string(got)) != c.want {
				t.Fatalf("pqPubKeyParams = %s, want %s", got, c.want)
			}
		})
	}
}
