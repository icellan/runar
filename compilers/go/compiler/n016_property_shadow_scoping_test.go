package compiler

// N-016 — a local that shares a contract property's name must never capture a
// later `this.<prop>` read or write (user decision R8: correct scoping). Port
// of packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts.
//
//	readonly target: bigint;
//	public unlock(n: bigint) { const target = n + 1n; assert(target == this.target); }
//
// compiled to 8b769c (OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved
// by name to the local's stack slot, an always-true self-comparison.
//
// Oracle: alpha-equivalence, from the source language rather than any compiler
// output. Renaming a local / private-helper param / public param to a fresh
// name cannot change the program's meaning, so each template compiled with
// `$L` = the property's name must produce exactly the bytes of `$L` = `lcl`,
// in both constant-folding modes.
//
// Proves: in the Go tier, property-named locals (top level, if-arm, nested
// block, loop variable, ++, byte-typed, inside a private helper), a private
// helper's param and a public param never capture `this.<prop>`; stateful
// property reads/writes and the continuation are unaffected by a same-named
// local, including an if whose arms rebind the local and write the property.
// Does NOT prove: on-chain behaviour (see
// packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts) or
// local-vs-compiler-temp collisions (a local literally named `t3`).

import (
	"strings"
	"testing"
)

func n016Stateless(body, propType string) string {
	return `import { SmartContract, assert, cat, ByteString } from 'runar-lang';

class Shadow extends SmartContract {
  readonly target: ` + propType + `;
  constructor(target: ` + propType + `) {
    super(target);
    this.target = target;
  }

` + body + `
}
`
}

func n016Stateful(body string) string {
	return `import { StatefulSmartContract, assert } from 'runar-lang';

class Shadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

` + body + `
}
`
}

type n016Shape struct {
	name, prop, template string
}

func n016Shapes() []n016Shape {
	return []n016Shape{
		{"local at method top level", "target", n016Stateless(`  public unlock(n: bigint) {
    const $L = n + 1n;
    assert($L == this.target);
  }`, "bigint")},
		{"local inside an if-arm", "target", n016Stateless(`  public unlock(n: bigint) {
    if (n > 0n) {
      const $L = n + 1n;
      assert($L == this.target);
    } else {
      assert(n == this.target);
    }
  }`, "bigint")},
		{"local inside a nested block", "target", n016Stateless(`  public unlock(n: bigint) {
    if (n > 0n) {
      if (n > 1n) {
        const $L = n + 1n;
        assert($L == this.target);
      } else {
        assert(n + 2n == this.target);
      }
    } else {
      assert(false);
    }
  }`, "bigint")},
		{"loop variable", "target", n016Stateless(`  public unlock(n: bigint) {
    let acc = 0n;
    for (let $L = 0n; $L < 2n; $L++) {
      acc = acc + this.target - $L;
    }
    assert(acc == n);
  }`, "bigint")},
		{"local mutated with ++", "target", n016Stateless(`  public unlock(n: bigint) {
    let $L = n;
    $L++;
    assert($L == this.target);
  }`, "bigint")},
		{"byte-typed local", "target", n016Stateless(`  public unlock(a: ByteString) {
    const $L = cat(a, a);
    assert($L == this.target);
  }`, "ByteString")},
		{"local inside a private helper", "target", n016Stateless(`  private chk(n: bigint): boolean {
    const $L = n + 1n;
    return $L == this.target;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }`, "bigint")},
		{"private helper parameter", "target", n016Stateless(`  private chk($L: bigint): boolean {
    return this.target == $L + 1n;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }`, "bigint")},
		{"public parameter, property read first", "target", n016Stateless(`  public unlock($L: bigint) {
    assert(this.target == $L + 1n);
  }`, "bigint")},
		{"stateful: local, then property read + write", "count", n016Stateful(`  public bump(n: bigint) {
    const $L = n * 2n;
    this.count = this.count + $L;
    assert($L > 0n);
  }`)},
		{"stateful: local live across a property write", "count", n016Stateful(`  public bump(n: bigint) {
    let $L = n;
    this.count = this.count + 1n;
    assert(this.count > $L);
  }`)},
		{"stateful: if-arms rebind the local and write the property", "count", n016Stateful(`  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      $L = $L + 1n;
      this.count = this.count + $L;
    } else {
      this.count = this.count + 1n;
    }
  }`)},
		{"stateful: an if-arm writes the property, then rebinds the local read after the if", "count", n016Stateful(`  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      this.count = this.count + $L;
      $L = $L + 1n;
    } else {
      this.count = this.count + 1n;
    }
    assert($L > 0n);
  }`)},
	}
}

func n016Hex(t *testing.T, source string, disableFold bool) string {
	t.Helper()
	r := CompileFromSourceStrWithResult(source, "Shadow.runar.ts", CompileOptions{DisableConstantFolding: disableFold})
	if !r.Success || r.Artifact == nil {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	return r.Artifact.Script
}

func TestN016_ProbeNoLongerSelfCompares(t *testing.T) {
	src := strings.ReplaceAll(n016Shapes()[0].template, "$L", "target")
	if got := n016Hex(t, src, true); got != "8b009c" {
		t.Fatalf("want 8b009c (OP_1ADD <target placeholder> OP_NUMEQUAL), got %s", got)
	}
}

func TestN016_ShadowingCompilesLikeRenamedSpelling(t *testing.T) {
	for _, s := range n016Shapes() {
		for _, fold := range []bool{true, false} {
			shadow := n016Hex(t, strings.ReplaceAll(s.template, "$L", s.prop), fold)
			control := n016Hex(t, strings.ReplaceAll(s.template, "$L", "lcl"), fold)
			if shadow != control {
				t.Errorf("%s (disableFold=%v): shadowing spelling %s != renamed spelling %s", s.name, fold, shadow, control)
			}
		}
	}
}
