// N-142 (Go twin of F-200) — .runar.sol leading-underscore stripping applies
// to CONSTRUCTOR params only.
//
// `parseSolParams` used to strip a leading `_` from every parameter, but only
// `parseSolConstructor` renames its body to match. So a METHOD param `_x` was
// declared as `x` while the body still read `_x`:
//
//   - unbound: `function check(bigint _x) public { require(_x == target); }`
//     failed typecheck with "Undefined variable '_x'" (TS compiles it);
//   - silent: `function inc(bigint _count) public { count++; }` declared a
//     param `count` that shadowed the property, so the bare `count++` would
//     bump the param and drop the state write;
//   - inter: both at once.
//
// The rule is the TS reference's (01-parse-sol.ts): `parseConstructor` strips
// `_` and renames the body; `parseFunction` keeps param names verbatim.
//
// What this proves: in the Go tier, method params keep their `_` name, the
// constructor still strips it, the bare `count++` stays a property write, and
// all three shapes compile (fold-ON default) to the TS reference bytes
// (sha256-pinned, the same pins as
// conformance/negatives/sol-method-param-underscore-parity.test.ts).
// What it does NOT prove: other tiers (the 7-tier pin lives in that
// conformance test), fold-OFF output, or on-chain spend behaviour of the bytes.

package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

const n142Unbound = `pragma runar ^0.1.0;

contract F200Unbound is SmartContract {
    bigint immutable target;

    constructor(bigint _target) {
        target = _target;
    }

    function check(bigint _x) public {
        require(_x == target);
    }
}
`

const n142Silent = `pragma runar ^0.1.0;

contract F200Silent is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function inc(bigint _count) public {
        count++;
    }
}
`

const n142Inter = `pragma runar ^0.1.0;

contract F200Inter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function inc(bigint _count) public {
        count++;
        require(_count > 0);
    }
}
`

func n142Method(t *testing.T, src, file, name string) (frontend.MethodNode, *frontend.ContractNode) {
	t.Helper()
	r := frontend.ParseSource([]byte(src), file)
	if len(r.Errors) > 0 || r.Contract == nil {
		t.Fatalf("parse errors: %s", strings.Join(r.ErrorStrings(), "; "))
	}
	for _, m := range r.Contract.Methods {
		if m.Name == name {
			return m, r.Contract
		}
	}
	t.Fatalf("no method %s", name)
	return frontend.MethodNode{}, nil
}

func n142HexSha(t *testing.T, src, file string) string {
	t.Helper()
	r := CompileFromSourceStrWithResult(src, file)
	if !r.Success {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("%s did not compile: %s", file, strings.Join(msgs, "; "))
	}
	sum := sha256.Sum256([]byte(r.ScriptHex))
	return hex.EncodeToString(sum[:])
}

func TestN142_SolMethodParamKeepsUnderscoreConstructorStrips(t *testing.T) {
	m, c := n142Method(t, n142Unbound, "F200Unbound.runar.sol", "check")
	if len(m.Params) != 1 || m.Params[0].Name != "_x" {
		t.Fatalf("method params = %+v, want [_x]", m.Params)
	}
	if len(c.Constructor.Params) != 1 || c.Constructor.Params[0].Name != "target" {
		t.Fatalf("constructor params = %+v, want [target]", c.Constructor.Params)
	}
}

func TestN142_SolUnboundShapeCompilesToTSBytes(t *testing.T) {
	r := CompileFromSourceStrWithResult(n142Unbound, "F200Unbound.runar.sol")
	if !r.Success {
		var msgs []string
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("did not compile: %s", strings.Join(msgs, "; "))
	}
	if r.ScriptHex != "009c" {
		t.Fatalf("hex = %s, want 009c", r.ScriptHex)
	}
}

func TestN142_SolSilentShapeWritesState(t *testing.T) {
	m, _ := n142Method(t, n142Silent, "F200Silent.runar.sol", "inc")
	if len(m.Params) != 1 || m.Params[0].Name != "_count" {
		t.Fatalf("method params = %+v, want [_count]", m.Params)
	}
	es, ok := m.Body[0].(frontend.ExpressionStmt)
	if !ok {
		t.Fatalf("body[0] = %T, want ExpressionStmt", m.Body[0])
	}
	ie, ok := es.Expr.(frontend.IncrementExpr)
	if !ok {
		t.Fatalf("expr = %T, want IncrementExpr", es.Expr)
	}
	if _, ok := ie.Operand.(frontend.PropertyAccessExpr); !ok {
		t.Fatalf("operand = %T, want PropertyAccessExpr", ie.Operand)
	}
	const want = "484142b25662c6a0a0126f11b1d4700fd79632224dc38c6ae869c889e5fe30d5"
	if got := n142HexSha(t, n142Silent, "F200Silent.runar.sol"); got != want {
		t.Fatalf("sha256(hex) = %s, want %s", got, want)
	}
}

func TestN142_SolInterShapeCompilesToTSBytes(t *testing.T) {
	const want = "29956ebf68e8510b65a74f18a47e5851f322bf6dc2d0981b45ee301f2aaae575"
	if got := n142HexSha(t, n142Inter, "F200Inter.runar.sol"); got != want {
		t.Fatalf("sha256(hex) = %s, want %s", got, want)
	}
}
