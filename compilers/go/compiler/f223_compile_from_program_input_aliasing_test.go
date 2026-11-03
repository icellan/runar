package compiler

// F-223 (CX-BUG-109, Go-tier parity) — `CompileFromProgram` took its
// `*ir.ANFProgram` parameter by reference and `applyConstructorArgs` wrote
// baked values directly onto the caller's `Properties` slice elements
// (`program.Properties[i].InitialValue = v`, options.go) with no clone. A
// caller that loads an ANF program once (e.g. via `ir.LoadIRFromBytes`) and
// calls `CompileFromProgram` on it twice with different `ConstructorArgs`
// therefore sees:
//   (a) its own `*ir.ANFProgram` permanently mutated after the call returns;
//   (b) a LATER call on that same object with no `ConstructorArgs` silently
//       inherit the EARLIER call's baked value instead of compiling the
//       property as unbaked (OP_0 placeholder).
//
// This mirrors the TypeScript reference bug fixed in `compileFromANF`
// (packages/runar-compiler/src/index.ts) and the Rust tier's
// `compile_from_program_with_options`, which clones its `&ir::ANFProgram`
// borrow before baking for the same reason.
//
// Proves: after two `CompileFromProgram` calls with different
// `ConstructorArgs` on the same shared `*ir.ANFProgram`, the caller's
// `Properties[i].InitialValue` is unchanged, and a later no-args call on that
// object compiles exactly like a fresh, never-baked program.
// Does NOT prove anything about the TS/Rust/Python/Ruby/Zig/Java tiers;
// those are covered (or found not to have the bug) in their own suites.

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

const f223UnbakedXIR = `{
  "contractName": "Baked",
  "properties": [
    { "name": "x", "type": "bigint", "readonly": true }
  ],
  "methods": [
    {
      "name": "unlock",
      "isPublic": true,
      "params": [],
      "body": [
        { "name": "t0", "value": { "kind": "load_prop", "name": "x" } },
        { "name": "t1", "value": { "kind": "assert", "value": "t0" } }
      ]
    }
  ]
}`

func f223LoadUnbakedX(t *testing.T) *ir.ANFProgram {
	t.Helper()
	program, err := ir.LoadIRFromBytes([]byte(f223UnbakedXIR))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return program
}

func TestF223_CompileFromProgram_DoesNotMutateCallerProgram(t *testing.T) {
	shared := f223LoadUnbakedX(t)

	art1, err := CompileFromProgram(shared, CompileOptions{
		ConstructorArgs: map[string]interface{}{"x": big.NewInt(1)},
	})
	if err != nil {
		t.Fatalf("bake x=1: %v", err)
	}
	art2, err := CompileFromProgram(shared, CompileOptions{
		ConstructorArgs: map[string]interface{}{"x": big.NewInt(2)},
	})
	if err != nil {
		t.Fatalf("bake x=2: %v", err)
	}

	// The caller's own property must never have been written to.
	if shared.Properties[0].InitialValue != nil {
		t.Errorf("caller's program.Properties[0].InitialValue was mutated: got %#v, want nil",
			shared.Properties[0].InitialValue)
	}

	// Each call must have baked its own value, independently of the other.
	fresh1, err := CompileFromProgram(f223LoadUnbakedX(t), CompileOptions{
		ConstructorArgs: map[string]interface{}{"x": big.NewInt(1)},
	})
	if err != nil {
		t.Fatalf("fresh bake x=1: %v", err)
	}
	fresh2, err := CompileFromProgram(f223LoadUnbakedX(t), CompileOptions{
		ConstructorArgs: map[string]interface{}{"x": big.NewInt(2)},
	})
	if err != nil {
		t.Fatalf("fresh bake x=2: %v", err)
	}
	if art1.Script != fresh1.Script {
		t.Errorf("x=1 bake on shared program diverged from a fresh-program bake: %s vs %s", art1.Script, fresh1.Script)
	}
	if art2.Script != fresh2.Script {
		t.Errorf("x=2 bake on shared program diverged from a fresh-program bake: %s vs %s", art2.Script, fresh2.Script)
	}
	if art1.Script == art2.Script {
		t.Errorf("x=1 and x=2 bakes produced the same script: %s", art1.Script)
	}
}

func TestF223_CompileFromProgram_LaterNoArgsCallIsNotOrderDependent(t *testing.T) {
	shared := f223LoadUnbakedX(t)

	// Bake x=1 once.
	if _, err := CompileFromProgram(shared, CompileOptions{
		ConstructorArgs: map[string]interface{}{"x": big.NewInt(1)},
	}); err != nil {
		t.Fatalf("bake x=1: %v", err)
	}

	// A later call on the SAME object with no ConstructorArgs must compile
	// exactly like a fresh, never-baked program (OP_0 placeholder) — it must
	// not inherit the earlier bake via a mutated shared property.
	later, err := CompileFromProgram(shared, CompileOptions{})
	if err != nil {
		t.Fatalf("later unbaked compile: %v", err)
	}
	freshUnbaked, err := CompileFromProgram(f223LoadUnbakedX(t), CompileOptions{})
	if err != nil {
		t.Fatalf("fresh unbaked compile: %v", err)
	}
	if later.Script != freshUnbaked.Script {
		t.Errorf("later no-args call on a previously-baked shared program diverged from a fresh unbaked compile: %s vs %s",
			later.Script, freshUnbaked.Script)
	}
}
