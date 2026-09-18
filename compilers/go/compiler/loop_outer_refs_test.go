package compiler

// Port of the TypeScript reference test
// packages/runar-compiler/src/__tests__/loop-outer-refs.test.ts.
//
// Stack lowering across unrolled for-loops — outer-scope refs (method params,
// pre-loop consts) must survive loop unrolling:
//
//	(a) a const defined before a loop and referenced inside it (including only
//	    inside a nested if-branch) used to fail compilation with
//	    "Value 'X' not found on stack" — the first iteration consumed it;
//	(b) worse, a method PARAM referenced after an unrolled loop whose body also
//	    references it was silently lowered to an empty push (OP_0): compilation
//	    succeeded, the env-based interpreter passed, but the emitted Script
//	    failed at runtime (silent interpreter <-> Script divergence).
//
// The fix: lowerLoop collects outer refs deeply (nested branches included) and
// protects them in non-final iterations, and in the final iteration whenever
// the enclosing scope still references them after the loop. The old silent
// OP_0 fallbacks are now hard errors.

import (
	"strings"
	"testing"
)

const loopWalkSource = `import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class LoopWalk extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public walk(data: ByteString) {
    let off = 5n;
    for (let i = 0n; i < 3n; i++) {
      if (i < bin2num(cat(substr(data, 4n, 1n), this.pad00))) {
        const sl = bin2num(cat(substr(data, off + 36n, 1n), this.pad00));
        assert(sl < 253n);
        off = off + 36n + 1n + sl + 4n;
      }
    }
    const tail = bin2num(cat(substr(data, off, 1n), this.pad00));
    assert(tail === 7n);
  }
}
`

const constBeforeLoopSource = `import { SmartContract, assert, substr, cat, bin2num } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class ConstLoop extends SmartContract {
  readonly pad00: ByteString = "00" as ByteString;

  constructor() {
    super();
  }

  public probe(data: ByteString) {
    const base = 5n;
    let acc = 0n;
    for (let i = 0n; i < 3n; i++) {
      const b = bin2num(cat(substr(data, base + i, 1n), this.pad00));
      acc = acc + b;
    }
    assert(acc === 6n);
  }
}
`

// A loop-carried local REASSIGNED and then READ AGAIN in the same iteration.
// The rebinding shadows the incoming slot under the same name; the later read
// was its last body use, so it consumed the UPDATED value and left the dead
// incoming one for the next iteration to resolve. `wacc` came out as `step*N`
// instead of `step*N*(N+1)/2` — silently in a stateless contract, and as a
// permanently unspendable UTXO in a stateful one. Real-VM proof:
// packages/runar-testing/src/__tests__/loop-carried-local-read-after-reassign-vm.test.ts
const carriedRebindSource = `import { SmartContract, assert } from 'runar-lang';

class LoopCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
      wacc = wacc + acc;
    }
    assert(wacc === this.expected);
  }
}
`

// Control: the same loop with a single self-accumulating carrier — no read
// after the rebinding. Its bytes must NOT move, or the carried-rebind fix has
// been written too wide and every shipped BoundedLoop-shaped contract pays.
// R-186 / R-292 re-stamped this pin on 2026-09-14: the accumulator body leaves
// the carried local on top, so the iteration variable sat one slot down and
// `lowerLoop`'s `depth == 0` cleanup never fired. The control still says what it
// was written to say about the carried-rebind fix; it no longer pins the bytes
// that predate it.
const plainAccumulatorSource = `import { SmartContract, assert } from 'runar-lang';

class LoopPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      acc = acc + step;
    }
    assert(acc === this.expected);
  }
}
`

// The same cross-read one loop deeper. The predicate keys on the body's
// TOP-LEVEL binding names, and at the OUTER level `acc` is bound only inside
// the nested loop — so it was neither an outer ref nor a carried rebind, and
// every outer iteration restarted from the slot the previous one left behind.
// `wacc` came out 24 where the source says 30 (step = 3). Real-VM proof:
// packages/runar-testing/src/__tests__/nested-loop-carried-local-vm.test.ts
const nestedCarriedRebindSource = `import { SmartContract, assert } from 'runar-lang';

class LoopNestedCarriedRebind extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    let wacc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
        wacc = wacc + acc;
      }
    }
    assert(wacc === this.expected);
  }
}
`

// Control: NESTED loops with a single self-accumulating carrier. The flatten
// step fires here (the body does contain a nested loop) but the predicate still
// says "not carried", so the bytes must NOT move — that is what keeps nesting
// itself from costing anything.
// R-186 / R-292 re-stamped this pin on 2026-09-14 as well. Nesting still costs
// nothing — the single-level accumulator moved by exactly the same change.
const nestedPlainAccumulatorSource = `import { SmartContract, assert } from 'runar-lang';

class LoopNestedPlainAccumulator extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public verify(step: bigint) {
    let acc = 0n;
    for (let i = 0n; i < 2n; i++) {
      for (let j = 0n; j < 2n; j++) {
        acc = acc + step;
      }
    }
    assert(acc === this.expected);
  }
}
`

// Byte-identical across all seven compiler tiers (fold-OFF).
const carriedRebindHex = "000000537953797c937b78937b7551547a53797c937b7c9377009c7777"
const plainAccumulatorHex = "000052797b7c9377517b7b7c9377009c"
const nestedCarriedRebindHex = "00000000547954797c93537a78937b7551557953797c937b78937b75537a755100567954797c93537a78937b7551577a53797c937b7c93777b75009c77777777"
const nestedPlainAccumulatorHex = "0000005379537a7c93775153797b7c93777751005379537a7c937751537a7b7c937777009c"

func TestLoopCarriedRebind_SurvivesTheIteration(t *testing.T) {
	result := CompileFromSourceStrWithResult(carriedRebindSource, "LoopCarriedRebind.runar.ts",
		CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}
	if result.Artifact.Script != carriedRebindHex {
		t.Fatalf("carried-rebind hex mismatch\n  want %s\n  got  %s", carriedRebindHex, result.Artifact.Script)
	}
}

func TestLoopCarriedRebind_PlainAccumulatorUnchanged(t *testing.T) {
	result := CompileFromSourceStrWithResult(plainAccumulatorSource, "LoopPlainAccumulator.runar.ts",
		CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}
	if result.Artifact.Script != plainAccumulatorHex {
		t.Fatalf("plain-accumulator hex mismatch\n  want %s\n  got  %s", plainAccumulatorHex, result.Artifact.Script)
	}
}

func TestLoopCarriedRebind_NestedSurvivesTheIteration(t *testing.T) {
	result := CompileFromSourceStrWithResult(nestedCarriedRebindSource, "LoopNestedCarriedRebind.runar.ts",
		CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}
	if result.Artifact.Script != nestedCarriedRebindHex {
		t.Fatalf("nested carried-rebind hex mismatch\n  want %s\n  got  %s", nestedCarriedRebindHex, result.Artifact.Script)
	}
}

func TestLoopCarriedRebind_NestedPlainAccumulatorUnchanged(t *testing.T) {
	result := CompileFromSourceStrWithResult(nestedPlainAccumulatorSource, "LoopNestedPlainAccumulator.runar.ts",
		CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}
	if result.Artifact.Script != nestedPlainAccumulatorHex {
		t.Fatalf("nested plain-accumulator hex mismatch\n  want %s\n  got  %s", nestedPlainAccumulatorHex, result.Artifact.Script)
	}
}

func TestLoopOuterRefs_ParamAfterLoopIsNotEmptyPush(t *testing.T) {
	result := CompileFromSourceStrWithResult(loopWalkSource, "LoopWalk.runar.ts", CompileOptions{})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}

	// The post-loop code (after the last OP_ENDIF) reads `data` via
	// substr(data, off, 1n). With the bug, `data` was emitted as OP_0 right
	// after the final OP_ENDIF; the fixed code brings the real param up.
	asm := result.Artifact.ASM
	idx := strings.LastIndex(asm, "OP_ENDIF")
	if idx < 0 {
		t.Fatalf("expected the unrolled loop to emit at least one OP_ENDIF; asm:\n%s", asm)
	}
	postLoop := asm[idx:]
	if strings.Contains(postLoop, "OP_0") {
		t.Fatalf("post-loop region should not contain a silent OP_0 for the param; post-loop asm:\n%s", postLoop)
	}
}

func TestLoopOuterRefs_ConstBeforeLoopCompiles(t *testing.T) {
	// Previously: "Value 'base' not found on stack (...)".
	result := CompileFromSourceStrWithResult(constBeforeLoopSource, "ConstLoop.runar.ts", CompileOptions{})
	if !result.Success {
		t.Fatalf("compilation failed for a const referenced inside a loop: %v", result.Diagnostics)
	}
	if result.Artifact == nil || result.Artifact.Script == "" {
		t.Fatal("expected a compiled artifact with a script")
	}
}

func TestLoopOuterRefs_UnsatisfiableLoadParamIsHardError(t *testing.T) {
	// Hand-written ANF referencing a parameter the method does not have — the
	// old code silently emitted OP_0 here.
	irJSON := `{
		"contractName": "Broken",
		"properties": [],
		"methods": [{
			"name": "run",
			"isPublic": true,
			"params": [{"name": "x", "type": "bigint"}],
			"body": [
				{"name": "t0", "value": {"kind": "load_param", "name": "ghost"}},
				{"name": "t1", "value": {"kind": "assert", "value": "t0"}}
			]
		}]
	}`

	_, err := CompileFromIRBytes([]byte(irJSON))
	if err == nil {
		t.Fatal("expected a hard error for an unsatisfiable load_param, got nil")
	}
	if !strings.Contains(err.Error(), "Refusing to emit a silent OP_0") {
		t.Fatalf("expected a 'Refusing to emit a silent OP_0' error; got: %v", err)
	}
}
