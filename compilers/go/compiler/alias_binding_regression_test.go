package compiler

import "testing"

// TestAliasBindingMultipleMethods reproduces a divergence the IR-based
// differential fuzzer surfaced between the Go compiler and the TS / Rust /
// Python / Zig / Ruby compilers.
//
// Minimal contract: two public methods (so method dispatch is emitted) and
// a method body that binds a parameter through two let-aliases before using
// it once:
//
//	public method9(a, b, c) {
//	  const x = b;
//	  const y = b;
//	  assert(x === y);
//	}
//
// The reference compilers emit `OVER ROT NUMEQUAL` for the body (dup b,
// rotate, compare). The Go compiler instead emits `0 0 0 NOT` — it throws
// the parameter references away and succeeds unconditionally on three push-0s.
//
// Expected hex (confirmed identical across ts / rust / python / zig / ruby
// via the IR differential fuzzer):
//
//	76009c6375787b9c67519d9168
//	|dispatch|method9|method7|
func TestAliasBindingMultipleMethods_MatchesReference(t *testing.T) {
	source := `import { SmartContract, assert } from 'runar-lang';

class Repro extends SmartContract {
  readonly flag: boolean;

  constructor(flag: boolean) {
    super(flag);
    this.flag = flag;
  }

  public method9(a: bigint, b: bigint, c: boolean): void {
    const x: bigint = b;
    const y: bigint = b;
    assert(x === y);
  }

  public method7(z: boolean): void {
    assert(!z);
  }
}
`

	const expectedHex = "76009c6375787b9c67519d9168"

	result := CompileFromSourceStrWithResult(source, "Repro.runar.ts", CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation failed: %v", result.Diagnostics)
	}
	if result.Artifact == nil {
		t.Fatal("no artifact produced")
	}
	if got := result.Artifact.Script; got != expectedHex {
		t.Fatalf("Go compiler output diverges from reference compilers:\n  got:  %s\n  want: %s\n  (asm: %s)",
			got, expectedHex, result.Artifact.ASM)
	}
}
