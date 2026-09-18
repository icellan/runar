package main

import (
	"strings"
	"testing"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
)

// R-091 — the playground must compile with the OFFICIAL pipeline.
//
// `compileSource` ran ParseSource → Validate → TypeCheck → LowerToANF →
// LowerToStack → Emit by hand. The official pipeline additionally runs
// ExpandFixedArrays (pass 3b), constant folding, the EC optimizer, dead-binding
// elimination and the peephole pass, so the playground showed a script the real
// compiler would never emit.
//
// Measured before the fix, same source:
//
//	CLI         011293009c                                 5 bytes
//	playground  537c7c93547c7c93557c7c93567c7c93007c7c9c  20 bytes
//
// The playground is where people learn what Rúnar compiles to, and a
// FixedArray contract would not merely differ — with pass 3b missing it
// cannot lower at all.
//
// These tests compare the playground path against the library entry point the
// CLI uses, so the two cannot drift apart again.

const foldSensitiveSource = `import { SmartContract, assert } from 'runar-lang';

export class FoldSensitive extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(seed: bigint) {
    let acc: bigint = seed;
    for (let i = 3n; i < 7n; i++) { acc = acc + i; }
    assert(acc === this.target);
  }
}`

const fixedArraySource = `import { SmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class ArrayRead extends SmartContract {
  readonly table: FixedArray<bigint, 4> = [10n, 20n, 30n, 40n];
  constructor() { super(); }
  public lookup(i: bigint, expected: bigint) {
    assert(this.table[i] === expected);
  }
}`

const p2pkhSource = `import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { Addr, PubKey, Sig } from 'runar-lang';

export class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}`

func officialHex(t *testing.T, source, fileName string) string {
	t.Helper()
	result := gocompiler.CompileFromSourceStrWithResult(source, fileName)
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.Message)
		}
		t.Fatalf("official pipeline failed for %s: %s", fileName, strings.Join(msgs, "; "))
	}
	return result.ScriptHex
}

func TestPlaygroundMatchesOfficialPipeline_FoldSensitive(t *testing.T) {
	want := officialHex(t, foldSensitiveSource, "FoldSensitive.runar.ts")
	got, _, _, err := compileSource([]byte(foldSensitiveSource), "FoldSensitive.runar.ts")
	if err != nil {
		t.Fatalf("playground compile failed: %v", err)
	}
	if got != want {
		t.Errorf("playground hex diverges from the CLI on a FOLD-SENSITIVE contract.\n"+
			"  playground: %s (%d bytes)\n"+
			"  official:   %s (%d bytes)\n"+
			"The playground is where people read what Rúnar compiles to; showing an "+
			"unoptimised script teaches the wrong thing about the size and shape of "+
			"the real output.", got, len(got)/2, want, len(want)/2)
	}
}

func TestPlaygroundMatchesOfficialPipeline_FixedArray(t *testing.T) {
	want := officialHex(t, fixedArraySource, "ArrayRead.runar.ts")
	got, _, _, err := compileSource([]byte(fixedArraySource), "ArrayRead.runar.ts")
	if err != nil {
		t.Fatalf("playground compile failed — pass 3b (ExpandFixedArrays) is what "+
			"turns a FixedArray property into scalar slots, so without it this "+
			"contract does not lower at all: %v", err)
	}
	if got != want {
		t.Errorf("playground hex diverges from the CLI on a FIXEDARRAY contract.\n"+
			"  playground: %s\n  official:   %s", got, want)
	}
}

func TestPlaygroundMatchesOfficialPipeline_P2PKH(t *testing.T) {
	// The canonical contract. It has nothing for the optimizers to do, so it is
	// the control: if this one ever differs, the divergence is not about passes.
	want := officialHex(t, p2pkhSource, "P2PKH.runar.ts")
	got, _, _, err := compileSource([]byte(p2pkhSource), "P2PKH.runar.ts")
	if err != nil {
		t.Fatalf("playground compile failed: %v", err)
	}
	if got != want {
		t.Errorf("playground hex diverges from the CLI on P2PKH.\n  playground: %s\n  official:   %s", got, want)
	}
}
