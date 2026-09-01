package compiler

import "testing"

// Issue #123 — mode-aware codegen parity with the TypeScript reference tier.
// Golden scripts are the TS compiler's fold-OFF output; the Go tier must be
// byte-identical.

func counterOut(directive string) string {
	return `
  class Counter extends StatefulSmartContract {
    n: bigint;
    constructor(n: bigint) { super(n); this.n = n; }
    ` + directive + `
    public bump(): void { this.addOutput(1000n, this.n); }
  }
`
}

func fund(directive string) string {
	return `
  class Fund extends StatefulSmartContract {
    raised: bigint;
    constructor(raised: bigint) { super(raised); this.raised = raised; }
    ` + directive + `
    public pledge(amount: bigint): void { this.raised = this.raised + amount; }
  }
`
}

func compileOK(t *testing.T, src, fileName string) *CompileResult {
	t.Helper()
	r := CompileFromSourceStrWithResult(src, fileName, CompileOptions{DisableConstantFolding: true})
	if !r.Success {
		t.Fatalf("compile failed: %v", diagMessages(r))
	}
	return r
}

func abiSigHash(r *CompileResult, method string) *int {
	for _, m := range r.Artifact.ABI.Methods {
		if m.Name == method {
			return m.SigHashType
		}
	}
	return nil
}

// TS-reference golden scripts (fold-OFF).
const (
	counterDefaultScript = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778101419d7601687f7782012c947f758258947f758258947f778102e803785679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777"
	counterSingleScript  = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01437e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778101439d7601687f7782012c947f758258947f758258947f778102e803785679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777"
	fundAcpScript        = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01c17e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778102c1009d7601687f7782012c947f758258947f758258947f778176567a9377547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777"
)

func TestSighashCodegen_DefaultEqualsExplicitAllForkID(t *testing.T) {
	dflt := compileOK(t, counterOut(""), "Counter.runar.ts")
	allExplicit := compileOK(t, counterOut("/** @sighash ALL|FORKID */"), "Counter.runar.ts")
	if dflt.ScriptHex != counterDefaultScript {
		t.Fatalf("default script != TS golden:\n got %s\nwant %s", dflt.ScriptHex, counterDefaultScript)
	}
	// ALL|FORKID must be byte-identical to no directive (and carry no ABI mode).
	if allExplicit.ScriptHex != dflt.ScriptHex {
		t.Fatalf("explicit ALL|FORKID diverges from default script")
	}
	if abiSigHash(allExplicit, "bump") != nil {
		t.Fatalf("explicit ALL|FORKID must omit ABI sigHashType")
	}
}

func TestSighashCodegen_SingleForkIDByteIdenticalToTS(t *testing.T) {
	single := compileOK(t, counterOut("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts")
	if single.ScriptHex != counterSingleScript {
		t.Fatalf("SINGLE|FORKID script != TS golden:\n got %s\nwant %s", single.ScriptHex, counterSingleScript)
	}
	sig := abiSigHash(single, "bump")
	if sig == nil || *sig != 0x43 {
		t.Fatalf("ABI sigHashType = %v, want 0x43", sig)
	}
}

func TestSighashCodegen_AnyoneCanPayByteIdenticalToTS(t *testing.T) {
	acp := compileOK(t, fund("/** @sighash ALL|ANYONECANPAY|FORKID */"), "Fund.runar.ts")
	if acp.ScriptHex != fundAcpScript {
		t.Fatalf("ANYONECANPAY script != TS golden:\n got %s\nwant %s", acp.ScriptHex, fundAcpScript)
	}
	sig := abiSigHash(acp, "pledge")
	if sig == nil || *sig != 0xc1 {
		t.Fatalf("ABI sigHashType = %v, want 0xc1", sig)
	}
}

func TestSighashCodegen_DefaultHasNoAbiMode(t *testing.T) {
	dflt := compileOK(t, fund(""), "Fund.runar.ts")
	if abiSigHash(dflt, "pledge") != nil {
		t.Fatalf("default method must omit ABI sigHashType")
	}
}
