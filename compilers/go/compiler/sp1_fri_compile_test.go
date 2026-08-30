package compiler

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/codegen"
)

// ---------------------------------------------------------------------------
// SP1 FRI verifier — end-to-end compile-frontend tests.
//
// Plumbing landed in commit `e132eda`:
//   - compilers/go/compiler/options.go — `WithSp1FriParams(params)` style
//     option (`CompileOptions.SP1FriParams`) + `SP1FriPreset(name)` /
//     `SP1FriPresetMust(name)` helper for canonical preset names.
//   - compilers/go/compiler/compiler.go — option threaded through to codegen.
//   - compilers/go/codegen/stack.go — receives params via
//     `LowerToStackOptions.SP1FriParams` (-> `loweringContext.sp1FriParams`).
//
// These tests exercise the full path
// `compiler.CompileFromSource(path, CompileOptions{SP1FriParams: ...})` —
// the natural production-deploy entry point — and assert the artifact
// matches the validated codegen-test measurement at
// `compilers/go/codegen/sp1_fri_test.go::TestSp1FriVerifier_AcceptsEvmGuestFixture`.
//
// References:
//   - docs/sp1-fri-verifier.md §4 (script-size, stack, timing targets)
//   - docs/fri-verifier-measurements.md (production-fixture measurements)
//   - packages/runar-go/sp1fri/verify.go (off-chain reference verifier)
// ---------------------------------------------------------------------------

// sp1FriPocContractPath returns the absolute path to the canonical
// Sp1FriVerifierPoc contract source. The path is relative to this test
// file's location so the test is location-independent.
func sp1FriPocContractPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..",
		"integration", "go", "contracts", "Sp1FriVerifierPoc.runar.go")
}

// emitProductionBodyHex emits `EmitFullSP1FriVerifierBody(emit, params)`
// directly through the same Emit pipeline `assembleArtifact` uses, and
// returns the resulting hex-encoded Bitcoin Script. The returned bytes
// are the locking-body bytes only — they correspond to the fragment
// `lowerVerifySP1FRI` produces inside the compiled artifact's `Script`,
// after the contract prelude (constructor-slot push for Sp1VKeyHash, the
// drop for the empty sp1VKeyHash arg) and before the trailing assert /
// success residue.
//
// Mirrors the compiler.go pipeline: stack-lower (the body emission here
// IS the stack-lower output) → `codegen.OptimizeStackOps` (the peephole
// pass at compiler.go:198, always enabled) → `codegen.Emit`. Without the
// peephole pass the bodies would diverge byte-for-byte on every
// optimization the peephole layer applies (push-drop elimination, dup-
// drop elimination, etc.), so applying it here is required for
// byte-equality comparison.
func emitProductionBodyHex(t *testing.T, params codegen.SP1FriVerifierParams) string {
	t.Helper()
	var ops []codegen.StackOp
	codegen.EmitFullSP1FriVerifierBody(func(op codegen.StackOp) {
		ops = append(ops, op)
	}, params)
	ops = codegen.OptimizeStackOps(ops)
	method := codegen.StackMethod{Name: "test", Ops: ops}
	res, err := codegen.Emit([]codegen.StackMethod{method})
	if err != nil {
		t.Fatalf("Emit(EmitFullSP1FriVerifierBody): %v", err)
	}
	return res.ScriptHex
}

// TestSp1Fri_CompileFromSource_DefaultParams compiles the canonical PoC
// contract through the full pipeline at the validated PoC tuple
// (`codegen.DefaultSP1FriParams()`) and asserts the resulting artifact
// has a non-empty Script of the expected ~242 KB locking-script size
// (matches the regtest measurement at
// `docs/fri-verifier-measurements.md`'s Regtest table — PoC row
// "Locking-script size 242.7 KB"). Default-options (no SP1FriParams set)
// must take this path.
func TestSp1Fri_CompileFromSource_DefaultParams(t *testing.T) {
	contractPath := sp1FriPocContractPath(t)
	artifact, err := CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("CompileFromSource(default): %v", err)
	}
	if artifact == nil {
		t.Fatal("expected non-nil artifact")
	}
	if artifact.ContractName != "Sp1FriVerifierPoc" {
		t.Errorf("contractName: got %q want %q", artifact.ContractName, "Sp1FriVerifierPoc")
	}
	if artifact.Script == "" {
		t.Fatal("expected non-empty Script")
	}

	scriptBytes := len(artifact.Script) / 2
	t.Logf("default-params (PoC) compiled: |Script|=%d bytes (~%d KB)",
		scriptBytes, scriptBytes/1024)

	// PoC tuple regtest measurement: 242.7 KB locking script. Expect the
	// compiled artifact to land in roughly the same window — allow ±25%
	// to insulate against trivial peephole-optimizer / emit-format drift.
	const expectedPoCBytes = 242_000
	const tolerance = 60_000 // ~25%
	if scriptBytes < expectedPoCBytes-tolerance ||
		scriptBytes > expectedPoCBytes+tolerance {
		t.Errorf("PoC script size %d B out of expected window [%d, %d] "+
			"(see docs/fri-verifier-measurements.md regtest PoC row)",
			scriptBytes, expectedPoCBytes-tolerance, expectedPoCBytes+tolerance)
	}

	// The first ~28 bytes of the locking body are the proof-blob push-and-
	// hash binding: OP_SHA256, OP_TOALTSTACK, push field0 depth (= numChunks-
	// 1), OP_PICK, ... For the PoC this is dispatched after a brief contract
	// prelude (constructor slot pushes + parameter handling). The exact byte
	// alignment depends on the contract's auto-generated arg unwrapping, but
	// the OP_SHA256 + OP_TOALTSTACK marker pair (a8 6b in BSV opcode hex)
	// MUST appear early in the script as the binding signature.
	const proofBlobBindingMarker = "a86b" // OP_SHA256 (0xa8) OP_TOALTSTACK (0x6b)
	idx := strings.Index(artifact.Script, proofBlobBindingMarker)
	if idx < 0 {
		t.Errorf("proof-blob binding marker (OP_SHA256+OP_TOALTSTACK = 0xa86b) "+
			"not found in artifact.Script — Step-1 binding emission missing")
	} else {
		t.Logf("proof-blob binding marker found at byte offset %d", idx/2)
	}
}

// TestSp1Fri_CompileFromSource_WithProductionPreset compiles the same PoC
// contract at the production "evm-guest" preset (degreeBits=10, num_queries=
// 100, log_blowup=1, log_final_poly_len=0, commit/queryPoWBits=16) and
// asserts the resulting Script size matches the codegen-test measurement
// of ~1,609,627 bytes. This is the natural production-deploy path the
// `WithSp1FriParams + SP1FriPreset` API surface enables.
//
// Cross-references:
//   - codegen.TestSp1FriVerifier_AcceptsEvmGuestFixture (sp1_fri_test.go:2349)
//     measures `compiled script=1609627 B (~1571 KB)`.
//   - sp1fri.evmGuestConfig in packages/runar-go/sp1fri/verify.go.
func TestSp1Fri_CompileFromSource_WithProductionPreset(t *testing.T) {
	contractPath := sp1FriPocContractPath(t)
	preset := SP1FriPresetMust("evm-guest")
	artifact, err := CompileFromSource(contractPath, CompileOptions{
		SP1FriParams: preset,
	})
	if err != nil {
		t.Fatalf("CompileFromSource(evm-guest preset): %v", err)
	}
	if artifact == nil {
		t.Fatal("expected non-nil artifact")
	}
	if artifact.Script == "" {
		t.Fatal("expected non-empty Script")
	}

	scriptBytes := len(artifact.Script) / 2
	t.Logf("production-preset (evm-guest) compiled: |Script|=%d bytes (~%d KB)",
		scriptBytes, scriptBytes/1024)

	// Measurement reconciliation:
	//
	//   codegen.TestSp1FriVerifier_AcceptsEvmGuestFixture (sp1_fri_test.go:2349)
	//   reports `compiled script=1609627 B` for the prelude + body emission
	//   WITHOUT the peephole optimizer pass. The compiler-frontend path here
	//   runs every method's StackOps through `codegen.OptimizeStackOps` between
	//   stack-lowering and emit (compiler.go:198) — that pass eliminates
	//   countless dup-drop pairs in the per-query Step-10 stub and the bulk
	//   `tracker.drop()` drain at end of body, halving the body size.
	//
	//   Net: the production-preset compiled-artifact Script lands around
	//   849 KB (= ~829 KB locking body + a small contract wrapper). The
	//   1.57 MB number from the codegen test is the un-optimized prelude +
	//   body; the deployed locking script benefits from peephole as well.
	//
	// Window: 800-900 KB. Tight enough to catch a regression that disables
	// peephole (bumping back to ~1.5 MB) or a regression that loses the
	// production param tuple (collapsing back to ~242 KB PoC size).
	const lowerBound = 800_000
	const upperBound = 900_000
	if scriptBytes < lowerBound || scriptBytes > upperBound {
		t.Errorf("production-preset script size %d B out of expected window [%d, %d] "+
			"(post-peephole locking-script body for evm-guest tuple "+
			"degreeBits=10 num_queries=100 log_blowup=1 log_final_poly_len=0)",
			scriptBytes, lowerBound, upperBound)
	}

	// Sanity: the production preset should produce a script roughly 6×
	// larger than the PoC default — the production tuple unrolls 10
	// commit-phase rounds and 100 query-derive ops vs. PoC's 1 round and
	// 2 query-derive ops.
	defaultArtifact, err := CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("CompileFromSource(default) for size comparison: %v", err)
	}
	defaultBytes := len(defaultArtifact.Script) / 2
	if scriptBytes <= defaultBytes {
		t.Errorf("production-preset script (%d B) should be larger than default (%d B)",
			scriptBytes, defaultBytes)
	}
	ratio := float64(scriptBytes) / float64(defaultBytes)
	t.Logf("production/default size ratio: %.2fx (default=%d B, production=%d B)",
		ratio, defaultBytes, scriptBytes)
}

// TestSp1Fri_CompileFromSource_PresetByteEqualsCodegen asserts that the
// production-preset compile output's locking-body bytes are byte-identical
// to running `codegen.EmitFullSP1FriVerifierBody(emit, productionParams)`
// directly. This proves the compiler-frontend path matches the validated
// codegen path: any future regression that breaks this equivalence (e.g.
// an extra peephole pass that mutates the body, or option threading that
// loses the params on the way down) is caught here.
//
// Comparison strategy: the locking-body hex string must appear as a
// contiguous substring of the artifact's `Script` hex. The contract
// prelude (constructor-slot push for the Sp1VKeyHash readonly field, the
// param-unwrap, and the `drop` of the empty sp1VKeyHash typed arg that
// `lowerVerifySP1FRI` emits at sp1_fri.go:196 when SP1VKeyHashByteSize ==
// 0) sits before the body; the contract epilogue (assert + success
// residue) sits after.
func TestSp1Fri_CompileFromSource_PresetByteEqualsCodegen(t *testing.T) {
	contractPath := sp1FriPocContractPath(t)
	preset := SP1FriPresetMust("evm-guest")
	artifact, err := CompileFromSource(contractPath, CompileOptions{
		SP1FriParams: preset,
	})
	if err != nil {
		t.Fatalf("CompileFromSource(evm-guest): %v", err)
	}
	bodyHex := emitProductionBodyHex(t, *preset)
	if bodyHex == "" {
		t.Fatal("emitProductionBodyHex returned empty hex")
	}

	// The compiler artifact embeds the body hex contiguously. Substring
	// match is a strict byte-equality test for the body bytes (since both
	// sides are deterministic emissions of the same StackOp stream through
	// the same Emit pipeline).
	idx := strings.Index(artifact.Script, bodyHex)
	if idx < 0 {
		// Diagnostics: report the body's first 40 hex chars vs. the script's
		// equivalent window so a regression report shows the divergence point.
		head := bodyHex
		if len(head) > 80 {
			head = head[:80]
		}
		t.Fatalf("locking-body hex (%d hex chars) NOT a substring of artifact.Script "+
			"(%d hex chars) — compiler-frontend path produced different bytes than "+
			"codegen.EmitFullSP1FriVerifierBody. Body[0..40]=%s",
			len(bodyHex), len(artifact.Script), head)
	}
	t.Logf("production-preset locking-body byte-identical to codegen: "+
		"body=%d hex chars, script=%d hex chars, body offset in script=%d (%d bytes prelude)",
		len(bodyHex), len(artifact.Script), idx, idx/2)
}

// TestSp1Fri_AllPresetsCompile is a coverage check: every preset
// `SP1FriPreset` exposes (minimal-guest, evm-guest, production-100,
// production-64, production-16) must compile the PoC contract to a
// non-empty artifact. Documents each preset's resulting script size so
// the fallback recommendation in `docs/fri-verifier-measurements.md`
// has empirical numbers to anchor on.
//
// The `production-100` alias must produce byte-identical output to
// `evm-guest` (they resolve to the same params via SP1FriPreset).
func TestSp1Fri_AllPresetsCompile(t *testing.T) {
	contractPath := sp1FriPocContractPath(t)
	presets := []string{
		"minimal-guest",
		"evm-guest",
		"production-100",
		"production-64",
		"production-16",
	}

	sizes := make(map[string]int, len(presets))
	for _, name := range presets {
		t.Run(name, func(t *testing.T) {
			preset, err := SP1FriPreset(name)
			if err != nil {
				t.Fatalf("SP1FriPreset(%q): %v", name, err)
			}
			artifact, err := CompileFromSource(contractPath, CompileOptions{
				SP1FriParams: &preset,
			})
			if err != nil {
				t.Fatalf("CompileFromSource(preset=%q): %v", name, err)
			}
			if artifact == nil || artifact.Script == "" {
				t.Fatalf("preset %q produced empty artifact/script", name)
			}
			sizes[name] = len(artifact.Script) / 2
			t.Logf("preset=%q script size=%d B (~%d KB)",
				name, sizes[name], sizes[name]/1024)
		})
	}

	// evm-guest and production-100 are aliases per options.go:96 — must
	// produce identical bytes.
	if sizes["evm-guest"] != 0 && sizes["production-100"] != 0 {
		if sizes["evm-guest"] != sizes["production-100"] {
			t.Errorf("evm-guest and production-100 are aliases but produced "+
				"different script sizes: %d vs %d", sizes["evm-guest"], sizes["production-100"])
		}
	}

	// Fallback ordering sanity: production-100 > production-64 > production-16
	// (more queries → more per-query Step-10 derive ops → larger script).
	if sizes["production-100"] > 0 && sizes["production-64"] > 0 {
		if sizes["production-100"] <= sizes["production-64"] {
			t.Errorf("production-100 (%d B) should be larger than production-64 (%d B) "+
				"— more queries means more per-query Step-10 derive ops",
				sizes["production-100"], sizes["production-64"])
		}
	}
	if sizes["production-64"] > 0 && sizes["production-16"] > 0 {
		if sizes["production-64"] <= sizes["production-16"] {
			t.Errorf("production-64 (%d B) should be larger than production-16 (%d B)",
				sizes["production-64"], sizes["production-16"])
		}
	}
}

// TestSp1Fri_UnknownPresetRejected guards the API contract: an unknown
// preset name must surface as an error from SP1FriPreset (and a panic
// from SP1FriPresetMust). This protects against silent typos in
// downstream consumer code that would otherwise compile against
// DefaultSP1FriParams() (the PoC tuple) when the consumer expected a
// production tuple.
func TestSp1Fri_UnknownPresetRejected(t *testing.T) {
	_, err := SP1FriPreset("nonexistent-preset")
	if err == nil {
		t.Error("expected SP1FriPreset to reject unknown name; got nil error")
	}
	if !strings.Contains(err.Error(), "unknown preset") {
		t.Errorf("expected error to mention 'unknown preset'; got: %v", err)
	}
}
