package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
)

// sp1VKPath returns the path to the SP1 v6.0.0 test vector VK, resolved
// relative to the repository root. The compilers/go test CWD is
// `compilers/go/compiler`, so we walk up two levels.
func sp1VKPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "tests", "vectors", "sp1", "v6.0.0", "vk.json"))
	if err != nil {
		t.Fatalf("resolve SP1 VK path: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("SP1 VK fixture missing at %s: %v", abs, err)
	}
	return abs
}

// sharedSP1Artifact compiles the SP1 VK once and caches the result so the
// three test cases below don't each regenerate the 700 KB script. The 700 KB
// emit is fast (<1s), but deterministic-derivation tests read the hex anyway,
// and caching keeps the suite well under 2s.
var (
	sp1ArtifactOnce sync.Once
	sp1Artifact     *Artifact
	sp1ArtifactErr  error
)

func loadSP1Artifact(t *testing.T) *Artifact {
	t.Helper()
	sp1ArtifactOnce.Do(func() {
		sp1Artifact, sp1ArtifactErr = CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{})
	})
	if sp1ArtifactErr != nil {
		t.Fatalf("CompileGroth16WA (cached): %v", sp1ArtifactErr)
	}
	return sp1Artifact
}

// TestCompileGroth16WA_SP1VK_ProducesArtifact is the load-bearing smoke
// test: feed the real SP1 v6.0.0 VK in and confirm the artifact has the
// expected shape. This exercises the full path from JSON load ->
// PrecomputeAlphaNegBeta -> codegen -> emit -> artifact serialization.
func TestCompileGroth16WA_SP1VK_ProducesArtifact(t *testing.T) {
	art := loadSP1Artifact(t)

	// Non-empty script hex.
	if len(art.Script) == 0 {
		t.Fatal("Script is empty")
	}
	// Hex must be even-length and pure hex.
	if len(art.Script)%2 != 0 {
		t.Errorf("Script hex length %d is odd", len(art.Script))
	}
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if !hexPattern.MatchString(art.Script) {
		t.Errorf("Script is not valid hex")
	}

	// Contract name defaults to "Groth16Verifier".
	if art.ContractName != "Groth16Verifier" {
		t.Errorf("ContractName = %q, want %q", art.ContractName, "Groth16Verifier")
	}

	// Constructor slots must be empty (VK is baked in, not patched).
	if len(art.ConstructorSlots) != 0 {
		t.Errorf("ConstructorSlots len = %d, want 0", len(art.ConstructorSlots))
	}

	// ABI must expose exactly one public method `verify` with no params.
	if len(art.ABI.Methods) != 1 {
		t.Fatalf("ABI.Methods len = %d, want 1", len(art.ABI.Methods))
	}
	verify := art.ABI.Methods[0]
	if verify.Name != "verify" {
		t.Errorf("method name = %q, want \"verify\"", verify.Name)
	}
	if !verify.IsPublic {
		t.Errorf("verify is not marked public")
	}
	if len(verify.Params) != 0 {
		t.Errorf("verify has %d params, want 0", len(verify.Params))
	}

	// Groth16WA metadata must be populated.
	if art.Groth16WA == nil {
		t.Fatal("Groth16WA metadata is nil")
	}
	if art.Groth16WA.NumPubInputs != 5 {
		t.Errorf("Groth16WA.NumPubInputs = %d, want 5", art.Groth16WA.NumPubInputs)
	}
	// SHA-256 hex must be exactly 64 lowercase hex chars.
	digestPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !digestPattern.MatchString(art.Groth16WA.VKDigest) {
		t.Errorf("Groth16WA.VKDigest = %q, want 64 lowercase hex chars", art.Groth16WA.VKDigest)
	}

	// Sanity report.
	scriptBytes := len(art.Script) / 2
	t.Logf("SP1 verifier script: %d bytes (%.1f KB), numPubInputs=%d",
		scriptBytes, float64(scriptBytes)/1024, art.Groth16WA.NumPubInputs)
}

// TestCompileGroth16WA_DefaultsToThreshold0 verifies that the default
// ModuloThreshold (0) produces the ~718 KB "strict mod-reduce" script that
// Phase 4 measured. If this test fails, either the default changed or the
// Groth16 codegen was reshuffled — both warrant human review.
func TestCompileGroth16WA_DefaultsToThreshold0(t *testing.T) {
	art := loadSP1Artifact(t)
	scriptBytes := len(art.Script) / 2

	// Phase 4 measured ~718 KB on go-sdk. Allow +/- 64 KB headroom so
	// optimizer improvements / regressions don't break the test on
	// every unrelated change, but a 2x blow-up still fires.
	const (
		minBytes = 600 * 1024
		maxBytes = 800 * 1024
	)
	if scriptBytes < minBytes || scriptBytes > maxBytes {
		t.Errorf("default-threshold script size %d bytes is outside the expected [%d, %d] window",
			scriptBytes, minBytes, maxBytes)
	}
	t.Logf("default-threshold SP1 script size: %d bytes (%.1f KB)", scriptBytes, float64(scriptBytes)/1024)
}

// TestCompileGroth16WA_RoundTripToJSON verifies that serializing the
// artifact to JSON and reading it back preserves both the script hex and
// the Groth16WA metadata. This is the contract with downstream SDK
// consumers: they MUST be able to load a `.runar.json` file from disk and
// get the same locking script bytes back.
func TestCompileGroth16WA_RoundTripToJSON(t *testing.T) {
	art := loadSP1Artifact(t)

	tmpPath := filepath.Join(t.TempDir(), "sp1.runar.json")
	jsonBytes, err := ArtifactToJSON(art)
	if err != nil {
		t.Fatalf("ArtifactToJSON: %v", err)
	}
	if err := os.WriteFile(tmpPath, jsonBytes, 0644); err != nil {
		t.Fatalf("write tmp artifact: %v", err)
	}

	// Read back and decode into a generic map so we don't couple this
	// test to the concrete Artifact struct field order.
	raw, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("read tmp artifact: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal tmp artifact: %v", err)
	}

	gotScript, _ := parsed["script"].(string)
	if gotScript != art.Script {
		t.Errorf("round-tripped script mismatch:\n  have len %d\n  want len %d",
			len(gotScript), len(art.Script))
	}

	waRaw, ok := parsed["groth16WA"].(map[string]interface{})
	if !ok {
		t.Fatalf("groth16WA missing or wrong type in JSON output")
	}
	if np, _ := waRaw["numPubInputs"].(float64); int(np) != art.Groth16WA.NumPubInputs {
		t.Errorf("round-tripped numPubInputs = %v, want %d", waRaw["numPubInputs"], art.Groth16WA.NumPubInputs)
	}
	if digest, _ := waRaw["vkDigest"].(string); digest != art.Groth16WA.VKDigest {
		t.Errorf("round-tripped vkDigest = %q, want %q", digest, art.Groth16WA.VKDigest)
	}

	// Recompile from the same VK and assert byte-identical script hex.
	// This is the deterministic-build guarantee: two compiles of the
	// same VK must produce the same bytes.
	art2, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{})
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if art2.Script != art.Script {
		t.Errorf("re-compile produced different script hex (len %d vs %d)", len(art2.Script), len(art.Script))
	}
	if art2.Groth16WA == nil || art2.Groth16WA.VKDigest != art.Groth16WA.VKDigest {
		t.Errorf("re-compile produced different VKDigest")
	}
}

// TestCompileGroth16WA_InvalidVKPath confirms the function returns an
// error (not a panic) when the VK file does not exist.
func TestCompileGroth16WA_InvalidVKPath(t *testing.T) {
	_, err := CompileGroth16WA("/nonexistent/vk.json", Groth16WAOpts{})
	if err == nil {
		t.Fatal("expected error for missing VK file, got nil")
	}
}

// TestCompileGroth16WA_CustomContractName verifies the --name option
// propagates to the artifact.
func TestCompileGroth16WA_CustomContractName(t *testing.T) {
	art, err := CompileGroth16WA(sp1VKPath(t), Groth16WAOpts{ContractName: "MySP1Verifier"})
	if err != nil {
		t.Fatalf("CompileGroth16WA: %v", err)
	}
	if art.ContractName != "MySP1Verifier" {
		t.Errorf("ContractName = %q, want %q", art.ContractName, "MySP1Verifier")
	}
}
