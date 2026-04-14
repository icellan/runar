package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCLI_Groth16WA_SP1 builds the compilers/go binary, runs it with the
// `groth16-wa` subcommand against the SP1 v6.0.0 fixture, and verifies the
// resulting artifact has the expected shape. This is the end-to-end smoke
// test for the CLI wrapping.
//
// The build + invocation together take under 10s on a modern machine; the
// 700 KB emit is the dominant cost. The test relies on `go build` being
// on PATH, which is guaranteed in any environment `go test` runs in.
func TestCLI_Groth16WA_SP1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CLI smoke test on -short")
	}

	// 1. Resolve fixture VK path relative to compilers/go/ (this file's
	//    package CWD during `go test`).
	vkAbs, err := filepath.Abs(filepath.Join("..", "..", "tests", "vectors", "sp1", "v6.0.0", "vk.json"))
	if err != nil {
		t.Fatalf("resolve VK path: %v", err)
	}
	if _, err := os.Stat(vkAbs); err != nil {
		t.Fatalf("fixture VK missing at %s: %v", vkAbs, err)
	}

	// 2. Build the CLI binary into a temp dir. We use `go build .`
	//    inside compilers/go so the module resolution matches what
	//    end-users actually do from the repo.
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "runar-compiler-go")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "." // compilers/go (main package's directory)
	buildOutput, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, string(buildOutput))
	}

	// 3. Invoke the binary as `runar-compiler-go groth16-wa --vk ... --out ...`.
	outPath := filepath.Join(tmp, "sp1.runar.json")
	cmd = exec.Command(binPath, "groth16-wa",
		"--vk", vkAbs,
		"--out", outPath,
		"--name", "SP1Verifier_CLI_Smoke",
	)
	runOutput, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI run failed: %v\n%s", err, string(runOutput))
	}

	// 4. Assert the output file exists, is valid JSON, and has the
	//    expected structural properties.
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output artifact: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse output artifact JSON: %v", err)
	}

	script, _ := parsed["script"].(string)
	if len(script) == 0 {
		t.Fatal("artifact script is empty")
	}
	// Script hex is 2 chars per byte; >600 KB is the lower bound for the
	// witness-assisted verifier with ModuloThreshold=0.
	scriptBytes := len(script) / 2
	if scriptBytes < 600*1024 {
		t.Errorf("script too small: %d bytes (expected > 600 KB)", scriptBytes)
	}

	name, _ := parsed["contractName"].(string)
	if name != "SP1Verifier_CLI_Smoke" {
		t.Errorf("contractName = %q, want %q", name, "SP1Verifier_CLI_Smoke")
	}

	waRaw, ok := parsed["groth16WA"].(map[string]interface{})
	if !ok {
		t.Fatalf("groth16WA missing in CLI output")
	}
	if np, _ := waRaw["numPubInputs"].(float64); int(np) != 5 {
		t.Errorf("numPubInputs = %v, want 5", waRaw["numPubInputs"])
	}
	if digest, _ := waRaw["vkDigest"].(string); len(digest) != 64 {
		t.Errorf("vkDigest length %d, want 64", len(digest))
	}

	t.Logf("CLI produced %d byte script (%.1f KB); stderr:\n%s",
		scriptBytes, float64(scriptBytes)/1024, string(runOutput))
}
