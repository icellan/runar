package runar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// R3-COMPILECHECK-VK: CompileCheck has no vk.json, so a method that calls
// AssertGroth16WitnessAssistedWithMSM and binds its statement only through
// the vk.json's pinnedPublicInputs is refused there (R2-MSM-UNBOUND), while
// the compiler accepts it with --groth16-wa-vk. CompileCheckWithGroth16VK
// runs the same frontend with the vk.json the contract will be compiled with.
//
// Proves: RollupGroth16WA (integration/go/contracts) passes the frontend with
// the pinned SP1 v6.0.0 vk.json the integration test compiles it with, is
// refused with the R2-MSM-UNBOUND diagnostic with the unpinned vk.json, and
// plain CompileCheck still refuses it with the same diagnostic.
// Does not prove: that the compiled script verifies a proof (the regtest
// integration test groth16_wa_stateful_test.go covers that).

func compileCheckRepoPath(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("%s not found: %v", p, err)
	}
	return p
}

// pinnedSP1V6VK writes the SP1 v6.0.0 vk.json with pinnedPublicInputs fixing
// slots 0, 2 and 3 to the fixture's values (the same pins
// integration/go/groth16_wa_stateful_test.go writePinnedSP1V6VK writes).
func pinnedSP1V6VK(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(compileCheckRepoPath(t, "tests/vectors/sp1/v6.0.0/vk.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vk map[string]json.RawMessage
	if err := json.Unmarshal(raw, &vk); err != nil {
		t.Fatal(err)
	}
	if _, has := vk["pinnedPublicInputs"]; has {
		t.Fatal("fixture vk.json already pins public inputs; the unpinned case would be vacuous")
	}
	pubs, err := bn254witness.LoadSP1PublicInputs(compileCheckRepoPath(t, "tests/vectors/sp1/v6.0.0/groth16_public_inputs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{}
	for _, i := range []int{0, 2, 3} {
		pins[strconv.Itoa(i)] = pubs[i].String()
	}
	pinsJSON, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	vk["pinnedPublicInputs"] = pinsJSON
	out, err := json.Marshal(vk)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "vk.pinned.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCompileCheckWithGroth16VK_PinnedVKBindsStatement(t *testing.T) {
	src := compileCheckRepoPath(t, "integration/go/contracts/RollupGroth16WA.runar.go")
	if err := CompileCheckWithGroth16VK(src, pinnedSP1V6VK(t)); err != nil {
		t.Fatalf("RollupGroth16WA with its pinned vk.json must pass the frontend check: %v", err)
	}
}

func TestCompileCheckWithGroth16VK_UnpinnedVKRefused(t *testing.T) {
	src := compileCheckRepoPath(t, "integration/go/contracts/RollupGroth16WA.runar.go")
	unpinned := compileCheckRepoPath(t, "tests/vectors/sp1/v6.0.0/vk.json")
	err := CompileCheckWithGroth16VK(src, unpinned)
	if err == nil {
		t.Fatal("RollupGroth16WA with an unpinned vk.json binds no statement and must be refused")
	}
	want := frontend.Groth16WAUnboundStatementMessage("advanceState")
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("want the R2-MSM-UNBOUND diagnostic %q, got: %v", want, err)
	}
}

func TestCompileCheckWithGroth16VK_UnreadableVK(t *testing.T) {
	src := compileCheckRepoPath(t, "integration/go/contracts/RollupGroth16WA.runar.go")
	missing := filepath.Join(t.TempDir(), "no-such-vk.json")
	err := CompileCheckWithGroth16VK(src, missing)
	if err == nil || !strings.Contains(err.Error(), "loading Groth16WAVKey") || !strings.Contains(err.Error(), "no-such-vk.json") {
		t.Fatalf("want a vk.json load error naming the path, got: %v", err)
	}
}

// Plain CompileCheck is unchanged: with no vk.json it cannot see the pins, so
// the vk-bound contract is refused with the R2-MSM-UNBOUND diagnostic.
func TestCompileCheck_NoVKStillRefusesVKBoundMethod(t *testing.T) {
	src := compileCheckRepoPath(t, "integration/go/contracts/RollupGroth16WA.runar.go")
	err := CompileCheck(src)
	want := frontend.Groth16WAUnboundStatementMessage("advanceState")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want CompileCheck to refuse with %q, got: %v", want, err)
	}
}

// A contract that binds its statement in the body passes both checks.
func TestCompileCheck_BodyBoundMethodPassesBoth(t *testing.T) {
	src := compileCheckRepoPath(t, "integration/go/contracts/RollupGroth16WAMSM.runar.go")
	if err := CompileCheck(src); err != nil {
		t.Fatalf("CompileCheck(RollupGroth16WAMSM): %v", err)
	}
	if err := CompileCheckWithGroth16VK(src, compileCheckRepoPath(t, "tests/vectors/sp1/v6.0.0/vk.json")); err != nil {
		t.Fatalf("CompileCheckWithGroth16VK(RollupGroth16WAMSM, unpinned): %v", err)
	}
}
