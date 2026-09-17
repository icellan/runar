package runar

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FixedArray state across the ANF-interpreter boundary (call path)
//
// Pass `03b-expand-fixed-arrays` runs BEFORE ANF lowering, so the ANF program
// has no property called `table` at all -- it has `table__0`..`table__3`, and
// every `load_prop` / `update_prop` in the method body names one of those. The
// SDK's user-facing `c.state`, by contrast, is keyed by the GROUPED name. Both
// directions of that boundary have to be bridged or the continuation output
// commits a state the method did not compute.
//
// Fixture: examples/ts/fixed-array-write/ArrayWrite.runar.ts --
// `table: FixedArray<bigint, 4> = [0n,0n,0n,0n]`, `bump(i)` doing
// `this.table[i]++`. Checked in at testdata/arraywrite-artifact.json, compiled
// with `--ir` so the artifact carries the ANF the call path needs; the
// conformance sdk-output fixture of the same contract has no `anf`, so
// ComputeNewStateAndDataOutputs is never reached through it and the defect does
// not reproduce there.
//
// Every test here runs on the DEFAULT validating MockProvider with a real
// LocalSigner, so each broadcast replays input 0 through the go-sdk script
// interpreter. A second call therefore has to satisfy the covenant that the
// first call's continuation committed -- the continuation bytes are load-
// bearing, not just asserted.
// ---------------------------------------------------------------------------

func loadArrayWriteArtifact(t *testing.T) *RunarArtifact {
	t.Helper()
	raw, err := os.ReadFile("testdata/arraywrite-artifact.json")
	if err != nil {
		t.Fatalf("reading ArrayWrite artifact: %v", err)
	}
	var artifact RunarArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("unmarshalling ArrayWrite artifact: %v", err)
	}
	if artifact.ANF == nil {
		t.Fatal("ArrayWrite artifact carries no ANF; the call path would never reach the interpreter")
	}
	return &artifact
}

// deployArrayWrite deploys the fixture and returns the contract plus the
// provider/signer the follow-up calls need.
func deployArrayWrite(t *testing.T) (*RunarContract, *MockProvider, Signer) {
	t.Helper()
	signer, err := NewLocalSigner("0000000000000000000000000000000000000000000000000000000000000007")
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	addr, err := signer.GetAddress()
	if err != nil {
		t.Fatalf("GetAddress: %v", err)
	}
	provider := NewMockProvider("testnet")
	provider.AddUtxo(addr, UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    1000000,
		Script:      BuildP2PKHScript(addr),
	})

	contract := NewRunarContract(loadArrayWriteArtifact(t), nil)
	if _, _, err := contract.Deploy(provider, signer, DeployOptions{Satoshis: 50000}); err != nil {
		t.Fatalf("Deploy error: %v", err)
	}
	return contract, provider, signer
}

// stateTailHex returns the state data section of a locking script: the 32 bytes
// after the final OP_RETURN (`6a`) separator that carry the
// `FixedArray<bigint, 4>` payload.
func stateTailHex(t *testing.T, scriptHex string) string {
	t.Helper()
	const stateNibbles = 4 * 8 * 2 // 4 leaves * 8 bytes * 2 hex chars
	if len(scriptHex) < stateNibbles+2 {
		t.Fatalf("locking script too short to carry a 32-byte state section: %d bytes", len(scriptHex)/2)
	}
	sep := scriptHex[len(scriptHex)-stateNibbles-2 : len(scriptHex)-stateNibbles]
	if sep != "6a" {
		t.Fatalf("expected OP_RETURN (6a) before the 32-byte state section, found %q", sep)
	}
	return scriptHex[len(scriptHex)-stateNibbles:]
}

// leHex renders leaf values as the contract's on-chain state bytes:
// little-endian 8-byte words, one per leaf.
func leHex(vals ...int64) string {
	var b strings.Builder
	for _, v := range vals {
		for i := 0; i < 8; i++ {
			b.WriteString(fmt.Sprintf("%02x", byte(v>>(8*i))))
		}
	}
	return b.String()
}

// groupedTable reads the user-facing grouped state entry as int64s.
func groupedTable(t *testing.T, state map[string]interface{}) []int64 {
	t.Helper()
	raw, ok := state["table"]
	if !ok {
		t.Fatal("state has no grouped `table` entry")
	}
	items, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("grouped `table` is %T, want []interface{}", raw)
	}
	out := make([]int64, len(items))
	for i, it := range items {
		switch v := it.(type) {
		case *big.Int:
			out[i] = v.Int64()
		case int64:
			out[i] = v
		case int:
			out[i] = int64(v)
		case string:
			// A grouped entry still holding the artifact's `initialValue`
			// is the compiler's `"0n"` literal form.
			n, ok := new(big.Int).SetString(strings.TrimSuffix(v, "n"), 10)
			if !ok {
				t.Fatalf("grouped `table`[%d] is the unparseable string %q", i, v)
			}
			out[i] = n.Int64()
		default:
			t.Fatalf("grouped `table`[%d] is %T, want a numeric value", i, it)
		}
	}
	return out
}

func assertTable(t *testing.T, label string, got []int64, want ...int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: grouped state has %d leaves, want %d (%v)", label, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: grouped state got %v, want %v", label, got, want)
		}
	}
}

// TestFixedArrayCall_Outbound_ContinuationCommitsNewState pins the OUTBOUND
// half: the post-call state the interpreter computed under the SYNTHETIC leaf
// names has to reach BOTH the continuation output's state section and the
// grouped user-facing `table` entry. A stale grouped entry is a state lie to
// every caller of GetState(), and it leaves the continuation bytes depending
// entirely on SerializeState's synthetic-key preference.
func TestFixedArrayCall_Outbound_ContinuationCommitsNewState(t *testing.T) {
	contract, provider, signer := deployArrayWrite(t)

	deployed := contract.GetCurrentUtxo().Script
	if got, want := len(deployed)/2, 884; got != want {
		t.Fatalf("deployed locking script: got %d bytes, want %d", got, want)
	}
	if got, want := stateTailHex(t, deployed), leHex(0, 0, 0, 0); got != want {
		t.Fatalf("deployed state section: got %s, want %s", got, want)
	}

	if _, _, err := contract.Call("bump", []interface{}{big.NewInt(0)}, provider, signer, nil); err != nil {
		t.Fatalf("Call(bump, 0) error: %v", err)
	}

	cont := contract.GetCurrentUtxo().Script
	if got, want := len(cont)/2, 884; got != want {
		t.Fatalf("continuation locking script: got %d bytes, want %d", got, want)
	}
	if got, want := stateTailHex(t, cont), leHex(1, 0, 0, 0); got != want {
		t.Fatalf("continuation state section: got %s, want %s (the continuation committed a state the method did not compute)", got, want)
	}
	assertTable(t, "after bump(0)", groupedTable(t, contract.GetState()), 1, 0, 0, 0)
}

// TestFixedArrayCall_Inbound_AccumulatesAcrossCalls pins the INBOUND half: the
// interpreter must see the CURRENT value of each leaf. If the grouped entry is
// never spread over the synthetic names, `this.table[i]++` evaluates against an
// absent property and every bump computes from the property's initialValue, so
// a second bump of the same slot sticks at 1 instead of reaching 2.
func TestFixedArrayCall_Inbound_AccumulatesAcrossCalls(t *testing.T) {
	contract, provider, signer := deployArrayWrite(t)

	for n := 1; n <= 3; n++ {
		if _, _, err := contract.Call("bump", []interface{}{big.NewInt(0)}, provider, signer, nil); err != nil {
			t.Fatalf("Call(bump, 0) #%d error: %v", n, err)
		}
		if got, want := stateTailHex(t, contract.GetCurrentUtxo().Script), leHex(int64(n), 0, 0, 0); got != want {
			t.Fatalf("after %d bump(0) calls: continuation state section got %s, want %s", n, got, want)
		}
		assertTable(t, fmt.Sprintf("after %d bump(0) calls", n), groupedTable(t, contract.GetState()), int64(n), 0, 0, 0)
	}
}

// TestFixedArrayCall_Inbound_ReadsRestoredGroupedState is the sharper inbound
// probe, and the one that costs money. A contract reconnected with FromUtxo
// carries the state ExtractStateFromScript decodes off chain, which for a
// FixedArray field is the GROUPED entry only -- no synthetic leaves at all.
// Without the inbound bridge the interpreter falls back to each leaf's ANF
// initialValue, and because `this.table[i]++` at a runtime index lowers to a
// per-leaf select it rewrites ALL FOUR leaves from that fallback: the call
// silently rewinds the array to its deploy-time contents and commits that to
// the continuation output.
func TestFixedArrayCall_Inbound_ReadsRestoredGroupedState(t *testing.T) {
	contract, provider, signer := deployArrayWrite(t)

	// Build some real on-chain history: table -> [0,2,0,0].
	for n := 0; n < 2; n++ {
		if _, _, err := contract.Call("bump", []interface{}{big.NewInt(1)}, provider, signer, nil); err != nil {
			t.Fatalf("Call(bump, 1) #%d error: %v", n+1, err)
		}
	}
	onChainUtxo := *contract.GetCurrentUtxo()
	if got, want := stateTailHex(t, onChainUtxo.Script), leHex(0, 2, 0, 0); got != want {
		t.Fatalf("state section before reconnect: got %s, want %s", got, want)
	}

	// Reconnect from chain. This is the fund-path scenario: a fresh process
	// that only ever sees the deployed script.
	restored, err := FromUtxo(loadArrayWriteArtifact(t), onChainUtxo)
	if err != nil {
		t.Fatalf("FromUtxo: %v", err)
	}
	if _, leaked := restored.GetState()["table__1"]; leaked {
		t.Fatal("FromUtxo produced a synthetic leaf; this test no longer probes the grouped-only restore path")
	}
	assertTable(t, "reconnected state", groupedTable(t, restored.GetState()), 0, 2, 0, 0)

	if _, _, err := restored.Call("bump", []interface{}{big.NewInt(1)}, provider, signer, nil); err != nil {
		t.Fatalf("Call(bump, 1) after reconnect error: %v", err)
	}

	cont := restored.GetCurrentUtxo().Script
	if got, want := stateTailHex(t, cont), leHex(0, 3, 0, 0); got != want {
		t.Fatalf("continuation after bump(1) on reconnected state: got %s, want %s (the interpreter did not see the restored leaves)", got, want)
	}
	assertTable(t, "after bump(1) on reconnected state", groupedTable(t, restored.GetState()), 0, 3, 0, 0)
}
