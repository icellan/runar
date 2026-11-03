package runar

// N-320: the state-reading paths must refuse a hostile script with a typed
// error, never panic, hang or fabricate state.
//
// Replays conformance/sdk-matches-artifact/hostile-state.json — the N-317
// hostile scripts of hostile.json with expected outcomes for
// ExtractStateFromScript, FromUtxo and FromTxId (replayed by all 7 SDKs).
// FromTxId has its own copy of the FromUtxo body in this tier, so both are
// replayed.
//
// PROVES: for each of the 30 scripts, ExtractStateFromScript on the stateful
// artifact returns exactly the expected state / nil / *MalformedScriptError,
// and FromUtxo and FromTxId either reconnect or return a *MalformedScriptError
// (never another error or a panic) — an odd-length, non-hex or non-ASCII
// script is refused before any reader runs, and a stateful artifact over a
// script with no state section is refused (C10, as in TS) instead of carrying
// constructor-initial state; the replay stays inside a process-CPU budget.
// DOES NOT PROVE: on-chain spendability of a reconnected contract; artifact
// shapes beyond the fixture's two; the plain error DeserializeState returns
// on a hex-valid truncated or overlong state section (no case reaches it).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func n320Outcome(err error) string {
	var malformed *MalformedScriptError
	if errors.As(err, &malformed) {
		return "malformed"
	}
	return "error:" + err.Error()
}

func n320Replay(artifacts map[string]RunarArtifact, cases []n317Case, want map[string][2]string) (diffs []string) {
	provider := NewMockProvider("testnet")
	for i, c := range cases {
		script := c.script()
		txid := strings.Repeat(fmt.Sprintf("%02x", i), 32)
		provider.AddTransaction(&TransactionData{Txid: txid, Version: 1, Outputs: []TxOutput{{Satoshis: 1000, Script: script}}})
		check := func(what, wantOutcome string, run func() string) {
			got := ""
			func() {
				defer func() {
					if r := recover(); r != nil {
						got = fmt.Sprintf("panic:%v", r)
					}
				}()
				got = run()
			}()
			if got != wantOutcome {
				diffs = append(diffs, fmt.Sprintf("%s %s: want %s, got %s", what, c.Name, wantOutcome, got))
			}
		}
		stateful := artifacts["stateful"]
		check("ExtractStateFromScript", want[c.Name][0], func() string {
			s, err := ExtractStateFromScript(&stateful, script)
			if err != nil {
				return n320Outcome(err)
			}
			if s == nil {
				return "null"
			}
			out := map[string]string{}
			for k, v := range s {
				out[k] = fmt.Sprint(v)
			}
			b, _ := json.Marshal(out)
			return string(b)
		})
		a := artifacts[c.Artifact]
		check("FromUtxo", want[c.Name][1], func() string {
			if _, err := FromUtxo(&a, UTXO{Txid: txid, OutputIndex: 0, Satoshis: 1000, Script: script}); err != nil {
				return n320Outcome(err)
			}
			return "ok"
		})
		check("FromTxId", want[c.Name][1], func() string {
			if _, err := FromTxId(&a, txid, 0, provider); err != nil {
				return n320Outcome(err)
			}
			return "ok"
		})
	}
	return diffs
}

func TestN320_HostileStatePaths(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-matches-artifact")
	var fx struct {
		Artifacts map[string]RunarArtifact `json:"artifacts"`
		Cases     []n317Case               `json:"cases"`
	}
	var sfx struct {
		Cases []struct {
			Name     string          `json:"name"`
			State    json.RawMessage `json:"state"`
			FromUtxo string          `json:"fromUtxo"`
		} `json:"cases"`
	}
	for file, into := range map[string]interface{}{"hostile.json": &fx, "hostile-state.json": &sfx} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
	}
	if len(fx.Cases) == 0 || len(sfx.Cases) != len(fx.Cases) {
		t.Fatalf("fixture mismatch: %d hostile cases, %d state cases", len(fx.Cases), len(sfx.Cases))
	}
	want := map[string][2]string{}
	for _, c := range sfx.Cases {
		state := strings.Trim(string(c.State), `"`)
		if strings.HasPrefix(state, "{") {
			var m map[string]string
			if err := json.Unmarshal(c.State, &m); err != nil {
				t.Fatalf("state of %s: %v", c.Name, err)
			}
			b, _ := json.Marshal(m)
			state = string(b)
		}
		want[c.Name] = [2]string{state, c.FromUtxo}
	}

	start := n317CPU()
	done := make(chan []string, 1)
	go func() { done <- n320Replay(fx.Artifacts, fx.Cases, want) }()
	for {
		select {
		case diffs := <-done:
			if used := n317CPU() - start; used > n317Budget {
				t.Errorf("replay used %v CPU, budget %v", used, n317Budget)
			}
			for _, d := range diffs {
				t.Error(d)
			}
			return
		case <-time.After(100 * time.Millisecond):
			if used := n317CPU() - start; used > n317Budget {
				t.Fatalf("replay still running after %v CPU (budget %v)", used, n317Budget)
			}
		}
	}
}
