package runar

// N-317: one hostile UTXO script must not take TokenWallet.GetUtxos down, and
// MatchesArtifact must agree with the TS SDK on every malformed shape.
//
// Replays the shared cross-tier vector conformance/sdk-matches-artifact/
// hostile.json (also replayed by the TS, Rust, Python, Zig, Ruby and Java
// SDKs): odd-length and non-hex scripts, truncated OP_PUSHDATA1/2/4,
// OP_PUSHDATA4 lengths with the high bit set, a push running past the slot,
// empty and short scripts and ~1 MiB scripts, beside SDK-built genuine
// instances.
//
// PROVES: MatchesArtifact gives exactly the fixture's outcome per vector
// (true / false / a *MalformedScriptError, never another error or a panic);
// GetUtxos keeps exactly the genuine instances for a stateful and a stateless
// artifact and never errors; the replay stays inside a process-CPU budget
// (getrusage, polled while a goroutine replays, as in the N-181 tests, so a
// hang fails at the budget).
// DOES NOT PROVE: on-chain spendability of the kept UTXOs, artifact shapes
// beyond the fixture's two, or anything about a forged codeSepIndex element
// (N-318).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Measured: well under a second of CPU after the fix.
const n317Budget = 20 * time.Second

type n317Case struct {
	Name     string `json:"name"`
	Artifact string `json:"artifact"`
	Prefix   string `json:"prefix"`
	Repeat   string `json:"repeat"`
	Count    int    `json:"count"`
	Suffix   string `json:"suffix"`
	Matches  string `json:"matches"`
	Wallet   *bool  `json:"wallet"`
}

func (c n317Case) script() string { return c.Prefix + strings.Repeat(c.Repeat, c.Count) + c.Suffix }

func n317CPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func n317Replay(artifacts map[string]RunarArtifact, cases []n317Case) (diffs []string) {
	defer func() {
		if r := recover(); r != nil {
			diffs = append(diffs, fmt.Sprintf("panic: %v", r))
		}
	}()
	for _, c := range cases {
		a := artifacts[c.Artifact]
		got := ""
		func() {
			defer func() {
				if r := recover(); r != nil {
					got = fmt.Sprintf("panic:%v", r)
				}
			}()
			ok, err := MatchesArtifact(&a, c.script())
			var malformed *MalformedScriptError
			switch {
			case err == nil && ok:
				got = "match"
			case err == nil:
				got = "no_match"
			case errors.As(err, &malformed):
				got = "malformed"
			default:
				got = "error:" + err.Error()
			}
		}()
		if got != c.Matches {
			diffs = append(diffs, fmt.Sprintf("%s: want %s, got %s", c.Name, c.Matches, got))
		}
	}
	for name := range artifacts {
		a := artifacts[name]
		provider := NewMockProvider("testnet")
		signer := NewMockSigner("", "")
		addr, _ := signer.GetAddress()
		want := []string{}
		for i, c := range cases {
			if c.Artifact != name || c.Wallet == nil {
				continue
			}
			txid := strings.Repeat(fmt.Sprintf("%02x", i), 32)
			provider.AddUtxo(addr, UTXO{Txid: txid, OutputIndex: 0, Satoshis: 1000, Script: c.script()})
			if *c.Wallet {
				want = append(want, txid)
			}
		}
		kept := []string{}
		func() {
			defer func() {
				if r := recover(); r != nil {
					diffs = append(diffs, fmt.Sprintf("GetUtxos (%s) panicked: %v", name, r))
				}
			}()
			utxos, err := NewTokenWallet(&a, provider, signer).GetUtxos()
			if err != nil {
				diffs = append(diffs, fmt.Sprintf("GetUtxos (%s): %v", name, err))
				return
			}
			for _, u := range utxos {
				kept = append(kept, u.Txid)
			}
			if !reflect.DeepEqual(want, kept) {
				diffs = append(diffs, fmt.Sprintf("GetUtxos (%s): want %v, got %v", name, want, kept))
			}
		}()
	}
	return diffs
}

func TestN317_HostileUtxoScripts(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-matches-artifact", "hostile.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Artifacts map[string]RunarArtifact `json:"artifacts"`
		Cases     []n317Case               `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 || len(fx.Artifacts) == 0 {
		t.Fatal("fixture has no cases")
	}

	start := n317CPU()
	done := make(chan []string, 1)
	go func() { done <- n317Replay(fx.Artifacts, fx.Cases) }()
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
