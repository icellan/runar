package runar

import (
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// N-239: TokenWallet.Merge / .Transfer are deprecated and unsafe. The ABI
// they drive cannot be made sound — merge(sig, otherSupply, otherHolder)
// cannot authenticate its companion input (supply inflation) and
// transfer(sig, to: Addr) cannot re-key a PubKey holder. User decision R92:
// deprecate (marker + one-time runtime warning + docs), do not redesign or
// remove.
//
// Proves: each method's doc carries a `Deprecated:` paragraph; calling it
// writes a warning to stderr naming its specific unsoundness and pointing to
// token-ft (FungibleTokenExample), once per process, not per call; the
// method's own behaviour (here, its error path) is unchanged.
// Does NOT prove: that anyone reads the warning, or anything on-chain — the
// happy paths stay covered by the f045 / n042 suites.

// n239CaptureStderr runs fn with os.Stderr redirected and returns what it wrote.
func n239CaptureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stderr = orig }()
		fn()
	}()
	w.Close()
	return <-done
}

func n239Wallet() *TokenWallet {
	art := &RunarArtifact{ContractName: "WalletToken", Script: "76a988ac"}
	return NewTokenWallet(art, NewMockProvider("testnet"), NewMockSigner("", ""))
}

func TestN239_TokenWalletMergeWarnsOnce(t *testing.T) {
	// Other tests in this package may already have spent the once.
	tokenWalletMergeWarnOnce = sync.Once{}
	tw := n239Wallet()
	out := n239CaptureStderr(t, func() {
		for i := 0; i < 2; i++ {
			if _, err := tw.Merge(); err == nil || !strings.Contains(err.Error(), "need at least 2 UTXOs") {
				t.Errorf("Merge error path changed: %v", err)
			}
		}
	})
	if n := strings.Count(out, "TokenWallet.Merge"); n != 1 {
		t.Fatalf("want exactly one Merge warning, got %d in %q", n, out)
	}
	for _, want := range []string{"deprecated", "supply inflation", "token-ft", "FungibleTokenExample"} {
		if !strings.Contains(out, want) {
			t.Errorf("Merge warning lacks %q: %q", want, out)
		}
	}
}

func TestN239_TokenWalletTransferWarnsOnce(t *testing.T) {
	tokenWalletTransferWarnOnce = sync.Once{}
	tw := n239Wallet()
	out := n239CaptureStderr(t, func() {
		for i := 0; i < 2; i++ {
			if _, err := tw.Transfer("recipient", 1); err == nil || !strings.Contains(err.Error(), "no token UTXOs found") {
				t.Errorf("Transfer error path changed: %v", err)
			}
		}
	})
	if n := strings.Count(out, "TokenWallet.Transfer"); n != 1 {
		t.Fatalf("want exactly one Transfer warning, got %d in %q", n, out)
	}
	for _, want := range []string{"deprecated", "re-key", "token-ft", "FungibleTokenExample"} {
		if !strings.Contains(out, want) {
			t.Errorf("Transfer warning lacks %q: %q", want, out)
		}
	}
}

func TestN239_TokenWalletDeprecatedMarkers(t *testing.T) {
	src, err := os.ReadFile("sdk_token_wallet.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"Transfer", "Merge"} {
		// A `// Deprecated:` paragraph inside the doc comment directly above the func.
		re := regexp.MustCompile(`// Deprecated:[^\n]*\n(?://[^\n]*\n)*func \(tw \*TokenWallet\) ` + m + `\(`)
		if !re.Match(src) {
			t.Errorf("%s lacks a // Deprecated: doc marker", m)
		}
	}
}
