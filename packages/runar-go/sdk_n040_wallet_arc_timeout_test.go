package runar

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// N-040: WalletProvider.Broadcast had no request timeout. TestF042_WalletBroadcast_Timeout
// (sdk_wallet_arc_broadcast_test.go) already had to reach into the unexported
// `wp.client` field and overwrite it with a 100ms-timeout client to avoid
// hanging forever — proof that NewWalletProvider's own default client
// (`&http.Client{}`, no Timeout) leaves a real caller with no bound at all
// against a hung ARC deployment.
//
// PROVES: constructing a WalletProvider through the PUBLIC
// WalletProviderOptions.ArcTimeout (no reaching into private fields) and
// pointing it at a real httptest server that accepts the connection and never
// writes a response, Broadcast returns an error, and does so well inside the
// configured timeout rather than hanging.
// DOES NOT PROVE: the right default timeout value for production (30s is a
// judgment call, not derived from a spec), or behavior against a live ARC
// deployment.
func TestN040_WalletBroadcast_TimeoutViaPublicOption(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	wp := NewWalletProvider(WalletProviderOptions{
		Wallet:     newMockWalletClient(""),
		ArcUrl:     srv.URL,
		ArcTimeout: 200 * time.Millisecond,
	})

	tx := transaction.NewTransaction()
	start := time.Now()
	txid, err := wp.Broadcast(tx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Broadcast must fail against a hung ARC, returned txid %q", txid)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Broadcast took %v, expected it to time out near the configured 200ms", elapsed)
	}
}
