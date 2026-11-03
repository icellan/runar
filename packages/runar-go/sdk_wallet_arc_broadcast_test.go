package runar

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// F-042: WalletProvider.Broadcast already returned an error on a transport
// failure and on a non-2xx response, but on any 2xx it returned the locally
// computed txid without reading the body — so a 200 whose ARC txStatus was
// REJECTED / DOUBLE_SPEND_ATTEMPTED / SEEN_IN_ORPHAN_MEMPOOL, or which carried
// an ARC error status, was reported as broadcast and cached.
//
// PROVES: against an httptest server standing in for ARC, Broadcast errors on a
// 500, a 4xx with an ARC error body, each rejecting txStatus, a 200 with an
// error `status` field, a 200 with no txid, a 200 whose txid is another
// transaction's, a client timeout and a refused connection, and caches nothing
// in those cases; only an accepting 200 echoing this transaction's txid
// returns it.
// DOES NOT PROVE: behaviour against the live ARC service, or the complete set
// of txStatus values an ARC deployment may emit (the rejection list mirrors
// @bsv/sdk's ARC broadcaster).

func f042Provider(url string) *WalletProvider {
	return NewWalletProvider(WalletProviderOptions{Wallet: newMockWalletClient(""), ArcUrl: url})
}

func f042Arc(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func f042ExpectRejected(t *testing.T, wp *WalletProvider, want ...string) {
	t.Helper()
	tx := transaction.NewTransaction()
	txid, err := wp.Broadcast(tx)
	if err == nil {
		t.Fatalf("Broadcast must fail, returned txid %q", txid)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not mention %q", err, w)
		}
	}
	if _, ok := wp.txCache[tx.TxID().String()]; ok {
		t.Error("a transaction ARC did not accept must not be cached as broadcast")
	}
}

func f042Body(t *testing.T, v map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestF042_WalletBroadcast_HTTP500(t *testing.T) {
	f042ExpectRejected(t, f042Provider(f042Arc(t, 500, `{"detail":"boom"}`)), "500", "boom")
}

func TestF042_WalletBroadcast_4xxErrorBody(t *testing.T) {
	body := `{"type":"https://bitcoin-sv.github.io/arc/#/errors?id=_461","title":"Malformed transaction","status":461,"detail":"Transaction is malformed"}`
	f042ExpectRejected(t, f042Provider(f042Arc(t, 461, body)), "461", "Malformed")
}

func TestF042_WalletBroadcast_200RejectedTxStatus(t *testing.T) {
	local := transaction.NewTransaction().TxID().String()
	for _, st := range []string{"REJECTED", "DOUBLE_SPEND_ATTEMPTED", "SEEN_IN_ORPHAN_MEMPOOL"} {
		t.Run(st, func(t *testing.T) {
			body := f042Body(t, map[string]interface{}{"txid": local, "txStatus": st, "extraInfo": "nope", "status": 200})
			f042ExpectRejected(t, f042Provider(f042Arc(t, 200, body)), st)
		})
	}
}

func TestF042_WalletBroadcast_200ErrorStatusField(t *testing.T) {
	local := transaction.NewTransaction().TxID().String()
	body := f042Body(t, map[string]interface{}{"txid": local, "status": 465, "title": "Fee too low", "detail": "fee too low"})
	f042ExpectRejected(t, f042Provider(f042Arc(t, 200, body)), "465", "Fee too low")
}

func TestF042_WalletBroadcast_200NoTxid(t *testing.T) {
	f042ExpectRejected(t, f042Provider(f042Arc(t, 200, `{"txStatus":"SEEN_ON_NETWORK"}`)), "txid")
}

func TestF042_WalletBroadcast_200ForeignTxid(t *testing.T) {
	local := transaction.NewTransaction().TxID().String()
	foreign := strings.Repeat("cc", 32)
	body := f042Body(t, map[string]interface{}{"txid": foreign, "txStatus": "SEEN_ON_NETWORK"})
	f042ExpectRejected(t, f042Provider(f042Arc(t, 200, body)), foreign, local)
}

func TestF042_WalletBroadcast_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	wp := f042Provider(srv.URL)
	wp.client = &http.Client{Timeout: 100 * time.Millisecond}
	f042ExpectRejected(t, wp, "sending request")
}

func TestF042_WalletBroadcast_ConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	f042ExpectRejected(t, f042Provider("http://"+addr), "sending request")
}

func TestF042_WalletBroadcast_200AcceptedReturnsArcTxid(t *testing.T) {
	tx := transaction.NewTransaction()
	local := tx.TxID().String()
	body := f042Body(t, map[string]interface{}{"txid": local, "txStatus": "SEEN_ON_NETWORK", "status": 200, "title": "OK"})
	wp := f042Provider(f042Arc(t, 200, body))
	txid, err := wp.Broadcast(tx)
	if err != nil {
		t.Fatalf("an accepting ARC response must succeed: %v", err)
	}
	if txid != local {
		t.Errorf("expected txid %s, got %s", local, txid)
	}
	if wp.txCache[local] != tx.Hex() {
		t.Error("an accepted broadcast must cache the raw tx")
	}
}
