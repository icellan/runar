package runar

// N-025: GorillaPoolProvider must call the routes the GorillaPool API actually
// serves, decode their documented shapes, and surface a 404 as an error. The
// old routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
// /inscriptions/address/{a}, /bsv20/balance/..., /bsv20/utxos/...) do not
// exist, and the provider mapped their 404 to [] / nil / "0".
//
// Proves: replaying the shared recorded responses
// (conformance/sdk-gorillapool/endpoint-vectors.json, recorded 2026-10-05),
// every call decodes to the independently derived expectation, every
// unrouted (404) request raises, tampered bodies (txid mismatch, listing value
// != raw tx value, inscription content not matching its hash) are refused,
// GetContractUtxo refuses (no documented route), and Broadcast posts
// {"rawtx": hex}.
// Does NOT prove: that the live API still serves these shapes; that POST
// /api/tx accepts {"rawtx"} (schema-documented, never sent live); pagination
// beyond the API's default page (100).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

type n025Route struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	BodyHex     string `json:"bodyHex"`
}

type n025Call struct {
	Call              string          `json:"call"`
	Args              []string        `json:"args"`
	Expect            json.RawMessage `json:"expect"`
	ExpectError       *string         `json:"expectError"`
	ExpectRequestJSON json.RawMessage `json:"expectRequestJson"`
}

type n025Vectors struct {
	NotFound n025Route   `json:"notFound"`
	Routes   []n025Route `json:"routes"`
	Calls    []n025Call  `json:"calls"`
}

func loadN025Vectors(t *testing.T) n025Vectors {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "sdk-gorillapool", "endpoint-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v n025Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

// serveN025 serves the recorded routes (paths from the host root); anything
// else gets the recorded 404. The provider's baseURL is <server>/api, so the
// host-root /content route resolves to <server>/content.
func serveN025(t *testing.T, v n025Vectors) (*GorillaPoolProvider, *httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	posted := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			posted = append(posted, string(b))
			mu.Unlock()
		}
		route := v.NotFound
		for _, x := range v.Routes {
			if x.Method == r.Method && x.Path == r.URL.Path {
				route = x
				break
			}
		}
		body, err := hex.DecodeString(route.BodyHex)
		if err != nil {
			t.Errorf("bad bodyHex for %s: %v", route.Path, err)
		}
		if route.ContentType != "" {
			w.Header().Set("Content-Type", route.ContentType)
		}
		w.WriteHeader(route.Status)
		w.Write(body)
	}))
	p, err := NewGorillaPoolProvider("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	p.baseURL = server.URL + "/api"
	return p, server, &posted
}

func invokeN025(p *GorillaPoolProvider, c n025Call) (interface{}, error) {
	switch c.Call {
	case "getRawTransaction":
		return p.GetRawTransaction(c.Args[0])
	case "getUtxos":
		return p.GetUtxos(c.Args[0])
	case "getContractUtxo":
		return p.GetContractUtxo(c.Args[0])
	case "getInscriptionsByAddress":
		return p.GetInscriptionsByAddress(c.Args[0])
	case "getInscription":
		return p.GetInscription(c.Args[0])
	case "getBSV20Balance":
		return p.GetBSV20Balance(c.Args[0], c.Args[1])
	case "getBSV21Balance":
		return p.GetBSV21Balance(c.Args[0], c.Args[1])
	case "getBSV20Utxos":
		return p.GetBSV20Utxos(c.Args[0], c.Args[1])
	case "getBSV21Utxos":
		return p.GetBSV21Utxos(c.Args[0], c.Args[1])
	case "broadcast":
		tx, err := transaction.NewTransactionFromHex(c.Args[0])
		if err != nil {
			return nil, fmt.Errorf("test: parse broadcast tx: %w", err)
		}
		return p.Broadcast(tx)
	}
	return nil, fmt.Errorf("test: unknown call %s", c.Call)
}

// n025Normalize round-trips a value through JSON into generic form, so a Go
// struct and the vector's expectation compare field by field (InscriptionDetail
// embeds InscriptionInfo, which JSON flattens exactly like the vector shape).
func n025Normalize(t *testing.T, raw []byte) interface{} {
	t.Helper()
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return out
}

func TestN025GorillaPoolEndpointVectors(t *testing.T) {
	v := loadN025Vectors(t)
	if len(v.Calls) < 27 {
		t.Fatalf("expected >= 27 calls in the shared vectors, got %d", len(v.Calls))
	}
	for i, c := range v.Calls {
		c := c
		t.Run(fmt.Sprintf("%02d_%s", i, c.Call), func(t *testing.T) {
			p, server, posted := serveN025(t, v)
			defer server.Close()
			got, err := invokeN025(p, c)
			if c.ExpectError != nil {
				if err == nil {
					t.Fatalf("%s(%v): expected error containing %q, got value %+v", c.Call, c.Args, *c.ExpectError, got)
				}
				if !strings.Contains(err.Error(), *c.ExpectError) {
					t.Fatalf("%s(%v): error %q does not contain %q", c.Call, c.Args, err.Error(), *c.ExpectError)
				}
			} else {
				if err != nil {
					t.Fatalf("%s(%v): unexpected error: %v", c.Call, c.Args, err)
				}
				gotJSON, err := json.Marshal(got)
				if err != nil {
					t.Fatalf("marshal result: %v", err)
				}
				want := n025Normalize(t, c.Expect)
				have := n025Normalize(t, gotJSON)
				if !reflect.DeepEqual(want, have) {
					t.Fatalf("%s(%v):\n got  %s\n want %s", c.Call, c.Args, gotJSON, string(c.Expect))
				}
			}
			if len(c.ExpectRequestJSON) > 0 {
				if len(*posted) != 1 {
					t.Fatalf("expected exactly 1 POST, got %d", len(*posted))
				}
				if !reflect.DeepEqual(n025Normalize(t, []byte((*posted)[0])), n025Normalize(t, c.ExpectRequestJSON)) {
					t.Fatalf("POST body %s, want %s", (*posted)[0], string(c.ExpectRequestJSON))
				}
			}
		})
	}
}
