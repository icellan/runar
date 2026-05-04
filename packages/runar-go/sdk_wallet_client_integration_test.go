package runar

// ---------------------------------------------------------------------------
// sdk_wallet_client_integration_test.go — live BRC-100 WalletClient round-trip.
//
// Mirrors integration/ruby/spec/wallet_client_spec.rb. Environment-gated:
// runs only when RUNAR_WALLET_ENDPOINT is set to the base URL of a BRC-100
// JSON-over-HTTP wallet endpoint. When unset, the test is skipped cleanly
// so local + CI runs stay green without any wallet setup.
//
// Optional env:
//   RUNAR_WALLET_ENDPOINT — base URL, required
//   RUNAR_WALLET_AUTH     — bearer token, optional
//   RUNAR_WALLET_BASKET   — basket name, default "runar-integration-test"
//
// Asserts the same shape Ruby asserts:
//   * GetPublicKey returns a 33-byte compressed pubkey (66 hex chars).
//   * ListOutputs returns an array; entries (if any) expose at least one of
//     outpoint / satoshis / locking_script.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// httpWalletClient is a tiny BRC-100 JSON-over-HTTP wallet adapter used only
// by this integration test. Speaks POST {endpoint}/{method} with a JSON body
// matching the BRC-100 request shape, returns the parsed JSON response.
type httpWalletClient struct {
	endpoint  string
	authToken string
	client    *http.Client
}

func newHTTPWalletClient(endpoint, authToken string) *httpWalletClient {
	return &httpWalletClient{
		endpoint:  strings.TrimRight(endpoint, "/"),
		authToken: authToken,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *httpWalletClient) post(method string, body any, dst any) error {
	bs, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", method, err)
	}
	req, err := http.NewRequest("POST", c.endpoint+"/"+method, bytes.NewReader(bs))
	if err != nil {
		return fmt.Errorf("new request %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("do %s: %w", method, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("wallet %s HTTP %d: %s", method, resp.StatusCode, string(respBody))
	}
	if dst == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, dst); err != nil {
		return fmt.Errorf("unmarshal %s: %w", method, err)
	}
	return nil
}

// GetPublicKey calls the BRC-100 getPublicKey endpoint and returns the
// hex-encoded compressed pubkey.
func (c *httpWalletClient) GetPublicKey(protocolID [2]interface{}, keyID string) (string, error) {
	req := map[string]interface{}{
		"protocolID": protocolID,
		"keyID":      keyID,
	}
	var resp struct {
		PublicKey    string `json:"publicKey"`
		PublicKeyHex string `json:"publicKeyHex"`
	}
	if err := c.post("getPublicKey", req, &resp); err != nil {
		return "", err
	}
	if resp.PublicKey != "" {
		return resp.PublicKey, nil
	}
	if resp.PublicKeyHex != "" {
		return resp.PublicKeyHex, nil
	}
	return "", fmt.Errorf("getPublicKey: missing publicKey in response")
}

// ListOutputs calls the BRC-100 listOutputs endpoint and decodes the
// outputs array.
func (c *httpWalletClient) ListOutputs(basket string, tags []string, limit int) ([]map[string]interface{}, error) {
	if tags == nil {
		tags = []string{}
	}
	req := map[string]interface{}{
		"basket": basket,
		"tags":   tags,
		"limit":  limit,
	}
	var resp struct {
		Outputs []map[string]interface{} `json:"outputs"`
	}
	if err := c.post("listOutputs", req, &resp); err != nil {
		return nil, err
	}
	return resp.Outputs, nil
}

func TestWalletClient_LiveEndpoint_RoundTrip(t *testing.T) {
	endpoint := os.Getenv("RUNAR_WALLET_ENDPOINT")
	if endpoint == "" {
		t.Skip("RUNAR_WALLET_ENDPOINT not set — skipping live BRC-100 wallet round-trip. " +
			"Set RUNAR_WALLET_ENDPOINT to a BRC-100 wallet URL to enable.")
	}
	authToken := os.Getenv("RUNAR_WALLET_AUTH")
	basket := os.Getenv("RUNAR_WALLET_BASKET")
	if basket == "" {
		basket = "runar-integration-test"
	}

	wallet := newHTTPWalletClient(endpoint, authToken)
	protocolID := [2]interface{}{2, "runar integration"}
	keyID := "1"

	// 1. getPublicKey: must return a 33-byte compressed secp256k1 key.
	pubKey, err := wallet.GetPublicKey(protocolID, keyID)
	if err != nil {
		t.Fatalf("getPublicKey: %v", err)
	}
	if pubKey == "" {
		t.Fatal("getPublicKey returned empty string")
	}
	if len(pubKey) != 66 {
		t.Fatalf("getPublicKey: expected 66 hex chars, got %d (%q)", len(pubKey), pubKey)
	}
	prefix := pubKey[:2]
	if prefix != "02" && prefix != "03" {
		t.Fatalf("getPublicKey: expected compressed prefix 02/03, got %q", prefix)
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(pubKey) {
		t.Fatalf("getPublicKey: not a hex string: %q", pubKey)
	}
	if _, err := hex.DecodeString(pubKey); err != nil {
		t.Fatalf("getPublicKey: invalid hex: %v", err)
	}

	// 2. listOutputs: must return an array (possibly empty).
	outputs, err := wallet.ListOutputs(basket, nil, 10)
	if err != nil {
		t.Fatalf("listOutputs: %v", err)
	}
	for i, out := range outputs {
		_, hasOutpoint := out["outpoint"]
		_, hasSatoshis := out["satoshis"]
		_, hasLocking := out["lockingScript"]
		if !hasOutpoint && !hasSatoshis && !hasLocking {
			t.Fatalf("listOutputs[%d]: missing canonical outpoint/satoshis/lockingScript fields: %#v", i, out)
		}
	}
}
