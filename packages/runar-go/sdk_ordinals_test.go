package runar

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test 1: Envelope build/parse round-trip (text)
// ---------------------------------------------------------------------------

func TestBuildParseInscriptionEnvelope_Text(t *testing.T) {
	contentType := "text/plain"
	data := hex.EncodeToString([]byte("hello world"))

	envelope := BuildInscriptionEnvelope(contentType, data)

	// Expected value from TypeScript reference
	expected := "0063036f7264510a746578742f706c61696e000b68656c6c6f20776f726c6468"
	if envelope != expected {
		t.Fatalf("envelope mismatch:\n  got:  %s\n  want: %s", envelope, expected)
	}

	parsed := ParseInscriptionEnvelope(envelope)
	if parsed == nil {
		t.Fatal("ParseInscriptionEnvelope returned nil")
	}
	if parsed.ContentType != contentType {
		t.Errorf("content type: got %q, want %q", parsed.ContentType, contentType)
	}
	if parsed.Data != data {
		t.Errorf("data: got %q, want %q", parsed.Data, data)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Envelope build/parse round-trip (large data forcing OP_PUSHDATA2)
// ---------------------------------------------------------------------------

func TestBuildParseInscriptionEnvelope_LargeData(t *testing.T) {
	contentType := "application/octet-stream"
	data := strings.Repeat("aa", 300) // 300 bytes > 255, forces OP_PUSHDATA2

	envelope := BuildInscriptionEnvelope(contentType, data)

	parsed := ParseInscriptionEnvelope(envelope)
	if parsed == nil {
		t.Fatal("ParseInscriptionEnvelope returned nil for large data")
	}
	if parsed.ContentType != contentType {
		t.Errorf("content type: got %q, want %q", parsed.ContentType, contentType)
	}
	if parsed.Data != data {
		t.Errorf("data length: got %d, want %d", len(parsed.Data)/2, 300)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Envelope build/parse round-trip (BSV-20 JSON)
// ---------------------------------------------------------------------------

func TestBuildParseInscriptionEnvelope_BSV20JSON(t *testing.T) {
	insc := BSV20Mint("RUNAR", "1000")
	envelope := BuildInscriptionEnvelope(insc.ContentType, insc.Data)

	parsed := ParseInscriptionEnvelope(envelope)
	if parsed == nil {
		t.Fatal("ParseInscriptionEnvelope returned nil for BSV-20 JSON")
	}
	if parsed.ContentType != "application/bsv-20" {
		t.Errorf("content type: got %q, want %q", parsed.ContentType, "application/bsv-20")
	}
	if parsed.Data != insc.Data {
		t.Errorf("data mismatch:\n  got:  %s\n  want: %s", parsed.Data, insc.Data)
	}
}

// ---------------------------------------------------------------------------
// Test 4: FindInscriptionEnvelope with envelope between code and OP_RETURN
// ---------------------------------------------------------------------------

func TestFindInscriptionEnvelope_BetweenCodeAndOpReturn(t *testing.T) {
	codeScript := "aabbccdd"
	data := hex.EncodeToString([]byte("hello world"))
	envelope := BuildInscriptionEnvelope("text/plain", data)
	stateData := "eeff"
	fullScript := codeScript + envelope + "6a" + stateData

	// Verify against TypeScript reference
	expectedScript := "aabbccdd0063036f7264510a746578742f706c61696e000b68656c6c6f20776f726c64686aeeff"
	if fullScript != expectedScript {
		t.Fatalf("full script mismatch:\n  got:  %s\n  want: %s", fullScript, expectedScript)
	}

	bounds := FindInscriptionEnvelope(fullScript)
	if bounds == nil {
		t.Fatal("FindInscriptionEnvelope returned nil")
	}

	// TypeScript reference: startHex=8, endHex=72
	if bounds.StartHex != 8 {
		t.Errorf("startHex: got %d, want 8", bounds.StartHex)
	}
	if bounds.EndHex != 72 {
		t.Errorf("endHex: got %d, want 72", bounds.EndHex)
	}
}

func TestFindInscriptionEnvelope_NoEnvelope(t *testing.T) {
	// A plain script with no envelope
	bounds := FindInscriptionEnvelope("76a914" + strings.Repeat("00", 20) + "88ac")
	if bounds != nil {
		t.Errorf("expected nil bounds, got %+v", bounds)
	}
}

// ---------------------------------------------------------------------------
// Test 5: StripInscriptionEnvelope preserves surrounding script
// ---------------------------------------------------------------------------

func TestStripInscriptionEnvelope(t *testing.T) {
	codeScript := "aabbccdd"
	data := hex.EncodeToString([]byte("hello world"))
	envelope := BuildInscriptionEnvelope("text/plain", data)
	stateData := "eeff"
	fullScript := codeScript + envelope + "6a" + stateData

	stripped := StripInscriptionEnvelope(fullScript)

	// TypeScript reference: "aabbccdd6aeeff"
	expected := "aabbccdd6aeeff"
	if stripped != expected {
		t.Errorf("stripped mismatch:\n  got:  %s\n  want: %s", stripped, expected)
	}
}

func TestStripInscriptionEnvelope_NoEnvelope(t *testing.T) {
	script := "76a914aabbccdd88ac"
	stripped := StripInscriptionEnvelope(script)
	if stripped != script {
		t.Errorf("expected unchanged script, got %s", stripped)
	}
}

// ---------------------------------------------------------------------------
// Test 6: BSV-20 deploy/mint/transfer JSON construction
// ---------------------------------------------------------------------------

func TestBSV20Deploy(t *testing.T) {
	lim := "1000"
	insc := BSV20Deploy("RUNAR", "21000000", &lim, nil)

	if insc.ContentType != "application/bsv-20" {
		t.Errorf("content type: got %q, want %q", insc.ContentType, "application/bsv-20")
	}

	// Reference from TypeScript
	expectedData := "7b2270223a226273762d3230222c226f70223a226465706c6f79222c227469636b223a2252554e4152222c226d6178223a223231303030303030222c226c696d223a2231303030227d"
	if insc.Data != expectedData {
		t.Errorf("deploy data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}

	// Decode and verify JSON
	jsonStr := hexToUtf8(insc.Data)
	expectedJSON := `{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000","lim":"1000"}`
	if jsonStr != expectedJSON {
		t.Errorf("decoded JSON mismatch:\n  got:  %s\n  want: %s", jsonStr, expectedJSON)
	}
}

func TestBSV20Deploy_NoOptional(t *testing.T) {
	insc := BSV20Deploy("TEST", "100", nil, nil)
	expectedData := "7b2270223a226273762d3230222c226f70223a226465706c6f79222c227469636b223a2254455354222c226d6178223a22313030227d"
	if insc.Data != expectedData {
		t.Errorf("deploy (no optional) data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}
}

func TestBSV20Mint(t *testing.T) {
	insc := BSV20Mint("RUNAR", "1000")

	expectedData := "7b2270223a226273762d3230222c226f70223a226d696e74222c227469636b223a2252554e4152222c22616d74223a2231303030227d"
	if insc.Data != expectedData {
		t.Errorf("mint data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}
}

func TestBSV20Transfer(t *testing.T) {
	insc := BSV20Transfer("RUNAR", "50")

	expectedData := "7b2270223a226273762d3230222c226f70223a227472616e73666572222c227469636b223a2252554e4152222c22616d74223a223530227d"
	if insc.Data != expectedData {
		t.Errorf("transfer data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}
}

// ---------------------------------------------------------------------------
// Test 7: BSV-21 deploy+mint/transfer JSON construction
// ---------------------------------------------------------------------------

func TestBSV21DeployMint(t *testing.T) {
	dec := "18"
	sym := "RNR"
	insc := BSV21DeployMint("1000000", &dec, &sym, nil)

	if insc.ContentType != "application/bsv-20" {
		t.Errorf("content type: got %q, want %q", insc.ContentType, "application/bsv-20")
	}

	expectedData := "7b2270223a226273762d3230222c226f70223a226465706c6f792b6d696e74222c22616d74223a2231303030303030222c22646563223a223138222c2273796d223a22524e52227d"
	if insc.Data != expectedData {
		t.Errorf("deploy+mint data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}
}

func TestBSV21Transfer(t *testing.T) {
	insc := BSV21Transfer("abc123_1", "100")

	expectedData := "7b2270223a226273762d3230222c226f70223a227472616e73666572222c226964223a226162633132335f31222c22616d74223a22313030227d"
	if insc.Data != expectedData {
		t.Errorf("BSV-21 transfer data mismatch:\n  got:  %s\n  want: %s", insc.Data, expectedData)
	}
}

// ---------------------------------------------------------------------------
// Test 8: GetLockingScript with inscription on stateless contract
// ---------------------------------------------------------------------------

func TestGetLockingScript_Stateless_WithInscription(t *testing.T) {
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, []interface{}{})
	data := hex.EncodeToString([]byte("hello"))
	contract.WithInscription(&Inscription{
		ContentType: "text/plain",
		Data:        data,
	})

	lockingScript := contract.GetLockingScript()

	// Should be: code + envelope
	expectedEnvelope := BuildInscriptionEnvelope("text/plain", data)
	expected := "aabbccdd" + expectedEnvelope
	if lockingScript != expected {
		t.Errorf("stateless locking script mismatch:\n  got:  %s\n  want: %s", lockingScript, expected)
	}
}

// ---------------------------------------------------------------------------
// Test 9: GetLockingScript with inscription on stateful contract
// (code + envelope + OP_RETURN + state)
// ---------------------------------------------------------------------------

func TestGetLockingScript_Stateful_WithInscription(t *testing.T) {
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "count", Type: "bigint"}}},
		Methods:     []ABIMethod{{Name: "increment", Params: []ABIParam{}, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{
			{Name: "count", Type: "bigint", Index: 0},
		}
	})

	contract := NewRunarContract(artifact, []interface{}{int64(42)})
	data := hex.EncodeToString([]byte("token"))
	contract.WithInscription(&Inscription{
		ContentType: "application/bsv-20",
		Data:        data,
	})

	lockingScript := contract.GetLockingScript()

	// Build expected: code + envelope + OP_RETURN + state
	expectedEnvelope := BuildInscriptionEnvelope("application/bsv-20", data)
	stateHex := SerializeState(artifact.StateFields, map[string]interface{}{"count": int64(42)})

	expected := "aabbccdd" + expectedEnvelope + "6a" + stateHex
	if lockingScript != expected {
		t.Errorf("stateful locking script mismatch:\n  got:  %s\n  want: %s", lockingScript, expected)
	}

	// Verify the envelope is between code and OP_RETURN
	bounds := FindInscriptionEnvelope(lockingScript)
	if bounds == nil {
		t.Fatal("could not find envelope in stateful locking script")
	}
	if lockingScript[:bounds.StartHex] != "aabbccdd" {
		t.Error("code before envelope is wrong")
	}
	afterEnvelope := lockingScript[bounds.EndHex:]
	if !strings.HasPrefix(afterEnvelope, "6a") {
		t.Error("expected OP_RETURN after envelope")
	}
}

// ---------------------------------------------------------------------------
// Test 10: FromUtxo round-trips inscription
// ---------------------------------------------------------------------------

func TestFromUtxo_RoundTripsInscription(t *testing.T) {
	// Build a stateless contract with inscription
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
	})

	data := hex.EncodeToString([]byte("hello world"))
	envelope := BuildInscriptionEnvelope("text/plain", data)
	onChainScript := "aabbccdd" + envelope

	contract := FromUtxo(artifact, UTXO{
		Txid:        strings.Repeat("ab", 32),
		OutputIndex: 0,
		Satoshis:    1,
		Script:      onChainScript,
	})

	insc := contract.GetInscription()
	if insc == nil {
		t.Fatal("FromUtxo did not detect inscription")
	}
	if insc.ContentType != "text/plain" {
		t.Errorf("content type: got %q, want %q", insc.ContentType, "text/plain")
	}
	if insc.Data != data {
		t.Errorf("data: got %q, want %q", insc.Data, data)
	}
}

func TestFromUtxo_RoundTripsInscription_Stateful(t *testing.T) {
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "count", Type: "bigint"}}},
		Methods:     []ABIMethod{{Name: "increment", Params: []ABIParam{}, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{
			{Name: "count", Type: "bigint", Index: 0},
		}
	})

	data := hex.EncodeToString([]byte("token"))
	envelope := BuildInscriptionEnvelope("application/bsv-20", data)
	stateHex := SerializeState(artifact.StateFields, map[string]interface{}{"count": int64(99)})
	onChainScript := "aabbccdd" + envelope + "6a" + stateHex

	contract := FromUtxo(artifact, UTXO{
		Txid:        strings.Repeat("ab", 32),
		OutputIndex: 0,
		Satoshis:    1,
		Script:      onChainScript,
	})

	insc := contract.GetInscription()
	if insc == nil {
		t.Fatal("FromUtxo did not detect inscription in stateful contract")
	}
	if insc.ContentType != "application/bsv-20" {
		t.Errorf("content type: got %q, want %q", insc.ContentType, "application/bsv-20")
	}
	if insc.Data != data {
		t.Errorf("data: got %q, want %q", insc.Data, data)
	}

	// Verify state was also extracted
	state := contract.GetState()
	if state["count"] != int64(99) {
		t.Errorf("state count: got %v, want 99", state["count"])
	}
}

// ---------------------------------------------------------------------------
// Test 11: Chain-loaded contract does not double-inject envelope
// ---------------------------------------------------------------------------

func TestFromUtxo_NoDoubleEnvelopeInjection(t *testing.T) {
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{{Name: "count", Type: "bigint"}}},
		Methods:     []ABIMethod{{Name: "increment", Params: []ABIParam{}, IsPublic: true}},
	}, func(a *RunarArtifact) {
		a.StateFields = []StateField{
			{Name: "count", Type: "bigint", Index: 0},
		}
	})

	data := hex.EncodeToString([]byte("token"))
	envelope := BuildInscriptionEnvelope("application/bsv-20", data)
	stateHex := SerializeState(artifact.StateFields, map[string]interface{}{"count": int64(42)})
	onChainScript := "aabbccdd" + envelope + "6a" + stateHex

	contract := FromUtxo(artifact, UTXO{
		Txid:        strings.Repeat("ab", 32),
		OutputIndex: 0,
		Satoshis:    1,
		Script:      onChainScript,
	})

	// GetLockingScript should produce the same script (using codeScript from chain)
	lockingScript := contract.GetLockingScript()
	if lockingScript != onChainScript {
		t.Errorf("chain-loaded locking script should match original:\n  got:  %s\n  want: %s", lockingScript, onChainScript)
	}

	// Verify only one envelope exists
	first := FindInscriptionEnvelope(lockingScript)
	if first == nil {
		t.Fatal("no envelope found")
	}
	remaining := lockingScript[first.EndHex:]
	second := FindInscriptionEnvelope(remaining)
	if second != nil {
		t.Error("found a second envelope -- double injection detected")
	}
}

// ---------------------------------------------------------------------------
// Test 12: GorillaPoolProvider implements Provider interface
// ---------------------------------------------------------------------------

func TestGorillaPoolProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*GorillaPoolProvider)(nil)
}

func TestGorillaPoolProvider_NetworkURLs(t *testing.T) {
	mainnet := NewGorillaPoolProvider("mainnet")
	if mainnet.baseURL != "https://ordinals.gorillapool.io/api" {
		t.Errorf("mainnet URL: got %q", mainnet.baseURL)
	}
	if mainnet.GetNetwork() != "mainnet" {
		t.Errorf("mainnet network: got %q", mainnet.GetNetwork())
	}

	testnet := NewGorillaPoolProvider("testnet")
	if testnet.baseURL != "https://testnet.ordinals.gorillapool.io/api" {
		t.Errorf("testnet URL: got %q", testnet.baseURL)
	}

	defaultNet := NewGorillaPoolProvider("")
	if defaultNet.GetNetwork() != "mainnet" {
		t.Errorf("default network: got %q", defaultNet.GetNetwork())
	}
}

func TestGorillaPoolProvider_FeeRate(t *testing.T) {
	p := NewGorillaPoolProvider("mainnet")
	rate, err := p.GetFeeRate()
	if err != nil {
		t.Fatalf("GetFeeRate error: %v", err)
	}
	if rate != 100 {
		t.Errorf("fee rate: got %d, want 100", rate)
	}
}

// ---------------------------------------------------------------------------
// Test 13: WithInscription chaining
// ---------------------------------------------------------------------------

func TestWithInscription_Chaining(t *testing.T) {
	artifact := makeArtifact("aabb", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, []interface{}{})
	result := contract.WithInscription(&Inscription{ContentType: "text/plain", Data: "aabb"})

	// WithInscription returns the same contract for chaining
	if result != contract {
		t.Error("WithInscription should return the same contract for chaining")
	}

	insc := contract.GetInscription()
	if insc == nil || insc.ContentType != "text/plain" {
		t.Error("inscription not set after WithInscription")
	}
}

// ---------------------------------------------------------------------------
// Test 14: Empty/nil inscription does not add envelope
// ---------------------------------------------------------------------------

func TestGetLockingScript_NoInscription(t *testing.T) {
	artifact := makeArtifact("aabbccdd", ABI{
		Constructor: ABIConstructor{Params: []ABIParam{}},
		Methods:     []ABIMethod{{Name: "unlock", Params: []ABIParam{}, IsPublic: true}},
	})

	contract := NewRunarContract(artifact, []interface{}{})
	lockingScript := contract.GetLockingScript()

	if lockingScript != "aabbccdd" {
		t.Errorf("script without inscription should be bare code: got %s", lockingScript)
	}

	if contract.GetInscription() != nil {
		t.Error("expected nil inscription")
	}
}
