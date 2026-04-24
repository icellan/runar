package integration

import (
	"strings"
	"testing"

	"runar-integration/helpers"

	runar "github.com/icellan/runar/packages/runar-go"
)

// TestAddDataOutputEndToEnd compiles a stateful contract whose method calls
// this.addDataOutput(...), drives the call through RunarContract.Call with a
// MockProvider, and verifies the resulting tx carries the declared data
// output in position [1] (between the state output and the change output).
// This is the acceptance test for BSVM R9 — data outputs must appear in
// the tx in declaration order between state outputs and change, so the
// compile-time continuation-hash check matches at spend time.
func TestAddDataOutputEndToEnd(t *testing.T) {
	const source = `
import { StatefulSmartContract, ByteString } from 'runar-lang';

export class DataEmitter extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    public emit(payload: ByteString) {
        this.counter = this.counter + 1n;
        this.addDataOutput(0n, payload);
    }
}
`

	artifact, err := helpers.CompileSourceStringToSDKArtifact(
		source, "DataEmitter.runar.ts", map[string]interface{}{},
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	contract := runar.NewRunarContract(artifact, []interface{}{int64(0)})

	provider := runar.NewMockProvider("testnet")
	mockAddr := strings.Repeat("00", 20)
	signer := runar.NewMockSigner("", mockAddr)

	// Fund the mock address
	provider.AddUtxo(mockAddr, runar.UTXO{
		Txid:        strings.Repeat("aa", 32),
		OutputIndex: 0,
		Satoshis:    1_000_000,
		Script:      "76a914" + strings.Repeat("00", 20) + "88ac",
	})

	_, _, err = contract.Deploy(provider, signer, runar.DeployOptions{Satoshis: 10_000})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// OP_RETURN "bsvm-test" — the data payload
	payload := "6a09" + "6273766d2d74657374"

	txid, _, err := contract.Call("emit", []interface{}{payload}, provider, signer, nil)
	if err != nil {
		t.Fatalf("call emit: %v", err)
	}
	if txid == "" {
		t.Fatal("expected non-empty txid")
	}

	// Inspect the broadcasted tx.
	broadcasted := provider.GetBroadcastedTxs()
	if len(broadcasted) < 2 {
		t.Fatalf("expected >=2 broadcasted txs (deploy+call), got %d", len(broadcasted))
	}
	callTxHex := broadcasted[len(broadcasted)-1]
	outputs, err := parseOutputsFromRawTxHex(callTxHex)
	if err != nil {
		t.Fatalf("parse tx: %v", err)
	}

	// Expected output order for this single-state + single-data method:
	// [0] = state (stateful continuation)
	// [1] = data (OP_RETURN "bsvm-test" = the payload we passed)
	// [2] = change (P2PKH)
	if len(outputs) < 2 {
		t.Fatalf("expected at least 2 outputs (state + data), got %d: %v", len(outputs), outputs)
	}
	if outputs[1].script != payload {
		t.Errorf("expected data output at index 1 to be %s, got %s", payload, outputs[1].script)
	}
	if outputs[1].satoshis != 0 {
		t.Errorf("expected data output satoshis to be 0, got %d", outputs[1].satoshis)
	}
}

// parseOutputsFromRawTxHex extracts (script, satoshis) pairs from a raw
// transaction hex. Minimal parser — enough for assertions, not for
// production use.
func parseOutputsFromRawTxHex(txHex string) ([]parsedOutput, error) {
	return parseTx(txHex)
}

type parsedOutput struct {
	satoshis int64
	script   string
}

func parseTx(hex string) ([]parsedOutput, error) {
	pos := 0
	// version: 4 bytes
	pos += 8
	// input count (varint)
	nIn, w := readVarIntHex(hex, pos)
	pos += w
	for i := 0; i < nIn; i++ {
		pos += 64 + 8 // prevTxid + prevOutIndex
		scriptLen, slw := readVarIntHex(hex, pos)
		pos += slw + scriptLen*2 + 8 // script + sequence
	}
	// output count (varint)
	nOut, w := readVarIntHex(hex, pos)
	pos += w
	outs := make([]parsedOutput, 0, nOut)
	for i := 0; i < nOut; i++ {
		// satoshis: 8 bytes little-endian
		sats := int64(0)
		for j := 0; j < 8; j++ {
			b, err := parseHexByte(hex[pos : pos+2])
			if err != nil {
				return nil, err
			}
			sats |= int64(b) << (8 * j)
			pos += 2
		}
		scriptLen, slw := readVarIntHex(hex, pos)
		pos += slw
		script := hex[pos : pos+scriptLen*2]
		pos += scriptLen * 2
		outs = append(outs, parsedOutput{satoshis: sats, script: script})
	}
	return outs, nil
}

func readVarIntHex(hex string, pos int) (int, int) {
	first, _ := parseHexByte(hex[pos : pos+2])
	if first < 0xfd {
		return int(first), 2
	}
	if first == 0xfd {
		lo, _ := parseHexByte(hex[pos+2 : pos+4])
		hi, _ := parseHexByte(hex[pos+4 : pos+6])
		return int(lo) | (int(hi) << 8), 6
	}
	if first == 0xfe {
		b0, _ := parseHexByte(hex[pos+2 : pos+4])
		b1, _ := parseHexByte(hex[pos+4 : pos+6])
		b2, _ := parseHexByte(hex[pos+6 : pos+8])
		b3, _ := parseHexByte(hex[pos+8 : pos+10])
		return int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24), 10
	}
	b0, _ := parseHexByte(hex[pos+2 : pos+4])
	b1, _ := parseHexByte(hex[pos+4 : pos+6])
	b2, _ := parseHexByte(hex[pos+6 : pos+8])
	b3, _ := parseHexByte(hex[pos+8 : pos+10])
	return int(b0) | (int(b1) << 8) | (int(b2) << 16) | (int(b3) << 24), 18
}

func parseHexByte(s string) (uint64, error) {
	var val uint64
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			val |= uint64(c - 'A' + 10)
		default:
			return 0, nil
		}
	}
	return val, nil
}
