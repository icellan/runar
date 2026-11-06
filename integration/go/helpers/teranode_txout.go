package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Teranode does not implement gettxout ("Command unimplemented"). Its asset
// service answers the same question for a known txid: GET
// /api/v1/utxos/:hash/json lists every output with a status ("OK" while
// unspent, "SPENT" plus spendingData once consumed).

func assetURL() string {
	if u := os.Getenv("ASSET_URL"); u != "" {
		return u
	}
	return "http://localhost:18090" // integration/teranode-compose asset port
}

func getTxOutTeranode(txid string, vout int) (map[string]interface{}, error) {
	resp, err := rpcClient.Get(fmt.Sprintf("%s/api/v1/utxos/%s/json", assetURL(), txid))
	if err != nil {
		return nil, fmt.Errorf("asset utxos(%s): %w", txid, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // unknown tx: same answer gettxout gives
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asset utxos(%s): HTTP %d: %s", txid, resp.StatusCode, body)
	}
	return teranodeTxOutFromUtxosJSON(body, vout)
}

// teranodeTxOutFromUtxosJSON maps the asset-service response to gettxout's
// contract: nil unless the output exists with status "OK". Any other status
// (SPENT, or one this harness does not know) reads as "not unspent", so a
// caller asserting an output is still unspent fails closed.
func teranodeTxOutFromUtxosJSON(body []byte, vout int) (map[string]interface{}, error) {
	var outs []struct {
		Vout          int    `json:"vout"`
		LockingScript string `json:"lockingScript"`
		Satoshis      int64  `json:"satoshis"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(body, &outs); err != nil {
		return nil, fmt.Errorf("asset utxos: parse: %w (body: %s)", err, body)
	}
	for _, o := range outs {
		if o.Vout != vout {
			continue
		}
		if o.Status != "OK" {
			return nil, nil
		}
		return map[string]interface{}{
			"value":        o.Satoshis,
			"scriptPubKey": map[string]interface{}{"hex": o.LockingScript},
		}, nil
	}
	return nil, nil
}
