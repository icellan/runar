package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

var rpcID atomic.Int64

func rpcURL() string {
	if v := os.Getenv("RPC_URL"); v != "" {
		return v
	}
	return "http://localhost:18332"
}

func rpcUser() string {
	if v := os.Getenv("RPC_USER"); v != "" {
		return v
	}
	return "bitcoin"
}

func rpcPass() string {
	if v := os.Getenv("RPC_PASS"); v != "" {
		return v
	}
	return "bitcoin"
}

type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcCall(method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}

	body, _ := json.Marshal(rpcRequest{
		JSONRPC: "1.0",
		ID:      rpcID.Add(1),
		Method:  method,
		Params:  params,
	})

	req, _ := http.NewRequest("POST", rpcURL(), bytes.NewReader(body))
	req.SetBasicAuth(rpcUser(), rpcPass())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC %s: %w", method, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RPC %s HTTP %d: %s", method, resp.StatusCode, string(respBody))
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("RPC %s: bad JSON: %w", method, err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC %s: %s", method, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func mine(nBlocks int) error {
	_, err := rpcCall("generate", nBlocks)
	if err != nil {
		addr, err2 := rpcCall("getnewaddress")
		if err2 != nil {
			return fmt.Errorf("mine: %w", err)
		}
		var addrStr string
		json.Unmarshal(addr, &addrStr)
		_, err = rpcCall("generatetoaddress", nBlocks, addrStr)
	}
	return err
}

type UTXO struct {
	Txid     string
	Vout     uint32
	Satoshis uint64
	Script   string
}

type Wallet struct {
	PrivKey   *ec.PrivateKey
	PubKey    *ec.PublicKey
	PubKeyHex string
	Address   string
	P2PKH     string
	Balance   int64
}

func newWallet() (*Wallet, error) {
	privKey, err := ec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	pubKey := privKey.PubKey()
	pubKeyHex := hex.EncodeToString(pubKey.Compressed())

	addr, err := script.NewAddressFromPublicKey(pubKey, false)
	if err != nil {
		return nil, err
	}

	pkh := crypto.Hash160(pubKey.Compressed())
	p2pkh := "76a914" + hex.EncodeToString(pkh) + "88ac"

	return &Wallet{
		PrivKey:   privKey,
		PubKey:    pubKey,
		PubKeyHex: pubKeyHex,
		Address:   addr.AddressString,
		P2PKH:     p2pkh,
		Balance:   0,
	}, nil
}

func fundWallet(address string, btcAmount float64) (string, error) {
	result, err := rpcCall("sendtoaddress", address, btcAmount)
	if err != nil {
		return "", err
	}
	var txid string
	json.Unmarshal(result, &txid)
	return txid, nil
}

func findUTXO(txid, expectedScript string) (*UTXO, error) {
	result, err := rpcCall("getrawtransaction", txid, true)
	if err != nil {
		return nil, err
	}

	var tx struct {
		Vout []struct {
			Value        float64 `json:"value"`
			N            uint32  `json:"n"`
			ScriptPubKey struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	json.Unmarshal(result, &tx)

	for _, v := range tx.Vout {
		if v.ScriptPubKey.Hex == expectedScript {
			sats := uint64(v.Value*1e8 + 0.5)
			return &UTXO{
				Txid:     txid,
				Vout:     v.N,
				Satoshis: sats,
				Script:   v.ScriptPubKey.Hex,
			}, nil
		}
	}

	return nil, fmt.Errorf("no output matching script in TX %s", txid)
}

func buildFundingTx(alice, bob *Wallet, aliceUTXO, bobUTXO *UTXO, lockingScriptHex string, contractSats uint64) (string, error) {
	tx := transaction.NewTransaction()

	aliceUnlocker, err := p2pkh.Unlock(alice.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("alice unlocker: %w", err)
	}
	if err := tx.AddInputFrom(aliceUTXO.Txid, aliceUTXO.Vout, aliceUTXO.Script, aliceUTXO.Satoshis, aliceUnlocker); err != nil {
		return "", fmt.Errorf("add alice input: %w", err)
	}

	bobUnlocker, err := p2pkh.Unlock(bob.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("bob unlocker: %w", err)
	}
	if err := tx.AddInputFrom(bobUTXO.Txid, bobUTXO.Vout, bobUTXO.Script, bobUTXO.Satoshis, bobUnlocker); err != nil {
		return "", fmt.Errorf("add bob input: %w", err)
	}

	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		return "", fmt.Errorf("parse lock script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      contractSats,
		LockingScript: lockScript,
	})

	changeSats := aliceUTXO.Satoshis + bobUTXO.Satoshis - contractSats
	if changeSats > 546 {
		aliceChangeScript, _ := script.NewFromHex(alice.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      changeSats / 2,
			LockingScript: aliceChangeScript,
		})
		bobChangeScript, _ := script.NewFromHex(bob.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      changeSats - changeSats/2,
			LockingScript: bobChangeScript,
		})
	}

	if err := tx.Sign(); err != nil {
		return "", fmt.Errorf("sign funding tx: %w", err)
	}

	return tx.String(), nil
}

func buildSpendingTx(alice, bob *Wallet, contractUTXO *UTXO, winnerP2PKH string, contractSats uint64) (string, error) {
	tx := transaction.NewTransaction()

	if err := tx.AddInputFrom(contractUTXO.Txid, contractUTXO.Vout, contractUTXO.Script, contractSats, nil); err != nil {
		return "", fmt.Errorf("add contract input: %w", err)
	}

	winnerScript, err := script.NewFromHex(winnerP2PKH)
	if err != nil {
		return "", fmt.Errorf("parse winner script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      contractSats,
		LockingScript: winnerScript,
	})

	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return "", fmt.Errorf("calc sighash: %w", err)
	}

	aliceSig, err := alice.PrivKey.Sign(sigHash)
	if err != nil {
		return "", fmt.Errorf("alice sign: %w", err)
	}
	aliceSigBytes := append(aliceSig.Serialize(), byte(sighash.AllForkID))

	bobSig, err := bob.PrivKey.Sign(sigHash)
	if err != nil {
		return "", fmt.Errorf("bob sign: %w", err)
	}
	bobSigBytes := append(bobSig.Serialize(), byte(sighash.AllForkID))

	unlockScript := &script.Script{}
	_ = unlockScript.AppendPushData(aliceSigBytes)
	_ = unlockScript.AppendPushData(bobSigBytes)
	_ = unlockScript.AppendOpcodes(script.Op1)

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx.String(), nil
}

func broadcastTx(txHex string) (string, error) {
	result, err := rpcCall("sendrawtransaction", txHex)
	if err != nil {
		return "", err
	}
	var txid string
	json.Unmarshal(result, &txid)
	return txid, nil
}

func findAllUTXOs(txid, expectedScript string) ([]*UTXO, error) {
	result, err := rpcCall("getrawtransaction", txid, true)
	if err != nil {
		return nil, err
	}

	var tx struct {
		Vout []struct {
			Value        float64 `json:"value"`
			N            uint32  `json:"n"`
			ScriptPubKey struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	json.Unmarshal(result, &tx)

	var utxos []*UTXO
	for _, v := range tx.Vout {
		if v.ScriptPubKey.Hex == expectedScript {
			sats := uint64(v.Value*1e8 + 0.5)
			utxos = append(utxos, &UTXO{
				Txid:     txid,
				Vout:     v.N,
				Satoshis: sats,
				Script:   v.ScriptPubKey.Hex,
			})
		}
	}
	return utxos, nil
}

