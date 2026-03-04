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

func buildFundingTx(funder *Wallet, funderUTXO *UTXO, lockingScriptHex string, contractSats uint64) (string, error) {
	tx := transaction.NewTransaction()

	unlocker, err := p2pkh.Unlock(funder.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("unlocker: %w", err)
	}
	if err := tx.AddInputFrom(funderUTXO.Txid, funderUTXO.Vout, funderUTXO.Script, funderUTXO.Satoshis, unlocker); err != nil {
		return "", fmt.Errorf("add input: %w", err)
	}

	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		return "", fmt.Errorf("parse lock script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      contractSats,
		LockingScript: lockScript,
	})

	changeSats := funderUTXO.Satoshis - contractSats
	if changeSats > 546 {
		changeScript, _ := script.NewFromHex(funder.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      changeSats,
			LockingScript: changeScript,
		})
	}

	if err := tx.Sign(); err != nil {
		return "", fmt.Errorf("sign funding tx: %w", err)
	}

	return tx.String(), nil
}

func buildDualFundingTx(player, house *Wallet, playerUTXO, houseUTXO *UTXO, lockingScriptHex string, contractSats uint64) (string, error) {
	tx := transaction.NewTransaction()

	playerUnlocker, err := p2pkh.Unlock(player.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("player unlocker: %w", err)
	}
	if err := tx.AddInputFrom(playerUTXO.Txid, playerUTXO.Vout, playerUTXO.Script, playerUTXO.Satoshis, playerUnlocker); err != nil {
		return "", fmt.Errorf("add player input: %w", err)
	}

	houseUnlocker, err := p2pkh.Unlock(house.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("house unlocker: %w", err)
	}
	if err := tx.AddInputFrom(houseUTXO.Txid, houseUTXO.Vout, houseUTXO.Script, houseUTXO.Satoshis, houseUnlocker); err != nil {
		return "", fmt.Errorf("add house input: %w", err)
	}

	lockScript, err := script.NewFromHex(lockingScriptHex)
	if err != nil {
		return "", fmt.Errorf("parse lock script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      contractSats,
		LockingScript: lockScript,
	})

	changeSats := playerUTXO.Satoshis + houseUTXO.Satoshis - contractSats
	if changeSats > 546 {
		playerChange := changeSats / 2
		houseChange := changeSats - playerChange

		playerChangeScript, _ := script.NewFromHex(player.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      playerChange,
			LockingScript: playerChangeScript,
		})
		houseChangeScript, _ := script.NewFromHex(house.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      houseChange,
			LockingScript: houseChangeScript,
		})
	}

	if err := tx.Sign(); err != nil {
		return "", fmt.Errorf("sign funding tx: %w", err)
	}

	return tx.String(), nil
}

func buildCancelSpendingTx(player, house *Wallet, contractUTXO *UTXO, playerP2PKH, houseP2PKH string, betSats uint64) (string, error) {
	tx := transaction.NewTransaction()

	if err := tx.AddInputFrom(contractUTXO.Txid, contractUTXO.Vout, contractUTXO.Script, contractUTXO.Satoshis, nil); err != nil {
		return "", fmt.Errorf("add contract input: %w", err)
	}

	playerScript, _ := script.NewFromHex(playerP2PKH)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      betSats,
		LockingScript: playerScript,
	})

	houseScript, _ := script.NewFromHex(houseP2PKH)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      betSats,
		LockingScript: houseScript,
	})

	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return "", fmt.Errorf("calc sighash: %w", err)
	}

	playerSig, err := player.PrivKey.Sign(sigHash)
	if err != nil {
		return "", fmt.Errorf("player sign: %w", err)
	}
	playerSigBytes := append(playerSig.Serialize(), byte(sighash.AllForkID))

	houseSig, err := house.PrivKey.Sign(sigHash)
	if err != nil {
		return "", fmt.Errorf("house sign: %w", err)
	}
	houseSigBytes := append(houseSig.Serialize(), byte(sighash.AllForkID))

	unlockScript := &script.Script{}
	_ = unlockScript.AppendPushData(playerSigBytes)
	_ = unlockScript.AppendPushData(houseSigBytes)
	_ = unlockScript.AppendOpcodes(script.Op1)

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx.String(), nil
}

func buildSpendingTxWithUnlockScript(contractUTXO *UTXO, outputs []*transaction.TransactionOutput, buildUnlock func(sigHash []byte) (*script.Script, error)) (string, error) {
	tx := transaction.NewTransaction()

	if err := tx.AddInputFrom(contractUTXO.Txid, contractUTXO.Vout, contractUTXO.Script, contractUTXO.Satoshis, nil); err != nil {
		return "", fmt.Errorf("add contract input: %w", err)
	}

	for _, out := range outputs {
		tx.AddOutput(out)
	}

	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return "", fmt.Errorf("calc sighash: %w", err)
	}

	unlockScript, err := buildUnlock(sigHash)
	if err != nil {
		return "", fmt.Errorf("build unlock script: %w", err)
	}

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx.String(), nil
}

func signSighash(w *Wallet, sigHash []byte) ([]byte, error) {
	sig, err := w.PrivKey.Sign(sigHash)
	if err != nil {
		return nil, err
	}
	return append(sig.Serialize(), byte(sighash.AllForkID)), nil
}

func buildOpReturnTx(funder *Wallet, funderUTXO *UTXO, data []byte) (string, error) {
	tx := transaction.NewTransaction()

	unlocker, err := p2pkh.Unlock(funder.PrivKey, nil)
	if err != nil {
		return "", fmt.Errorf("unlocker: %w", err)
	}
	if err := tx.AddInputFrom(funderUTXO.Txid, funderUTXO.Vout, funderUTXO.Script, funderUTXO.Satoshis, unlocker); err != nil {
		return "", fmt.Errorf("add input: %w", err)
	}

	opReturnScript := &script.Script{}
	_ = opReturnScript.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	_ = opReturnScript.AppendPushData([]byte("SCRIPT21"))
	_ = opReturnScript.AppendPushData(data)

	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnScript,
	})

	changeSats := funderUTXO.Satoshis
	if changeSats > 546 {
		changeScript, _ := script.NewFromHex(funder.P2PKH)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      changeSats,
			LockingScript: changeScript,
		})
	}

	if err := tx.Sign(); err != nil {
		return "", fmt.Errorf("sign op_return tx: %w", err)
	}

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
