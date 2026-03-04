package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const betSats = 1000
const contractSats = betSats * 2

type ContractState struct {
	PlayerIndex   int    `json:"playerIndex"`
	LockingScript string `json:"-"`
	ContractTxid  string `json:"contractTxid"`
	ContractVout  uint32 `json:"-"`
	SettleTxid    string `json:"settleTxid,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
	RabinSigHex   string `json:"rabinSig,omitempty"`
	RabinPadHex   string `json:"rabinPadding,omitempty"`
}

func encodeScriptNumber(n *big.Int) []byte {
	if n.Sign() == 0 {
		return nil
	}

	negative := n.Sign() < 0
	absVal := new(big.Int).Abs(n)

	var bytes []byte
	mask := big.NewInt(0xff)
	tmp := new(big.Int).Set(absVal)

	for tmp.Sign() > 0 {
		bytes = append(bytes, byte(new(big.Int).And(tmp, mask).Int64()))
		tmp.Rsh(tmp, 8)
	}

	if bytes[len(bytes)-1]&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] |= 0x80
	}

	return bytes
}

func appendScriptNumber(s *script.Script, n *big.Int) {
	if n.Sign() == 0 {
		_ = s.AppendOpcodes(script.Op0)
		return
	}

	if n.Sign() > 0 && n.BitLen() <= 4 && n.Int64() >= 1 && n.Int64() <= 16 {
		_ = s.AppendOpcodes(byte(0x50 + n.Int64()))
		return
	}

	if n.Sign() < 0 && n.Cmp(big.NewInt(-1)) == 0 {
		_ = s.AppendOpcodes(script.Op1NEGATE)
		return
	}

	bytes := encodeScriptNumber(n)
	_ = s.AppendPushData(bytes)
}

func deployPlayerContract(player *Wallet, playerUTXO *UTXO, house *Wallet, houseUTXO *UTXO, oraclePubKey *big.Int, roundId int64) (*ContractState, *UTXO, *UTXO, error) {
	scriptHex, _, err := compileBlackjackBet(player.PubKeyHex, house.PubKeyHex, oraclePubKey, roundId)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile: %w", err)
	}

	txHex, err := buildDualFundingTx(player, house, playerUTXO, houseUTXO, scriptHex, contractSats)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build funding tx: %w", err)
	}

	txid, err := broadcastTx(txHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("broadcast: %w", err)
	}

	var newPlayerUTXO, newHouseUTXO *UTXO

	playerUTXOs, _ := findAllUTXOs(txid, player.P2PKH)
	if len(playerUTXOs) > 0 {
		newPlayerUTXO = playerUTXOs[0]
	}

	houseUTXOs, _ := findAllUTXOs(txid, house.P2PKH)
	if len(houseUTXOs) > 0 {
		newHouseUTXO = houseUTXOs[0]
	}

	cs := &ContractState{
		LockingScript: scriptHex,
		ContractTxid:  txid,
		ContractVout:  0,
	}

	return cs, newPlayerUTXO, newHouseUTXO, nil
}

func settlePlayerWin(cs *ContractState, player *Wallet, _ *Wallet, outcome int64, rabinSig *RabinSignature) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	winnerScript, _ := script.NewFromHex(player.P2PKH)
	outputs := []*transaction.TransactionOutput{
		{Satoshis: contractSats, LockingScript: winnerScript},
	}

	txHex, err := buildSpendingTxWithUnlockScript(contractUTXO, outputs, func(sigHash []byte) (*script.Script, error) {
		playerSigBytes, err := signSighash(player, sigHash)
		if err != nil {
			return nil, err
		}

		unlockScript := &script.Script{}
		appendScriptNumber(unlockScript, big.NewInt(outcome))
		appendScriptNumber(unlockScript, rabinSig.Sig)
		appendScriptNumber(unlockScript, rabinSig.Padding)
		_ = unlockScript.AppendPushData(playerSigBytes)
		_ = unlockScript.AppendPushData([]byte{0x00})
		_ = unlockScript.AppendOpcodes(script.Op0)
		return unlockScript, nil
	})
	if err != nil {
		return "", err
	}

	txid, err := broadcastTx(txHex)
	if err != nil {
		return "", fmt.Errorf("broadcast settle: %w", err)
	}

	cs.SettleTxid = txid
	cs.RabinSigHex = hex.EncodeToString(rabinSig.Sig.Bytes())
	cs.RabinPadHex = hex.EncodeToString(rabinSig.Padding.Bytes())

	return txid, nil
}

func settleHouseWin(cs *ContractState, _ *Wallet, house *Wallet, outcome int64, rabinSig *RabinSignature) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	winnerScript, _ := script.NewFromHex(house.P2PKH)
	outputs := []*transaction.TransactionOutput{
		{Satoshis: contractSats, LockingScript: winnerScript},
	}

	txHex, err := buildSpendingTxWithUnlockScript(contractUTXO, outputs, func(sigHash []byte) (*script.Script, error) {
		houseSigBytes, err := signSighash(house, sigHash)
		if err != nil {
			return nil, err
		}

		unlockScript := &script.Script{}
		appendScriptNumber(unlockScript, big.NewInt(outcome))
		appendScriptNumber(unlockScript, rabinSig.Sig)
		appendScriptNumber(unlockScript, rabinSig.Padding)
		_ = unlockScript.AppendPushData([]byte{0x00})
		_ = unlockScript.AppendPushData(houseSigBytes)
		_ = unlockScript.AppendOpcodes(script.Op0)
		return unlockScript, nil
	})
	if err != nil {
		return "", err
	}

	txid, err := broadcastTx(txHex)
	if err != nil {
		return "", fmt.Errorf("broadcast settle: %w", err)
	}

	cs.SettleTxid = txid
	cs.RabinSigHex = hex.EncodeToString(rabinSig.Sig.Bytes())
	cs.RabinPadHex = hex.EncodeToString(rabinSig.Padding.Bytes())

	return txid, nil
}

func settlePush(cs *ContractState, player, house *Wallet) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	txHex, err := buildCancelSpendingTx(player, house, contractUTXO, player.P2PKH, house.P2PKH, betSats)
	if err != nil {
		return "", err
	}

	txid, err := broadcastTx(txHex)
	if err != nil {
		return "", fmt.Errorf("broadcast cancel: %w", err)
	}

	cs.SettleTxid = txid
	return txid, nil
}
