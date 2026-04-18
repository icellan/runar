package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const betSats = 1000
const blackjackPayout = betSats * 3 / 2  // 3:2 payout for blackjack
const houseSats = blackjackPayout        // house stakes enough to cover a blackjack win
const contractSats = betSats + houseSats // total locked in the contract

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

func appendMethodIndex(s *script.Script, idx byte) {
	if idx == 0 {
		_ = s.AppendOpcodes(script.Op0)
	} else {
		_ = s.AppendOpcodes(0x50 + idx)
	}
}

// Method indices (declaration order in BlackjackBet.runar.ts)
const (
	methodSettleBlackjack = 0
	methodSettleWin       = 1
	methodSettleLoss      = 2
	methodCancel          = 3
)

func deployPlayerContract(player *Wallet, playerUTXO *UTXO, house *Wallet, houseUTXO *UTXO, oraclePubKey *big.Int, oracleThreshold int64) (*ContractState, *UTXO, *UTXO, error) {
	scriptHex, _, err := compileBlackjackBet(player.PubKeyHex, house.PubKeyHex, oraclePubKey, oracleThreshold, betSats)
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

func debugOutputHash(label string, tx *transaction.Transaction, preimage []byte) {
	// Compute hashOutputs from the actual transaction outputs
	var outputBuf []byte
	for _, out := range tx.Outputs {
		// Serialize: value(8 LE) + varint(scriptLen) + script
		val := make([]byte, 8)
		v := out.Satoshis
		for i := 0; i < 8; i++ {
			val[i] = byte(v & 0xff)
			v >>= 8
		}
		outputBuf = append(outputBuf, val...)
		scriptBytes := *out.LockingScript
		// varint
		if len(scriptBytes) < 0xfd {
			outputBuf = append(outputBuf, byte(len(scriptBytes)))
		}
		outputBuf = append(outputBuf, scriptBytes...)
	}
}

// settleBlackjack: player gets all contractSats (3:2 payout). Method index 0.
func settleBlackjack(cs *ContractState, player *Wallet, outcomeType int64, nonce int64, rabinSig *RabinSignature) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	playerScript, _ := script.NewFromHex(player.P2PKH)
	outputs := []*transaction.TransactionOutput{
		{Satoshis: contractSats, LockingScript: playerScript},
	}

	txHex, err := buildSpendingTxWithUnlockScript(contractUTXO, outputs, func(tx *transaction.Transaction) (*script.Script, error) {
		opPushTxSigBytes, preimage, err := signOpPushTx(tx, 0)
		if err != nil {
			return nil, err
		}

		sigHash := crypto.Sha256d(preimage)
		playerSigBytes, err := signWithHash(player, sigHash)
		if err != nil {
			return nil, err
		}

		// Stack order (bottom to top): [opPushTxSig] [outcomeType] [nonce] [rabinSig] [padding] [playerSig] [preimage] [methodIndex]
		s := &script.Script{}
		_ = s.AppendPushData(opPushTxSigBytes)
		appendScriptNumber(s, big.NewInt(outcomeType))
		appendScriptNumber(s, big.NewInt(nonce))
		appendScriptNumber(s, rabinSig.Sig)
		appendScriptNumber(s, rabinSig.Padding)
		_ = s.AppendPushData(playerSigBytes)
		_ = s.AppendPushData(preimage)
		appendMethodIndex(s, methodSettleBlackjack)

		debugOutputHash("settleBlackjack", tx, preimage)
		return s, nil
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

// settleWin: player gets 2*bet, house gets remainder. Method index 1.
func settleWin(cs *ContractState, player, house *Wallet, outcomeType int64, nonce int64, rabinSig *RabinSignature) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	playerScript, _ := script.NewFromHex(player.P2PKH)
	houseScript, _ := script.NewFromHex(house.P2PKH)
	outputs := []*transaction.TransactionOutput{
		{Satoshis: betSats * 2, LockingScript: playerScript},
		{Satoshis: contractSats - betSats*2, LockingScript: houseScript},
	}

	txHex, err := buildSpendingTxWithUnlockScript(contractUTXO, outputs, func(tx *transaction.Transaction) (*script.Script, error) {
		opPushTxSigBytes, preimage, err := signOpPushTx(tx, 0)
		if err != nil {
			return nil, err
		}

		sigHash := crypto.Sha256d(preimage)
		playerSigBytes, err := signWithHash(player, sigHash)
		if err != nil {
			return nil, err
		}

		s := &script.Script{}
		_ = s.AppendPushData(opPushTxSigBytes)
		appendScriptNumber(s, big.NewInt(outcomeType))
		appendScriptNumber(s, big.NewInt(nonce))
		appendScriptNumber(s, rabinSig.Sig)
		appendScriptNumber(s, rabinSig.Padding)
		_ = s.AppendPushData(playerSigBytes)
		_ = s.AppendPushData(preimage)
		appendMethodIndex(s, methodSettleWin)
		debugOutputHash("settleWin", tx, preimage)
		return s, nil
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

// settleLoss: house takes all contractSats. Method index 2.
func settleLoss(cs *ContractState, house *Wallet, outcomeType int64, nonce int64, rabinSig *RabinSignature) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	houseScript, _ := script.NewFromHex(house.P2PKH)
	outputs := []*transaction.TransactionOutput{
		{Satoshis: contractSats, LockingScript: houseScript},
	}

	txHex, err := buildSpendingTxWithUnlockScript(contractUTXO, outputs, func(tx *transaction.Transaction) (*script.Script, error) {
		opPushTxSigBytes, preimage, err := signOpPushTx(tx, 0)
		if err != nil {
			return nil, err
		}

		sigHash := crypto.Sha256d(preimage)
		houseSigBytes, err := signWithHash(house, sigHash)
		if err != nil {
			return nil, err
		}

		s := &script.Script{}
		_ = s.AppendPushData(opPushTxSigBytes)
		appendScriptNumber(s, big.NewInt(outcomeType))
		appendScriptNumber(s, big.NewInt(nonce))
		appendScriptNumber(s, rabinSig.Sig)
		appendScriptNumber(s, rabinSig.Padding)
		_ = s.AppendPushData(houseSigBytes)
		_ = s.AppendPushData(preimage)
		appendMethodIndex(s, methodSettleLoss)
		debugOutputHash("settleLoss", tx, preimage)
		return s, nil
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

// settlePush: both parties sign cancel, each gets their stake back. Method index 3.
func settlePush(cs *ContractState, player, house *Wallet) (string, error) {
	contractUTXO := &UTXO{
		Txid:     cs.ContractTxid,
		Vout:     cs.ContractVout,
		Satoshis: contractSats,
		Script:   cs.LockingScript,
	}

	txHex, err := buildCancelSpendingTx(player, house, contractUTXO, player.P2PKH, house.P2PKH, betSats, houseSats, methodCancel)
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
