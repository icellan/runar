package runar

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// TokenWallet — Token UTXO management
// ---------------------------------------------------------------------------

// N-239 (user decision R92): Merge and Transfer drive an ABI that cannot be
// made sound, so they are deprecated rather than redesigned or removed. Each
// warns once per process on first use.
const (
	tokenWalletMergeDeprecation = "runar-sdk: warning: TokenWallet.Merge is deprecated and unsafe. " +
		"Its merge(sig, otherSupply, otherHolder) ABI cannot authenticate the companion input, " +
		"so a holder can call merge on ONE input with a made-up otherSupply (supply inflation). " +
		"Use the token-ft example (FungibleTokenExample, examples/*/token-ft/) instead (N-239).\n"
	tokenWalletTransferDeprecation = "runar-sdk: warning: TokenWallet.Transfer is deprecated and unsafe. " +
		"Its transfer(sig, to: Addr) ABI cannot re-key the PubKey holder from an Addr, " +
		"so the token stays with the current holder instead of moving to the recipient. " +
		"Use the token-ft example (FungibleTokenExample, examples/*/token-ft/) instead (N-239).\n"
)

var tokenWalletMergeWarnOnce, tokenWalletTransferWarnOnce sync.Once

// TokenWallet manages token UTXOs for a fungible token contract.
//
// Assumes the artifact describes a token contract with:
//   - A `transfer` public method.
//   - A state field named `balance`, `supply`, or `amount` of type int/bigint.
//
// This is a higher-level convenience wrapper around RunarContract for the
// common token use-case.
type TokenWallet struct {
	artifact *RunarArtifact
	provider Provider
	signer   Signer
}

// NewTokenWallet creates a new TokenWallet instance.
func NewTokenWallet(artifact *RunarArtifact, provider Provider, signer Signer) *TokenWallet {
	return &TokenWallet{
		artifact: artifact,
		provider: provider,
		signer:   signer,
	}
}

// GetBalance returns the total token balance across all UTXOs belonging to
// this wallet.
func (tw *TokenWallet) GetBalance() (int64, error) {
	utxos, err := tw.GetUtxos()
	if err != nil {
		return 0, err
	}

	var total int64
	for _, utxo := range utxos {
		contract, err := FromTxId(tw.artifact, utxo.Txid, utxo.OutputIndex, tw.provider)
		if err != nil {
			return 0, fmt.Errorf("TokenWallet.GetBalance: %w", err)
		}
		state := contract.GetState()
		balanceField := getBalanceField(state)
		total += toInt64(balanceField)
	}

	return total, nil
}

// Transfer transfers the entire balance of a token UTXO to a new address.
//
// The FungibleToken.transfer(sig, to) method transfers the full supply held
// in the UTXO to the given address. The signature is produced by this
// wallet's signer and passed as the first argument.
//
// recipientAddr is the BSV address of the recipient.
// amount is the minimum token balance required in the source UTXO.
// Returns the txid of the transfer transaction.
//
// Deprecated: unsafe (N-239). The transfer(sig, to: Addr) ABI cannot re-key
// a PubKey holder, so the token does not move to recipientAddr. Use the
// token-ft example (FungibleTokenExample) instead.
func (tw *TokenWallet) Transfer(recipientAddr string, amount int64) (string, error) {
	tokenWalletTransferWarnOnce.Do(func() { fmt.Fprint(os.Stderr, tokenWalletTransferDeprecation) })
	utxos, err := tw.GetUtxos()
	if err != nil {
		return "", err
	}
	if len(utxos) == 0 {
		return "", fmt.Errorf("TokenWallet.transfer: no token UTXOs found")
	}

	for _, utxo := range utxos {
		contract, err := FromTxId(tw.artifact, utxo.Txid, utxo.OutputIndex, tw.provider)
		if err != nil {
			continue
		}
		state := contract.GetState()
		balance := toInt64(getBalanceField(state))

		if balance >= amount {
			// FungibleToken.transfer(sig: Sig, to: Addr)
			// F-045: pass nil for the Sig so Call auto-signs the transaction
			// it actually builds and broadcasts. Signing a locally built
			// preliminary tx covers a different tx and is rejected on-chain.
			// An Addr is a 20-byte hash160: accept a Base58 address (as
			// documented), a raw hash160, or a public key.
			toPKH, err := addrToPKH(recipientAddr)
			if err != nil {
				return "", fmt.Errorf("TokenWallet.transfer: %w", err)
			}
			changeAddress, err := tw.signer.GetAddress()
			if err != nil {
				return "", fmt.Errorf("TokenWallet.transfer: getting address: %w", err)
			}

			txid, _, err := contract.Call(
				"transfer",
				[]interface{}{nil, toPKH},
				tw.provider,
				tw.signer,
				&CallOptions{ChangeAddress: changeAddress},
			)
			if err != nil {
				return "", fmt.Errorf("TokenWallet.transfer: %w", err)
			}
			return txid, nil
		}
	}

	return "", fmt.Errorf("TokenWallet.transfer: insufficient token balance for transfer of %d", amount)
}

// Merge merges two token UTXOs into a single UTXO.
//
// FungibleToken.merge(sig, otherSupply, otherHolder) combines the supply
// from two UTXOs. The second UTXO's supply and holder are read from its
// on-chain state and passed as arguments.
//
// Returns the txid of the merge transaction.
//
// Deprecated: unsafe (N-239). The merge(sig, otherSupply, otherHolder) ABI
// cannot authenticate its companion input, so a holder can inflate supply.
// Use the token-ft example (FungibleTokenExample) instead.
func (tw *TokenWallet) Merge() (string, error) {
	tokenWalletMergeWarnOnce.Do(func() { fmt.Fprint(os.Stderr, tokenWalletMergeDeprecation) })
	utxos, err := tw.GetUtxos()
	if err != nil {
		return "", err
	}
	if len(utxos) < 2 {
		return "", fmt.Errorf("TokenWallet.merge: need at least 2 UTXOs to merge")
	}

	firstUtxo := utxos[0]
	contract, err := FromTxId(tw.artifact, firstUtxo.Txid, firstUtxo.OutputIndex, tw.provider)
	if err != nil {
		return "", fmt.Errorf("TokenWallet.merge: %w", err)
	}

	// Read the second UTXO's state
	secondUtxo := utxos[1]
	secondContract, err := FromTxId(tw.artifact, secondUtxo.Txid, secondUtxo.OutputIndex, tw.provider)
	if err != nil {
		return "", fmt.Errorf("TokenWallet.merge: reading second UTXO: %w", err)
	}
	secondState := secondContract.GetState()
	otherSupply := toInt64(getBalanceField(secondState))
	otherHolder := ""
	if h, ok := secondState["holder"]; ok {
		otherHolder = fmt.Sprintf("%v", h)
	}

	// FungibleToken.merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey)
	// F-045: spend BOTH token UTXOs in one tx. Each input's unlock carries
	// the OTHER input's supply/holder, and every Sig is nil so Call signs
	// each input over the transaction it actually broadcasts.
	firstState := contract.GetState()
	firstSupply := toInt64(getBalanceField(firstState))
	firstHolder := ""
	if h, ok := firstState["holder"]; ok {
		firstHolder = fmt.Sprintf("%v", h)
	}

	changeAddress, err := tw.signer.GetAddress()
	if err != nil {
		return "", fmt.Errorf("TokenWallet.merge: getting address: %w", err)
	}

	txid, _, err := contract.Call(
		"merge",
		[]interface{}{nil, int64(otherSupply), otherHolder},
		tw.provider,
		tw.signer,
		&CallOptions{
			ChangeAddress:               changeAddress,
			AdditionalContractInputs:    []*UTXO{&secondUtxo},
			AdditionalContractInputArgs: [][]interface{}{{nil, int64(firstSupply), firstHolder}},
		},
	)
	if err != nil {
		return "", fmt.Errorf("TokenWallet.merge: %w", err)
	}
	return txid, nil
}

// GetUtxos returns all token UTXOs associated with this wallet's signer address.
func (tw *TokenWallet) GetUtxos() ([]UTXO, error) {
	address, err := tw.signer.GetAddress()
	if err != nil {
		return nil, fmt.Errorf("TokenWallet.getUtxos: getting address: %w", err)
	}
	allUtxos, err := tw.provider.GetUtxos(address)
	if err != nil {
		return nil, fmt.Errorf("TokenWallet.getUtxos: %w", err)
	}

	// N-076: the artifact script is the TEMPLATE; every slot (constructor
	// arg, codeSepIndex, code-part length) is a placeholder that deployment
	// replaces, so a raw prefix of it never matches a slotted deployment. With
	// constructor slots, use the slot-aware MatchesArtifact; a template with
	// none is deployed verbatim, so its literal prefix is exact.
	template := tw.artifact.Script
	slotted := len(tw.artifact.ConstructorSlots) > 0

	var filtered []UTXO
	for _, utxo := range allUtxos {
		if utxo.Script == "" || template == "" {
			filtered = append(filtered, utxo)
			continue
		}
		if !slotted {
			if strings.HasPrefix(utxo.Script, template) {
				filtered = append(filtered, utxo)
			}
			continue
		}
		// N-317: any UTXO the provider lists is attacker-influenced; a script
		// that is not whole hex bytes is not an instance of this contract.
		if !isHexBytes(utxo.Script) {
			continue
		}
		// MatchesArtifact strips the state section only for artifacts that
		// declare StateFields; cut it here for the rest.
		codeHex := utxo.Script
		if len(tw.artifact.StateFields) == 0 {
			if pos := FindLastOpReturn(codeHex); pos != -1 {
				codeHex = codeHex[:pos]
			}
		}
		// A script that is not well-formed at the artifact's slot offsets
		// (F-238) returns an error and is not an instance of this contract.
		if ok, err := MatchesArtifact(tw.artifact, codeHex); err == nil && ok {
			filtered = append(filtered, utxo)
		}
	}
	return filtered, nil
}

// addrToPKH returns the 20-byte hash160 (hex) an Addr argument carries, from a
// Base58 address, a raw hash160, or a public key. BuildP2PKHScript panics on
// malformed input; surface that as an error instead.
func addrToPKH(addr string) (pkh string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid recipient address %q: %v", addr, r)
		}
	}()
	return BuildP2PKHScript(addr)[6:46], nil
}

// getBalanceField extracts the balance/supply/amount field from state.
func getBalanceField(state map[string]interface{}) interface{} {
	if v, ok := state["supply"]; ok {
		return v
	}
	if v, ok := state["balance"]; ok {
		return v
	}
	if v, ok := state["amount"]; ok {
		return v
	}
	return int64(0)
}
