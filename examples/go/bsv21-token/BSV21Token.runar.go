package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BSV21Token — Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
//
// BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
// of tick-based. The token ID is derived from the deploy transaction
// (<txid>_<vout>), eliminating ticker squatting and enabling admin-controlled
// distribution.
//
// # BSV-21 Token Lifecycle
//
//  1. Deploy+Mint — A single inscription deploys the token and mints the
//     initial supply in one atomic operation. The token ID is the outpoint of
//     the output containing this inscription.
//  2. Transfer    — Inscribe a transfer JSON referencing the token ID and
//     amount.
//
// The SDK helpers BSV21DeployMint and BSV21Transfer build the correct
// inscription payloads for each operation.
type BSV21Token struct {
	runar.SmartContract
	PubKeyHash runar.Addr `runar:"readonly"`
}

// Unlock verifies ownership of the private key corresponding to PubKeyHash.
func (c *BSV21Token) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
