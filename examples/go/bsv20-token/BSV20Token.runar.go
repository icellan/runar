package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BSV20Token — Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
//
// BSV-20 is a 1sat ordinals token standard where fungible tokens are represented
// as inscriptions on P2PKH UTXOs. The contract logic is standard P2PKH — the
// token semantics (deploy, mint, transfer) are encoded in the inscription
// envelope and interpreted by indexers, not by the script itself.
//
// # BSV-20 Token Lifecycle
//
//  1. Deploy   — Inscribe a deploy JSON
//     ({"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}) onto a
//     UTXO to register a new ticker. First deployer wins.
//  2. Mint     — Inscribe a mint JSON
//     ({"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}) to claim tokens
//     up to the per-mint limit.
//  3. Transfer — Inscribe a transfer JSON
//     ({"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}) to move
//     tokens between addresses.
//
// The SDK helpers BSV20Deploy, BSV20Mint and BSV20Transfer build the correct
// inscription payloads for each operation.
type BSV20Token struct {
	runar.SmartContract
	PubKeyHash runar.Addr `runar:"readonly"`
}

// Unlock verifies ownership of the private key corresponding to PubKeyHash.
func (c *BSV20Token) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
