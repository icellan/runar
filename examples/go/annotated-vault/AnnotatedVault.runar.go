package contract

import runar "github.com/icellan/runar/packages/runar-go"

// AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
// ByteString state field (Memo) BEFORE a mutable PubKey (Owner). Anyone may
// replace the memo; only the owner may withdraw.
type AnnotatedVault struct {
	runar.StatefulSmartContract
	Memo    runar.ByteString
	Owner   runar.PubKey
	Balance runar.Bigint
}

// Annotate replaces the memo. Anyone can call this method.
func (c *AnnotatedVault) Annotate(nextMemo runar.ByteString) {
	c.Memo = nextMemo
}

// Withdraw lets only the owner spend.
func (c *AnnotatedVault) Withdraw(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}
