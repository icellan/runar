package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Directives is the Go port of
// examples/ts/compiler-directives/Directives.runar.ts.
//
// The two compiler directives in their native Go DSL spelling (N-093): the
// struct tag option embedAlways keeps DeployTag in the locking script although
// no method reads it, and the directive comment //runar:sighash on the line
// directly above SpendSingle declares the BIP-143 mode it commits to.
type Directives struct {
	runar.SmartContract
	PubKeyHash runar.Addr       `runar:"readonly"`
	DeployTag  runar.ByteString `runar:"readonly,embedAlways"`
}

func (c *Directives) SpendAll(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}

//runar:sighash SINGLE|FORKID
func (c *Directives) SpendSingle(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
