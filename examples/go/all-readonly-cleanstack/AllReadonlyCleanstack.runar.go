//go:build ignore

// EXCLUDED FROM THE GO BUILD — Go rejects the unused local that IS the fixture.
//
//	declared and not used: ownerCopy
//
// `ownerCopy := c.Owner` is not dead code here, it is the regression. The
// binding force-embeds the readonly field onto the stack where nothing consumes
// it, which is what reproduced issue #44 — the leftover item survived the
// terminal method and mainnet rejected the spend with "Script did not clean its
// stack". Go's unused-variable rule is a compile error, not a warning, so there
// is no build tag or pragma that keeps the binding and satisfies the compiler.
//
// `_ = ownerCopy` compiles, and was measured: it adds a `load_const
// @ref:ownerCopy` binding to the emitted ANF IR, so it changes the contract the
// seven tiers compare and moves this fixture's golden. Silently weakening the
// regression to get a green build is worse than the exclusion.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// AllReadonlyCleanstack — regression fixture for issue #44.
//
// A StatefulSmartContract with ZERO mutable fields (only a readonly Owner)
// plus a readonly-field-binding in a terminal method. The ownerCopy := c.Owner
// binding force-embeds the readonly field onto the stack; it is not consumed by
// the terminal CheckSig assertion, leaving an excess stack item below the
// top-of-stack boolean. Before the fix, the leftover survived and the spend was
// rejected on mainnet with "Script did not clean its stack". The fix runs the
// stack cleanup for every public method, emitting the trailing OP_NIP.
type AllReadonlyCleanstack struct {
	runar.StatefulSmartContract
	Owner runar.PubKey `runar:"readonly"`
}

func (c *AllReadonlyCleanstack) Claim(sig runar.Sig) {
	ownerCopy := c.Owner
	runar.Assert(runar.CheckSig(sig, c.Owner))
}
