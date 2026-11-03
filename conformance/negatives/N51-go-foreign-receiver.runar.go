//go:build ignore

// F-010 — an exported method on a type that is NOT the contract.
//
// `Drain` has a value receiver of the helper type `Unrelated`. Go-DSL parsers
// that ignored (or only checked pointer) receiver types compiled it into
// `Guarded` as a PUBLIC method whose body is `assert(true)`: a spending path
// anyone satisfies with `<amount> <1>` and no key. Pre-fix, @bsv/sdk
// Spend.validate accepted exactly that against the TS and Go artifacts.
//
// Every tier must refuse with:
//   method 'Drain' has receiver type 'Unrelated', not the contract type 'Guarded'; methods on other types are not allowed
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Guarded struct {
	runar.SmartContract
	PubKey runar.PubKey `runar:"readonly"`
}

func (c *Guarded) Unlock(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.PubKey))
}

type Unrelated struct{}

func (u Unrelated) Drain(amount runar.Bigint) {
	runar.Assert(true)
}
