// F-063: the brief's shape on the Go surface -- an unknown function nested in
// checkMultiSig's PubKey array. Pre-fix the Go tier's typechecker never
// visited array-literal elements, so the call escaped the "only Rúnar
// built-ins" rule. Every tier must refuse it.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type N103 struct {
	runar.SmartContract
	Pk runar.PubKey `runar:"readonly"`
}

func (c *N103) Unlock(sig runar.Sig) {
	runar.Assert(runar.CheckMultiSig([1]runar.Sig{sig}, [2]runar.PubKey{c.Pk, totallyBogusFunction(1)}))
}
