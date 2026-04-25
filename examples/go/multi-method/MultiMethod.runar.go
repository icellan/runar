//go:build ignore

package contract

import "runar"

type MultiMethod struct {
	runar.SmartContract
	Owner  runar.PubKey `runar:"readonly"`
	Backup runar.PubKey `runar:"readonly"`
}

func (c *MultiMethod) computeThreshold(a runar.Int, b runar.Int) runar.Int {
	return a*b + 1
}

func (c *MultiMethod) SpendWithOwner(sig runar.Sig, amount runar.Int) {
	threshold := c.computeThreshold(amount, 2)
	runar.Assert(threshold > 10)
	runar.Assert(runar.CheckSig(sig, c.Owner))
}

func (c *MultiMethod) SpendWithBackup(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Backup))
}
