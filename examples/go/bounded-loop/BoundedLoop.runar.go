//go:build ignore

package contract

import "runar"

type BoundedLoop struct {
	runar.SmartContract
	ExpectedSum runar.Int `runar:"readonly"`
}

func (c *BoundedLoop) Verify(start runar.Int) {
	sum := runar.Int(0)
	for i := runar.Int(0); i < 5; i++ {
		sum = sum + start + i
	}
	runar.Assert(sum == c.ExpectedSum)
}
