package contract

import runar "github.com/icellan/runar/packages/runar-go"

// DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
type DigestLog struct {
	runar.StatefulSmartContract
	Digest runar.Ripemd160Hash // no tag = mutable state
}

func (c *DigestLog) Replace(newDigest runar.Ripemd160Hash, version runar.Bigint) {
	runar.Assert(version > 0)
	c.Digest = newDigest
}
