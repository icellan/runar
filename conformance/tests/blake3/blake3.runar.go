package contract

import "runar"

type Blake3Test struct {
	runar.SmartContract
	Expected runar.ByteString `runar:"readonly"`
}

func (c *Blake3Test) VerifyCompress(chainingValue runar.ByteString, block runar.ByteString) {
	result := runar.Blake3Compress(chainingValue, block)
	runar.Assert(result == c.Expected)
}

func (c *Blake3Test) VerifyHash(message runar.ByteString) {
	result := runar.Blake3Hash(message)
	runar.Assert(result == c.Expected)
}
