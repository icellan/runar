package contract

import runar "github.com/icellan/runar/packages/runar-go"

// StackTrackerReproV10min — minimal reproducer for issue #36 in Go form.
//
// The first `if (... < outCount)` branch leaves scriptLen, blobLen, and
// blob as branch-private locals on the stack. Without the lowerIf branch
// reconciliation fix, post-ENDIF cleanup misindexed against `p` and the
// downstream OP_SPLIT aborted. Mirrors the TS fixture in
// examples/ts/if-without-else-multi-temp/.
type StackTrackerReproV10min struct {
	runar.SmartContract
}

func (c *StackTrackerReproV10min) VerifyMneeTxContainsBothOutputs(
	rawTx runar.ByteString,
	expectedMneeOutputBytes runar.ByteString,
	expectedExtraDataOutputBytes runar.ByteString,
) {
	var p runar.Bigint = 46

	outCount := runar.Bin2Num(runar.Cat(runar.Substr(rawTx, p, 1), runar.Num2Bin(0, 1)))
	runar.Assert(outCount < 253)
	runar.Assert(outCount <= 8)
	p = p + 1

	var foundMnee runar.Bool = false
	var foundExtra runar.Bool = false

	if 0 < outCount {
		scriptLen := runar.Bin2Num(runar.Cat(runar.Substr(rawTx, p+8, 1), runar.Num2Bin(0, 1)))
		runar.Assert(scriptLen < 253)
		blobLen := 8 + 1 + scriptLen
		blob := runar.Substr(rawTx, p, blobLen)
		if blob == expectedMneeOutputBytes {
			foundMnee = true
		}
		if blob == expectedExtraDataOutputBytes {
			foundExtra = true
		}
		p = p + blobLen
	}
	if 1 < outCount {
		scriptLen := runar.Bin2Num(runar.Cat(runar.Substr(rawTx, p+8, 1), runar.Num2Bin(0, 1)))
		runar.Assert(scriptLen < 253)
		blobLen := 8 + 1 + scriptLen
		blob := runar.Substr(rawTx, p, blobLen)
		if blob == expectedMneeOutputBytes {
			foundMnee = true
		}
		if blob == expectedExtraDataOutputBytes {
			foundExtra = true
		}
		p = p + blobLen
	}

	runar.Assert(foundMnee)
	runar.Assert(foundExtra)
}

func (c *StackTrackerReproV10min) Other(x runar.ByteString) {
	runar.Assert(x == x)
}
