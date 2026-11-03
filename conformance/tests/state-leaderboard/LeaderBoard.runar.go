package contract

import runar "github.com/icellan/runar/packages/runar-go"

// LeaderBoard -- F-352 second witness for the mutable-state shape
// {PubKey, bigint}.
type LeaderBoard struct {
	runar.StatefulSmartContract
	Leader   runar.PubKey
	TopScore runar.Bigint
}

func (c *LeaderBoard) Claim(sig runar.Sig, newLeader runar.PubKey, score runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Leader))
	runar.Assert(score > c.TopScore)
	c.Leader = newLeader
	c.TopScore = score
}
