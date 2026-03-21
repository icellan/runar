package contract

import "runar"

type MessageBoard struct {
	runar.StatefulSmartContract
	Message runar.ByteString
	Owner   runar.PubKey `runar:"readonly"`
}

func (c *MessageBoard) Post(newMessage runar.ByteString) {
	c.Message = newMessage
	runar.Assert(true)
}

func (c *MessageBoard) Burn(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}
