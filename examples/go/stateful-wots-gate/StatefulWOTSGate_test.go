package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestStatefulWOTSGate_Compile(t *testing.T) {
	if err := runar.CompileCheck("StatefulWOTSGate.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Advance verifies a WOTS+ signature and only then bumps Count. Both halves
// matter: a gate that verified nothing would let Count advance for free, and a
// gate that verified but forgot the increment would leave the state stuck.
func TestStatefulWOTSGate_AdvancesOnAValidSignature(t *testing.T) {
	seed := make([]byte, 32)
	pubSeed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
		pubSeed[i] = byte(0x80 + i)
	}
	kp := runar.WotsKeygen(seed, pubSeed)
	msg := []byte("advance the gate")
	sig := runar.WotsSign(msg, kp.SK, kp.PubSeed)

	c := &StatefulWOTSGate{Count: 41}
	c.Advance(runar.ByteString(msg), runar.ByteString(sig), runar.ByteString(kp.PK))
	if c.Count != 42 {
		t.Fatalf("Count = %d after a valid Advance, want 42", c.Count)
	}
}

// The teeth. WOTS+ is a ONE-TIME signature: the row above would pass just as
// well on a gate that returned true unconditionally, and then anyone could
// advance the state without holding the key.
func TestStatefulWOTSGate_RefusesAForgedSignature(t *testing.T) {
	seed := make([]byte, 32)
	pubSeed := make([]byte, 32)
	kp := runar.WotsKeygen(seed, pubSeed)
	msg := []byte("advance the gate")
	sig := runar.WotsSign(msg, kp.SK, kp.PubSeed)

	for _, c := range []struct {
		name          string
		msg, sig, key []byte
	}{
		{"signature over a different message", []byte("a different message"), sig, kp.PK},
		{"tampered signature", msg, append(append([]byte{}, sig[:len(sig)-1]...), sig[len(sig)-1]^0xff), kp.PK},
		{"all-zero signature", msg, make([]byte, len(sig)), kp.PK},
		{"wrong public key", msg, sig, make([]byte, len(kp.PK))},
	} {
		t.Run(c.name, func(t *testing.T) {
			gate := &StatefulWOTSGate{Count: 41}
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: Advance was ACCEPTED", c.name)
				}
				if gate.Count != 41 {
					t.Fatalf("%s: Count advanced to %d on a refused spend", c.name, gate.Count)
				}
			}()
			gate.Advance(runar.ByteString(c.msg), runar.ByteString(c.sig), runar.ByteString(c.key))
		})
	}
}
