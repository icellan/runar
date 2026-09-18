package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestPostQuantumWOTSNaiveInsecure_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumWOTSNaiveInsecure.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// The port is INSECURE by design: it verifies a free WOTS+ signature over a
// free message, so anyone who observes one valid spend can replay the (msg,
// sig) pair. The correct hybrid pattern lives in examples/go/post-quantum-wallet.
//
// Insecure is not the same as vacuous, and this suite separates the two.
func wotsFixture(t *testing.T) (*PostQuantumWOTSNaiveInsecure, []byte, []byte) {
	t.Helper()
	seed, pubSeed := make([]byte, 32), make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
		pubSeed[i] = byte(0x80 + i)
	}
	kp := runar.WotsKeygen(seed, pubSeed)
	msg := []byte("naive wots spend")
	return &PostQuantumWOTSNaiveInsecure{Pubkey: runar.ByteString(kp.PK)},
		msg, runar.WotsSign(msg, kp.SK, kp.PubSeed)
}

func TestPostQuantumWOTSNaiveInsecure_AcceptsAValidSignature(t *testing.T) {
	c, msg, sig := wotsFixture(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a valid WOTS+ signature was REFUSED (%v)", r)
		}
	}()
	c.Spend(runar.ByteString(msg), runar.ByteString(sig))
}

// The teeth. runar.VerifyWOTS is real verification, not a stub like
// VerifySP1FRI; a verifier that returned true unconditionally would accept
// every row here and the compile-only suite this replaced would still be green.
func TestPostQuantumWOTSNaiveInsecure_RefusesForgeries(t *testing.T) {
	c, msg, sig := wotsFixture(t)

	for _, k := range []struct {
		name     string
		msg, sig []byte
	}{
		{"signature over a different message", []byte("a different message"), sig},
		{"tampered signature", msg, append(append([]byte{}, sig[:len(sig)-1]...), sig[len(sig)-1]^0xff)},
		{"all-zero signature", msg, make([]byte, len(sig))},
		{"truncated signature", msg, sig[:len(sig)-32]},
	} {
		t.Run(k.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s was ACCEPTED", k.name)
				}
			}()
			c.Spend(runar.ByteString(k.msg), runar.ByteString(k.sig))
		})
	}
}
