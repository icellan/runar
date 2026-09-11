package runar

import "testing"

// ---------------------------------------------------------------------------
// N-070 (extract half) — interpretScriptElement must know every ABI type
// spelling the compiler can emit.
//
// Two holes, identical in shape to the other six SDK tiers:
//
//	RabinSig / RabinPubKey — bigint ALIASES (runar-lang/src/types.ts:68-71)
//	  that verifyRabinSig consumes with OP_MOD, i.e. as a Script NUMBER. Absent
//	  from the switch, so a restored contract's modulus came back as the
//	  little-endian hex blob "1581e97df4102211" instead of the number. Feed that
//	  back into a call and the rebuilt locking script no longer matches chain.
//
//	boolean — the CANONICAL Rúnar primitive name; only the alias "bool" was
//	  handled. A boolean slot fell through to the byte branch, so true came back
//	  as the string "01" and false as "". Java (ContractScript.java) was the only
//	  tier of seven that tested both spellings.
//
// NOTE ON WIDTH: decodeScriptNumber returns int64, so this test uses a modulus
// that fits. A real 128-byte Rabin modulus does not — that is a pre-existing,
// type-INDEPENDENT limit of this tier's script-number decoder (it bites plain
// `bigint` ctor args of the same size identically) and is out of scope here.
// ---------------------------------------------------------------------------

// Template: <rabin@0> 7c <flag@2> 7c <blob@4> ac
func n070Artifact(rabinType, boolType string) *RunarArtifact {
	return &RunarArtifact{
		Script: "00" + "7c" + "00" + "7c" + "00" + "ac",
		ConstructorSlots: []ConstructorSlot{
			{ParamIndex: 0, ByteOffset: 0},
			{ParamIndex: 1, ByteOffset: 2},
			{ParamIndex: 2, ByteOffset: 4},
		},
		ABI: ABI{Constructor: ABIConstructor{Params: []ABIParam{
			{Name: "modulus", Type: rabinType},
			{Name: "flag", Type: boolType},
			{Name: "blob", Type: "ByteString"},
		}}},
	}
}

const (
	n070Modulus   = int64(1234567890123456789)
	n070RabinPush = "081581e97df4102211" // minimal LE sign-magnitude, 8 bytes
	n070Blob      = "04deadbeef"
)

func n070Script(flagOpcode string) string {
	return n070RabinPush + "7c" + flagOpcode + "7c" + n070Blob + "ac"
}

func TestN070_RabinSlotsExtractAsNumbers(t *testing.T) {
	for _, typeName := range []string{"RabinPubKey", "RabinSig"} {
		args := ExtractConstructorArgs(n070Artifact(typeName, "boolean"), n070Script("51"))
		got, ok := args["modulus"].(int64)
		if !ok {
			t.Fatalf("%s: modulus extracted as %T (%v), want int64", typeName, args["modulus"], args["modulus"])
		}
		if got != n070Modulus {
			t.Errorf("%s: modulus = %d, want %d", typeName, got, n070Modulus)
		}
	}
}

func TestN070_CanonicalBooleanSlotExtractsAsBool(t *testing.T) {
	cases := []struct {
		opcode string
		want   bool
	}{{"51", true}, {"00", false}}
	for _, c := range cases {
		args := ExtractConstructorArgs(n070Artifact("RabinPubKey", "boolean"), n070Script(c.opcode))
		got, ok := args["flag"].(bool)
		if !ok {
			t.Fatalf("opcode %s: flag extracted as %T (%v), want bool", c.opcode, args["flag"], args["flag"])
		}
		if got != c.want {
			t.Errorf("opcode %s: flag = %v, want %v", c.opcode, got, c.want)
		}
	}
}

func TestN070_BooleanAndBoolSpellingsAgree(t *testing.T) {
	for _, opcode := range []string{"51", "00"} {
		canonical := ExtractConstructorArgs(n070Artifact("RabinPubKey", "boolean"), n070Script(opcode))
		alias := ExtractConstructorArgs(n070Artifact("RabinPubKey", "bool"), n070Script(opcode))
		if canonical["flag"] != alias["flag"] {
			t.Errorf("opcode %s: boolean -> %v (%T) but bool -> %v (%T)",
				opcode, canonical["flag"], canonical["flag"], alias["flag"], alias["flag"])
		}
	}
}

// CONTROL: the classes that already worked must not move.
func TestN070_ControlOtherTypesUnchanged(t *testing.T) {
	for _, typeName := range []string{"bigint", "int"} {
		args := ExtractConstructorArgs(n070Artifact(typeName, "bool"), n070Script("51"))
		if args["modulus"] != n070Modulus {
			t.Errorf("%s: modulus = %v, want %d", typeName, args["modulus"], n070Modulus)
		}
	}
	// A ByteString slot still comes back as its hex payload, NOT a number, and
	// the offset walk past the wide Rabin push still lands on it.
	args := ExtractConstructorArgs(n070Artifact("RabinPubKey", "boolean"), n070Script("51"))
	if args["blob"] != "deadbeef" {
		t.Errorf("blob = %v, want deadbeef", args["blob"])
	}
	// S1: a 1-byte ByteString MINIMALDATA-encoded as OP_5 is still
	// reconstructed from the opcode.
	s1 := ExtractConstructorArgs(n070Artifact("RabinPubKey", "boolean"),
		n070RabinPush+"7c"+"51"+"7c"+"55"+"ac")
	if s1["blob"] != "05" {
		t.Errorf("S1 blob = %v, want 05", s1["blob"])
	}
}
