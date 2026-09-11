package compiler

// `RabinSig` / `RabinPubKey` are `bigint` ALIASES. A mutable one is stored in
// the state section as a bare 8-byte OP_NUM2BIN word, on BOTH sides.
//
// Go's READER already says so in three places — `isNumericStateType`
// (codegen/stack.go), the `lowerDeserializeState` size table (8), and
// `fixedStateSectionLength` (8). Its two state SERIALIZERS did not: they tested
// `prop.Type == "bigint"` literally, so a mutable Rabin field was pushed onto
// the accumulator in its MINIMAL script-number encoding with no NUM2BIN at all.
//
// That is a writer/reader split of the same class as `Sig` (6dc1979b), and the
// same fund loss: for any value whose minimal encoding is not exactly 8 bytes
// the continuation this contract builds cannot be re-read by its own script.
// Deploy succeeds, the first spend succeeds, and the UTXO it creates is dead.
//
// Cause: 31276a06 widened writer AND reader in the TypeScript reference;
// e06f8c2c widened only the reader here, and Rust / Python / Ruby / Java
// followed Go.
//
// The lock: a mutable Rabin field must compile BYTE-IDENTICALLY to the same
// contract with a `bigint` field — the path whose writer and reader are known
// to agree. `ByteString` / `Sig` (framed) and `PubKey` (33 raw) stay the
// negative controls, so the equality cannot be satisfied by collapsing
// everything onto one shape.

import (
	"fmt"
	"testing"
)

// Mutating method with an EXPLICIT addOutput — drives lowerAddOutput, the
// second serializer. `varLenWriteSource` (sig_state_varlen_test.go) covers the
// implicit-continuation serializer.
func rabinAddOutputSource(propType string) string {
	return fmt.Sprintf(`import { StatefulSmartContract } from 'runar-lang';

class RabinStateAddOutput extends StatefulSmartContract {
  tag: %s;

  constructor(tag: %s) {
    super(tag);
    this.tag = tag;
  }

  public update(next: %s) {
    this.tag = next;
    this.addOutput(1000n, next);
  }
}
`, propType, propType, propType)
}

var rabinStateShapes = []struct {
	label string
	build func(string) string
	file  string
}{
	{"implicit continuation", varLenWriteSource, "VarLenStateWrite.runar.ts"},
	{"explicit addOutput", rabinAddOutputSource, "RabinStateAddOutput.runar.ts"},
}

// The decisive equality: the writer must emit the reader's fixed 8-byte word.
func TestRabinState_WritesTheSameFixedWordAsBigint(t *testing.T) {
	for _, shape := range rabinStateShapes {
		control := compileVarLenOrFatal(t, shape.build("bigint"), shape.file)
		for _, propType := range []string{"RabinSig", "RabinPubKey"} {
			t.Run(shape.label+"/"+propType, func(t *testing.T) {
				got := compileVarLenOrFatal(t, shape.build(propType), shape.file)
				if got.Artifact.Script != control.Artifact.Script {
					t.Fatalf("a mutable %s field does not serialize like bigint — the writer disagrees with its own 8-byte reader: %s",
						propType, describeDivergence(got.Artifact.Script, control.Artifact.Script))
				}
			})
		}
	}
}

// Controls: the equality above must not be reachable by collapsing the framed
// or other-width types onto the same shape.
func TestRabinState_ControlsStayDistinct(t *testing.T) {
	for _, shape := range rabinStateShapes {
		control := compileVarLenOrFatal(t, shape.build("bigint"), shape.file)
		for _, propType := range []string{"ByteString", "Sig", "PubKey"} {
			t.Run(shape.label+"/"+propType, func(t *testing.T) {
				got := compileVarLenOrFatal(t, shape.build(propType), shape.file)
				if got.Artifact.Script == control.Artifact.Script {
					t.Fatalf("a mutable %s field compiled identically to bigint — the Rabin equality no longer discriminates", propType)
				}
			})
		}
	}
}
