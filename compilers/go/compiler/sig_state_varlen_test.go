package compiler

// `Sig` and `SigHashPreimage` state fields are push-data-framed variable-length
// state, exactly like `ByteString`, on BOTH the write and the read side.
//
// `compilers/go/codegen/stack.go` kept three lists of "which state types are
// stored with a push-data length prefix":
//
//   - isVariableLengthStateType + the lowerDeserializeState size table + the
//     var-length parse loop — all say ByteString | Sig | SigHashPreimage;
//   - the two state SERIALIZERS (lowerAddOutput at :3510 and the
//     compute-state-bytes path at :2904) — said `prop.Type == "ByteString"`;
//   - the var_len_props set inside computeUsesCodePart (:5067) — same.
//
// Two faces, both fund loss:
//
//   - WRITE: a mutating method wrote the continuation state RAW, with no
//     length prefix, while the reader in the NEXT spend push-data-decodes it
//     and takes the DER `0x30` as a length-48 push. Deploy succeeds, the first
//     spend succeeds, and the UTXO that spend creates is unspendable.
//   - READ: for a TERMINAL method reading a mutable Sig field usesCodePart
//     stayed false, lowerDeserializeState took its "no _codePart" shortcut and
//     pushed no mutable property at all, so every load_prop fell through to
//     the DEPLOY-TIME constructor placeholder — the script kept authorising
//     against the value baked in at deploy, for ever.
//
// The deploy-time writer settles which list is right: every SDK's
// encodeStateValue enumerates the fixed-size types (PubKey, Addr, Ripemd160,
// Sha256, Point, P256Point, P384Point) and push-data-frames everything else.
//
// The lock below: a Sig / SigHashPreimage field must compile BYTE-IDENTICALLY
// to the same contract with a ByteString field — the path that was already
// correct. RabinSig is the negative control; it is a bigint alias stored as a
// bare 8-byte NUM2BIN word and must NOT join the variable-length set, so its
// script must stay DIFFERENT.

import (
	"fmt"
	"testing"
)

// Mutating method — drives the state-continuation WRITE path.
func varLenWriteSource(propType string) string {
	return fmt.Sprintf(`import { StatefulSmartContract } from 'runar-lang';

class VarLenStateWrite extends StatefulSmartContract {
  tag: %s;

  constructor(tag: %s) {
    super(tag);
    this.tag = tag;
  }

  public update(next: %s) {
    this.tag = next;
  }
}
`, propType, propType, propType)
}

// Terminal method reading the field — drives computeUsesCodePart.
func varLenReadSource(propType string) string {
	return fmt.Sprintf(`import { StatefulSmartContract, assert, len } from 'runar-lang';

class VarLenStateRead extends StatefulSmartContract {
  tag: %s;

  constructor(tag: %s) {
    super(tag);
    this.tag = tag;
  }

  public check(expected: bigint): void {
    assert(len(this.tag) == expected);
  }
}
`, propType, propType)
}

func compileVarLenOrFatal(t *testing.T, source, fileName string) *CompileResult {
	t.Helper()
	result := CompileFromSourceStrWithResult(source, fileName, CompileOptions{DisableConstantFolding: true})
	if !result.Success {
		t.Fatalf("compilation of %s failed: %v", fileName, result.Diagnostics)
	}
	return result
}

func TestVarLenStateWrite_SigFramesLikeByteString(t *testing.T) {
	control := compileVarLenOrFatal(t, varLenWriteSource("ByteString"), "VarLenStateWrite.runar.ts")

	for _, propType := range []string{"Sig", "SigHashPreimage"} {
		t.Run(propType, func(t *testing.T) {
			got := compileVarLenOrFatal(t, varLenWriteSource(propType), "VarLenStateWrite.runar.ts")
			if got.Artifact.Script != control.Artifact.Script {
				t.Fatalf("a mutable %s field does not frame its continuation like ByteString: %s",
					propType, describeDivergence(got.Artifact.Script, control.Artifact.Script))
			}
		})
	}
}

func TestVarLenStateRead_SigTakesCodePartLikeByteString(t *testing.T) {
	control := compileVarLenOrFatal(t, varLenReadSource("ByteString"), "VarLenStateRead.runar.ts")

	for _, propType := range []string{"Sig", "SigHashPreimage"} {
		t.Run(propType, func(t *testing.T) {
			got := compileVarLenOrFatal(t, varLenReadSource(propType), "VarLenStateRead.runar.ts")
			if got.Artifact.Script != control.Artifact.Script {
				t.Fatalf("a terminal read of a mutable %s field diverges from the ByteString control: %s",
					propType, describeDivergence(got.Artifact.Script, control.Artifact.Script))
			}
			// The observable ABI consequence, not just the byte count: the
			// unlocking script must carry the implicit _codePart parameter.
			assertUsesCodePart(t, got, "check", true)
		})
	}

	assertUsesCodePart(t, control, "check", true)
}

// RabinSig is a bigint alias, NOT variable-length state. If this ever collapses
// onto the ByteString shape the two tests above stop discriminating.
func TestVarLenState_RabinSigIsNotVariableLength(t *testing.T) {
	control := compileVarLenOrFatal(t, varLenWriteSource("ByteString"), "VarLenStateWrite.runar.ts")
	rabin := compileVarLenOrFatal(t, varLenWriteSource("RabinSig"), "VarLenStateWrite.runar.ts")
	if rabin.Artifact.Script == control.Artifact.Script {
		t.Fatalf("RabinSig state compiled identically to ByteString — it must stay a bare 8-byte NUM2BIN word")
	}

	pubKey := compileVarLenOrFatal(t, varLenWriteSource("PubKey"), "VarLenStateWrite.runar.ts")
	if pubKey.Artifact.Script == control.Artifact.Script {
		t.Fatalf("PubKey state compiled identically to ByteString — it must stay 33 raw bytes")
	}
}

// describeDivergence summarises two scripts without dumping kilobytes of hex.
func describeDivergence(got, want string) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	at := n
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			at = i
			break
		}
	}
	lo, hi := at, at+24
	if hi > len(got) {
		hi = len(got)
	}
	wh := at + 24
	if wh > len(want) {
		wh = len(want)
	}
	return fmt.Sprintf("len(got)=%d len(want)=%d, first divergence at hex offset %d\n  got  ...%s\n  want ...%s",
		len(got), len(want), at, got[lo:hi], want[at:wh])
}

func assertUsesCodePart(t *testing.T, result *CompileResult, method string, want bool) {
	t.Helper()
	for _, m := range result.Artifact.ABI.Methods {
		if m.Name != method {
			continue
		}
		got := m.UsesCodePart != nil && *m.UsesCodePart
		if got != want {
			t.Fatalf("method %q: usesCodePart = %v, want %v", method, got, want)
		}
		return
	}
	t.Fatalf("method %q not found in the ABI", method)
}
