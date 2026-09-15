package runar

import "testing"

// round-trip only — absolute pin: packages/runar-go/sdk_state_push_framing_test.go (C9, state half).
// The S1 (constructor-arg) half has no Go-local literal-byte KAT; its only
// absolute evidence is indirect, via the deploy-time splice path
// (conformance/sdk-vertical) -- see the "unlocking-encodeArg-minimaldata"
// residual note in conformance/wire-primitives.json.
//
// ---------------------------------------------------------------------------
// C9 + S1 — single-byte MINIMALDATA ByteString roundtrip (state + ctor-arg).
//
// `EncodePushData` applies the BSV consensus rule SCRIPT_VERIFY_MINIMALDATA
// for single-byte pushes, short-circuiting to OP_1..OP_16 / OP_1NEGATE for
// payloads 0x01..0x10 / 0x81. It ALSO used to short-circuit a 1-byte 0x00
// payload to OP_0 ("00") — but OP_0 pushes the EMPTY byte array, not a
// 1-byte 0x00, so that short-circuit changed the value. The minimal
// encoding of a 1-byte 0x00 payload is the direct push "0100" (matching the
// compiler's encodePushBytesHex in push-encoding.ts).
//
// Independently, `DecodePushData` (state path, sdk_state.go) and
// `interpretScriptElement`'s default branch (ctor-restore path,
// sdk_script_utils.go) never understood OP_1..OP_16 / OP_1NEGATE as a
// 1-byte push at all — they fell through to "unknown opcode" / raw
// (empty) dataHex, so state/ctor ByteString values encoded via the
// MINIMALDATA short-circuit came back corrupted (empty) on restore.
// ---------------------------------------------------------------------------

func TestC9_StateByteString_MinimalDataRoundtrip(t *testing.T) {
	fields := []StateField{{Name: "b", Type: "bytes", Index: 0}}
	cases := []struct {
		label string
		hex   string
	}{
		{"0x00 (OP_0)", "00"},
		{"0x01 (OP_1)", "01"},
		{"0x05 (OP_5, mid OP_1..OP_16 range)", "05"},
		{"0x10 (OP_16)", "10"},
		{"0x81 (OP_1NEGATE)", "81"},
		{"multi-byte value", "aabbccdd"},
		{"empty", ""},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			encoded := SerializeState(fields, map[string]interface{}{"b": tc.hex})
			decoded := mustDeserializeState(t, fields, encoded)
			if got := decoded["b"]; got != tc.hex {
				t.Errorf("roundtrip %s: got %q, want %q (encoded=%q)", tc.label, got, tc.hex, encoded)
			}
		})
	}
}

func TestS1_CtorByteString_MinimalDataRoundtrip(t *testing.T) {
	cases := []struct {
		label string
		hex   string
	}{
		{"0x00 (OP_0)", "00"},
		{"0x01 (OP_1)", "01"},
		{"0x05 (OP_5, mid OP_1..OP_16 range)", "05"},
		{"0x10 (OP_16)", "10"},
		{"0x81 (OP_1NEGATE)", "81"},
		{"multi-byte value", "aabbccdd"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// Template: OP_DUP <ctor slot placeholder> OP_DROP ("ab" 00 "7c").
			artifact := &RunarArtifact{
				ContractName: "CtorByteString",
				Script:       "ab" + "00" + "7c",
				ABI: ABI{
					Constructor: ABIConstructor{
						Params: []ABIParam{{Name: "b", Type: "ByteString"}},
					},
					Methods: []ABIMethod{{Name: "noop", IsPublic: true}},
				},
				ConstructorSlots: []ConstructorSlot{{ParamIndex: 0, ByteOffset: 1}},
			}

			contract := NewRunarContract(artifact, []interface{}{tc.hex})
			lockingScript := contract.GetLockingScript()

			restored := ExtractConstructorArgs(artifact, lockingScript)
			if got := restored["b"]; got != tc.hex {
				t.Errorf("roundtrip %s: got %q, want %q (lockingScript=%q)", tc.label, got, tc.hex, lockingScript)
			}
		})
	}
}
