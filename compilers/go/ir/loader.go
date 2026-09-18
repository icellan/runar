package ir

import (
	"fmt"
	"os"
	"strings"

	"encoding/json"
)

// LoadIR reads an ANF IR JSON file from disk, deserialises it, validates it,
// and decodes constant values into their typed Go representations.
//
// Rejects oversized (>MaxIRBytes) or deeply-nested (>MaxIRNesting) payloads
// with typed IRSizeExceededError / IRNestingExceededError before json.Unmarshal
// runs.
func LoadIR(path string) (*ANFProgram, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading IR file: %w", err)
	}

	return LoadIRFromBytes(data)
}

// LoadIRFromBytes is like LoadIR but accepts raw JSON bytes directly.
//
// Rejects oversized (>MaxIRBytes) or deeply-nested (>MaxIRNesting) payloads
// with typed IRSizeExceededError / IRNestingExceededError before json.Unmarshal
// runs.
func LoadIRFromBytes(data []byte) (*ANFProgram, error) {
	// DoS-bound guards run before json.Unmarshal so a malicious payload
	// cannot exhaust memory (size) or the goroutine stack (nesting)
	// inside the stdlib decoder.
	if err := assertIRBytesUnderLimit(data); err != nil {
		return nil, err
	}
	if err := assertIRNestingUnderLimit(data); err != nil {
		return nil, err
	}

	var program ANFProgram
	if err := json.Unmarshal(data, &program); err != nil {
		return nil, fmt.Errorf("invalid IR JSON: %w", err)
	}

	if err := DecodeConstants(&program); err != nil {
		return nil, fmt.Errorf("decoding constants: %w", err)
	}

	if err := ValidateIR(&program); err != nil {
		return nil, err
	}

	return &program, nil
}

// MaxLoopCount is the maximum number of loop iterations allowed in a single
// loop binding. This prevents resource exhaustion from malicious or accidental
// extremely large loop counts during loop unrolling.
const MaxLoopCount = 10000

// ValidateIR performs basic structural validation of a parsed ANF program.
func ValidateIR(program *ANFProgram) error {
	if program.ContractName == "" {
		return fmt.Errorf("IR validation: contractName is required")
	}

	// R-126 / CL-BUG-164: an add_output must name exactly one state value per
	// MUTABLE property. Counted once, up front, so the per-binding check below
	// is a comparison rather than a rescan.
	mutableCount := 0
	for _, prop := range program.Properties {
		if !prop.Readonly {
			mutableCount++
		}
	}

	for i, method := range program.Methods {
		if method.Name == "" {
			return fmt.Errorf("IR validation: method[%d] has empty name", i)
		}
		for j, param := range method.Params {
			if param.Name == "" {
				return fmt.Errorf("IR validation: method %s param[%d] has empty name", method.Name, j)
			}
			if param.Type == "" {
				return fmt.Errorf("IR validation: method %s param %s has empty type", method.Name, param.Name)
			}
		}
		if err := validateBindings(method.Body, method.Name, mutableCount); err != nil {
			return err
		}
	}

	for i, prop := range program.Properties {
		if prop.Name == "" {
			return fmt.Errorf("IR validation: property[%d] has empty name", i)
		}
		if prop.Type == "" {
			return fmt.Errorf("IR validation: property %s has empty type", prop.Name)
		}
	}

	// R-081: a contract with no public method has no spending entry point and
	// emits an EMPTY locking script — which is anyone-can-spend, not merely
	// useless. On the real @bsv/sdk `Spend` engine under full consensus rules,
	// an empty locking script with the one-byte push-only witness OP_1 (0x51)
	// validates. Before this guard the --ir path exited 0 and handed the SDKs
	// a well-formed artifact whose "script" was "".
	//
	// The source pipeline already rejects the same shape in
	// frontend/validator.go; ValidateIR is reached only from LoadIRFromBytes,
	// so this closes the rule's gap on externally supplied IR.
	//
	// Checked LAST so the structural diagnostics above keep priority — a
	// malformed binding is the more actionable error when both are present.
	//
	// N-113: the CONSTRUCTOR does not count. This loop was written to mirror
	// frontend/validator.go's, but it runs over a differently-shaped list:
	// the AST that validator scans keeps the constructor in its own field
	// (ContractNode.Constructor), while ANF lowering flattens it INTO
	// program.Methods. So a single `isPublic: true` on the constructor walked
	// straight past this guard. It is never a spending entry point — both
	// codegen/emit.go and codegen/stack.go filter it out by NAME — and the
	// contract then emitted a locking script of "" at exit 0, with a
	// well-formed artifact an SDK would deploy.
	hasPublic := false
	for _, method := range program.Methods {
		if method.IsPublic && method.Name != "constructor" {
			hasPublic = true
			break
		}
	}
	if !hasPublic {
		return fmt.Errorf("IR validation: contract %s has no public methods — no spending entry points; an empty locking script is anyone-can-spend", program.ContractName)
	}

	return nil
}

// knownKinds enumerates all valid ANF value kinds.
var knownKinds = map[string]bool{
	"load_param":        true,
	"load_prop":         true,
	"load_const":        true,
	"bin_op":            true,
	"unary_op":          true,
	"call":              true,
	"method_call":       true,
	"if":                true,
	"loop":              true,
	"assert":            true,
	"update_prop":       true,
	"get_state_script":  true,
	"check_preimage":    true,
	"deserialize_state": true,
	"add_output":        true,
	"add_raw_output":    true,
	"add_data_output":   true,
	"array_literal":     true,
	"raw_script":        true,
}

func validateBindings(bindings []ANFBinding, methodName string, mutableCount int) error {
	for i, binding := range bindings {
		if binding.Name == "" {
			return fmt.Errorf("IR validation: method %s binding[%d] has empty name", methodName, i)
		}
		kind := binding.Value.Kind
		if kind == "" {
			return fmt.Errorf("IR validation: method %s binding %s has empty kind", methodName, binding.Name)
		}
		if !knownKinds[kind] {
			return fmt.Errorf("IR validation: method %s binding %s has unknown kind %q", methodName, binding.Name, kind)
		}

		// R-163 / R-165: builtin call arity. The source pipeline type-checks
		// every call; `--ir` runs no frontend, so a wrong-arity call used to
		// reach stack lowering, where each dispatch family pops len(args) from
		// the stack MODEL and then emits a FIXED-arity opcode blob. `cat` with
		// one argument compiled to a bare OP_CAT; `assert` with none compiled
		// to an EMPTY script, dropping the contract's only guard. See
		// builtin_arity.go.
		if kind == "call" {
			if ok, rule, isVariadic := VariadicArityOK(binding.Value.Func, len(binding.Value.Args)); isVariadic {
				if !ok {
					return fmt.Errorf(
						"IR validation: method %s binding %s calls %s() with %d argument(s); it takes %s",
						methodName, binding.Name, binding.Value.Func, len(binding.Value.Args), rule)
				}
			} else if allowed, known := AllowedArity(binding.Value.Func); known {
				got := len(binding.Value.Args)
				ok := false
				for _, want := range allowed {
					if got == want {
						ok = true
						break
					}
				}
				if !ok {
					return fmt.Errorf(
						"IR validation: method %s binding %s calls %s() with %d argument(s); it takes %s",
						methodName, binding.Name, binding.Value.Func, got, formatAllowedArity(allowed))
				}
			}
		}

		// R-164 / CL-BUG-134: `super` outside a constructor.
		//
		// `super` emits no opcodes — the constructor args are already on the
		// stack — but stack lowering pushes a stackMap slot for it anyway:
		// +1 model, +0 physical. On the SOURCE path that is invisible because
		// the constructor is never lowered to script; via `--ir` it is
		// reachable, and every subsequent PICK/ROLL depth is off by one.
		// Measured against the same IR with the binding deleted: PUSH 3;
		// OP_ROLL where the correct lowering emits OP_ROT, addressing a fourth
		// stack item that does not exist.
		//
		// Refusing beats inventing a physical push for a call with no runtime
		// meaning: a scan of all 114 checked-in IR files found 110 `super`
		// calls, every one inside a constructor.
		if kind == "call" && binding.Value.Func == "super" && methodName != "constructor" {
			return fmt.Errorf(
				"IR validation: super() is only valid in a constructor; method '%s' calls it. It emits no opcodes — the constructor args are already on the stack — so stack lowering pushes a model slot with no physical value, and every later PICK/ROLL depth in the method is off by one.",
				methodName)
		}

		// R-126 / CL-BUG-164: add_output state-value arity.
		//
		// The source pipeline counts addOutput arity in the typechecker (the
		// N20 / N23 / N26 negatives). `--ir` runs no frontend, so such a node
		// reached stack lowering directly, and lowerAddOutput serializes the
		// OP_RETURN payload with the MIN of the two lists:
		//
		//     for i := 0; i < len(stateValues) && i < len(stateProps); i++
		//
		// Under-arity therefore emitted an output carrying fewer state fields
		// than the contract has; over-arity silently dropped the surplus.
		// Measured through each tier's own --ir CLI on a two-mutable-field
		// contract (correct arity = 1394 hexchars): go, rust, zig, ruby, python
		// and java ALL accepted, emitting 1388 and 1396 hexchars respectively.
		//
		// CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
		// mutable fields, so a short-payload continuation is spendable only by a
		// hand-crafted transaction, and the successor it produces is permanently
		// unspendable because the next call's deserialize_state slices at fixed
		// offsets. The message is shared verbatim with the other six tiers.
		if kind == "add_output" && len(binding.Value.StateValues) != mutableCount {
			return fmt.Errorf(
				"IR validation: add_output in method '%s' carries %d state values, but the contract declares %d mutable properties. The output's OP_RETURN payload is serialized from this list while deserialize_state slices the declared properties at fixed offsets, so any other count commits to a state payload no SDK-built transaction can produce and a successor that cannot be spent.",
				methodName, len(binding.Value.StateValues), mutableCount)
		}

		// Validate nested bindings
		if kind == "if" {
			if err := validateBindings(binding.Value.Then, methodName, mutableCount); err != nil {
				return err
			}
			if err := validateBindings(binding.Value.Else, methodName, mutableCount); err != nil {
				return err
			}
		}
		if kind == "loop" {
			if binding.Value.Count < 0 {
				return fmt.Errorf("IR validation: method %s binding %s has negative loop count %d", methodName, binding.Name, binding.Value.Count)
			}
			if binding.Value.Count > MaxLoopCount {
				return fmt.Errorf("IR validation: method %s binding %s has loop count %d exceeding maximum %d", methodName, binding.Name, binding.Value.Count, MaxLoopCount)
			}
			if err := validateBindings(binding.Value.Body, methodName, mutableCount); err != nil {
				return err
			}
		}
		if kind == "raw_script" {
			body := binding.Value.Bytes
			// R-079: an empty span is a claim the emitter cannot honour.
			// Stack lowering models a raw_script purely from its declared
			// arities (codegen.lowerRawScript pops in_arity, pushes
			// out_arity) because the bytes are opaque to it, while emission
			// writes nothing at all for a zero-length span
			// (codegen.emitRawBytes returns early). The stack model and the
			// script then disagree, and every later PICK/ROLL depth derived
			// from that model addresses the wrong slot — the span silently
			// degrades to the identity function and a different witness
			// spends the output than the IR declared.
			//
			// The source path already rejects this ("asm() body must be a
			// non-empty hex string literal", frontend/validator.go); --ir is
			// the same rule at the external-input trust boundary.
			if len(body) == 0 {
				return fmt.Errorf("IR validation: method %s binding %s raw_script has an empty bytes body but declares in_arity %d / out_arity %d; a span that emits no bytes cannot have a stack effect", methodName, binding.Name, binding.Value.InArity, binding.Value.OutArity)
			}
			if len(body)%2 != 0 {
				return fmt.Errorf("IR validation: method %s binding %s raw_script bytes have odd hex length %d", methodName, binding.Name, len(body))
			}
			if !isHexString(body) {
				return fmt.Errorf("IR validation: method %s binding %s raw_script bytes contain non-hex characters", methodName, binding.Name)
			}
			if binding.Value.InArity < 0 {
				return fmt.Errorf("IR validation: method %s binding %s raw_script has negative in_arity %d", methodName, binding.Name, binding.Value.InArity)
			}
			if binding.Value.OutArity < 0 {
				return fmt.Errorf("IR validation: method %s binding %s raw_script has negative out_arity %d", methodName, binding.Name, binding.Value.OutArity)
			}
		}
	}
	return nil
}

// isHexString reports whether s contains only hex digits (0-9, a-f, A-F).
// An empty string is considered valid hex.
func isHexString(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// formatAllowedArity renders an arity list for a diagnostic: "2", or "2 or 3".
func formatAllowedArity(allowed []int) string {
	switch len(allowed) {
	case 0:
		return "no arguments"
	case 1:
		return fmt.Sprintf("%d", allowed[0])
	default:
		parts := make([]string, len(allowed))
		for i, a := range allowed {
			parts[i] = fmt.Sprintf("%d", a)
		}
		return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
	}
}
