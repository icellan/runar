package frontend

import "testing"

// The deployable SP1 FRI verifier is not sound at the PoC parameter set: the
// per-query chain is never emitted, so forged Merkle openings are ACCEPTED
// on-chain (docs/sp1-fri-verifier.md, pinned by
// compilers/go/compiler/sp1_fri_negative_test.go).
//
// A developer who just calls the built-in reads neither of those, so the
// validator raises it as a compile-time warning. These tests pin that it
// actually fires, and — just as importantly — that it does NOT fire for
// contracts that never touch the built-in, so it cannot decay into noise
// everyone learns to ignore.

func sp1WarningPresent(t *testing.T, contract *ContractNode) bool {
	t.Helper()
	res := Validate(contract)
	for _, d := range res.Warnings {
		if d.Severity == SeverityWarning && containsSubstr(d.Message, "NOT a sound proof verifier") {
			return true
		}
	}
	return false
}

func sp1RefusalPresent(t *testing.T, contract *ContractNode) bool {
	t.Helper()
	res := Validate(contract)
	for _, d := range res.Errors {
		if d.Severity == SeverityError && containsSubstr(d.Message, "not implemented for v1") {
			return true
		}
	}
	return false
}

func containsSubstr(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func sp1CallingContract() *ContractNode {
	return &ContractNode{
		Name: "UsesSP1",
		Methods: []MethodNode{{
			Name:       "spend",
			Visibility: "public",
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{
					Callee: Identifier{Name: "assert"},
					Args: []Expression{
						CallExpr{
							Callee: Identifier{Name: "verifySP1FRI"},
							Args: []Expression{
								Identifier{Name: "proof"},
								Identifier{Name: "publicValues"},
								Identifier{Name: "vkHash"},
							},
						},
					},
				}},
			},
		}},
	}
}

func TestSP1FriSoundnessWarning_FiresWhenBuiltinIsCalled(t *testing.T) {
	contract := sp1CallingContract()
	// DEFAULT: refuse. Documenting an unsound verifier is not the same as
	// preventing its deployment, and this one accepts forged proofs.
	if !sp1RefusalPresent(t, contract) {
		t.Fatal("expected verifySP1FRI to be REFUSED; the SP1 FRI verifier is not implemented for v1 (F-007)")
	}
	if sp1WarningPresent(t, contract) {
		t.Fatal("without the directive this must be an ERROR, not a downgradeable warning")
	}
}

// Was TestSP1FriSoundness_CompilesWithExplicitAcknowledgement.
// F-007: rewritten to expect refusal — the @acknowledgeUnsoundSP1FriVerifier override was removed for v1.
func TestSP1FriSoundness_NoAcknowledgementOverride(t *testing.T) {
	// The directive is now an inert comment: a contract that carried it parses
	// to exactly the AST sp1CallingContract builds, and that is refused.
	contract := sp1CallingContract()
	if !sp1RefusalPresent(t, contract) {
		t.Fatal("verifySP1FRI must be refused unconditionally; there is no acknowledgement override in v1")
	}
	if sp1WarningPresent(t, contract) {
		t.Fatal("the refusal must not be downgradeable to a warning")
	}
}

func TestSP1FriSoundnessWarning_SilentForUnrelatedContracts(t *testing.T) {
	contract := &ContractNode{
		Name: "NoSP1",
		Methods: []MethodNode{{
			Name:       "spend",
			Visibility: "public",
			Body: []Statement{
				ExpressionStmt{Expr: CallExpr{
					Callee: Identifier{Name: "assert"},
					Args: []Expression{
						BinaryExpr{Op: ">", Left: Identifier{Name: "a"}, Right: Identifier{Name: "b"}},
					},
				}},
			},
		}},
	}
	if sp1WarningPresent(t, contract) || sp1RefusalPresent(t, contract) {
		t.Fatal("the SP1 FRI diagnostic fired for a contract that never calls the built-in; " +
			"a diagnostic that fires everywhere is one nobody reads")
	}
}
