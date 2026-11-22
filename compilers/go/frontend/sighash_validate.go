package frontend

import "fmt"

// Field-usage validation for per-method `@sighash` modes (issue #123).
//
// SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage
// fields; a covenant that still reads one of those fields (or binds an output
// the flag no longer commits to) is exploitable — the attacker gets a free hand
// over exactly the part of the transaction the covenant believed it had pinned.
// This pass rejects, at compile time, every field read / output binding that
// becomes unsound under the method's declared mode.
//
// Faithful port of packages/runar-compiler/src/passes/sighash-validate.ts,
// including the security-audit fixes from commit e88f202c (F1 mutate-only
// SINGLE reject + explicit-single warning, F3 transitive walk over for-headers
// and assignment targets, F4 requireOutputP2PKH-under-SINGLE reject).
//
// BIP-143 field availability by sighash type (✓ = committed, ✗ = ZEROED):
//
//	field                 ALL    NONE   SINGLE   +ANYONECANPAY
//	---------------------------------------------------------
//	hashPrevouts           ✓      ✓      ✓         ✗
//	hashSequence           ✓      ✗      ✗         ✗
//	hashOutputs            ✓      ✗      same-idx   (per base)
//
// The this-input / always-present extractors (extractVersion, extractOutpoint,
// extractAmount, extractSequence, extractScriptCode, extractLocktime,
// extractSigHashType, extractInputIndex) are sound under every mode and are
// never rejected.

var (
	hashPrevoutsReaders   = map[string]bool{"extractHashPrevouts": true}
	hashSequenceReaders   = map[string]bool{"extractHashSequence": true}
	hashOutputsReaders    = map[string]bool{"extractOutputHash": true, "extractOutputs": true}
	prevoutScriptIntrins  = map[string]bool{"extractPrevOutputScript": true}
	outputAssertIntrins   = map[string]bool{"requireOutputP2PKH": true}
	stateOutputIntrinsics = map[string]bool{"addOutput": true, "addRawOutput": true}
	dataOutputIntrinsics  = map[string]bool{"addDataOutput": true}
)

// methodScan holds the flagged builtin/intrinsic usages collected from a
// method body (transitively through private helpers).
type methodScan struct {
	hashPrevoutsReads []string
	hashSequenceReads []string
	hashOutputsReads  []string
	prevoutScriptRead []string
	outputAsserts     []string
	stateOutputCount  int
	dataOutputCount   int
}

// ValidateSighashUsage validates every public method's `@sighash` field usage.
// Returns diagnostics (errors + warnings). Methods with no directive (default
// ALL|FORKID) are never flagged.
func ValidateSighashUsage(contract *ContractNode) []Diagnostic {
	var diags []Diagnostic
	isStateful := contract.ParentClass == "StatefulSmartContract"
	sideEffects := ComputeSideEffectSummary(contract)

	privateByName := make(map[string]MethodNode)
	for _, m := range contract.Methods {
		if m.Visibility == "private" {
			privateByName[m.Name] = m
		}
	}

	for _, method := range contract.Methods {
		if method.Visibility != "public" || method.SighashType == nil {
			continue // default ALL|FORKID — allow all
		}
		mode := *method.SighashType
		base := mode & sighashBaseTypeMask
		acp := mode&sighashFlagAnyone != 0
		label := describeSighash(mode)
		loc := method.SourceLocation

		scan := scanSighashMethod(method, privateByName)

		needsContinuation := isStateful && ContinuationShapeFor(sideEffects[method.Name]).NeedsChange

		pushErr := func(msg string) {
			l := loc
			diags = append(diags, Diagnostic{Message: msg, Severity: SeverityError, Loc: &l})
		}
		pushWarn := func(msg string) {
			l := loc
			diags = append(diags, Diagnostic{Message: msg, Severity: SeverityWarning, Loc: &l})
		}

		// ---- ANYONECANPAY: only THIS input is signed --------------------
		if acp {
			for _, name := range scan.hashPrevoutsReads {
				pushErr(fmt.Sprintf("@sighash %s: '%s' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the %s read.", label, name, name))
			}
			for _, name := range scan.prevoutScriptRead {
				pushErr(fmt.Sprintf("@sighash %s: '%s' binds a companion input's prevout script, but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set to be committed (drop ANYONECANPAY).", label, name))
			}
		}

		// ---- hashSequence committed only under pure ALL (no ACP) --------
		hashSequenceSound := base == sighashBaseAll && !acp
		if !hashSequenceSound {
			for _, name := range scan.hashSequenceReads {
				pushErr(fmt.Sprintf("@sighash %s: '%s' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the %s read.", label, name, name))
			}
		}

		// ---- NONE commits to NO outputs ---------------------------------
		if base == sighashBaseNone {
			if needsContinuation {
				pushErr(fmt.Sprintf("@sighash %s: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.", label))
			}
			for _, name := range scan.hashOutputsReads {
				pushErr(fmt.Sprintf("@sighash %s: '%s' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.", label, name))
			}
			for _, name := range scan.outputAsserts {
				pushErr(fmt.Sprintf("@sighash %s: '%s' asserts an output, but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.", label, name))
			}
			if scan.stateOutputCount+scan.dataOutputCount > 0 {
				pushErr(fmt.Sprintf("@sighash %s: this method emits %d output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.", label, scan.stateOutputCount+scan.dataOutputCount))
			}
		}

		// ---- SINGLE commits ONLY to the same-index output ---------------
		if base == sighashBaseSingle {
			// F4: a fixed-index output assertion (requireOutputP2PKH) cannot be
			// proven to land at THIS input's index, the only output SINGLE
			// commits to.
			for _, name := range scan.outputAsserts {
				pushErr(fmt.Sprintf("@sighash %s: '%s' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.", label, name))
			}

			// D25: a mutate-only (auto-continuation) method under SINGLE is
			// SOUND and is the DEFAULT for a contract whose continuation
			// methods are all mutate-only (continuation_binding.go). SINGLE
			// hashes the whole same-index output, value included, and the
			// F-024 floor (`_newAmount >= extractAmount`) stops a dust
			// continuation; the change is not committed (N-038). The refusal
			// that used to stand here (e88f202c8) predates both.
			isMutateOnlyAutoContinuation := needsContinuation &&
				scan.stateOutputCount == 0 && scan.dataOutputCount == 0

			stateOutputs := 0
			if scan.stateOutputCount > 0 {
				stateOutputs = scan.stateOutputCount
			} else if needsContinuation {
				stateOutputs = 1
			}
			committed := stateOutputs + scan.dataOutputCount

			switch {
			case isMutateOnlyAutoContinuation:
				// Sound (see above): nothing to report.
			case committed > 1:
				extra := ""
				if stateOutputs > scan.stateOutputCount {
					extra = " + state continuation"
				}
				pushErr(fmt.Sprintf("@sighash %s: SINGLE commits ONLY to the output at this input's index, but this method binds %d outputs (%d addOutput + %d addDataOutput%s). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.", label, committed, scan.stateOutputCount, scan.dataOutputCount, extra))
			case committed == 1:
				pushWarn(fmt.Sprintf("@sighash %s: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.", label))
			}
		}
	}

	return diags
}

// scanSighashMethod walks a method body (transitively through private-method
// calls) collecting every flagged builtin/intrinsic usage. Cycle-guarded (the
// validator forbids recursion, but we guard defensively). Faithful port of the
// TS scanMethod including the F3 for-header + assignment-target coverage.
func scanSighashMethod(method MethodNode, privateByName map[string]MethodNode) methodScan {
	var scan methodScan
	visiting := make(map[string]bool)

	var walkBody func(stmts []Statement)
	var walkStmt func(stmt Statement)
	var walkExpr func(expr Expression)

	calleeName := func(callee Expression) string {
		switch c := callee.(type) {
		case Identifier:
			return c.Name
		case PropertyAccessExpr:
			return c.Property
		case MemberExpr:
			return c.Property
		}
		return ""
	}

	walkBody = func(stmts []Statement) {
		for _, s := range stmts {
			walkStmt(s)
		}
	}

	walkStmt = func(stmt Statement) {
		switch s := stmt.(type) {
		case AssignmentStmt:
			// F3: walk BOTH sides — a forbidden read can hide in the target
			// (e.g. arr[extractOutputHash(pre)] = x), not just the value.
			walkExpr(s.Target)
			walkExpr(s.Value)
		case ExpressionStmt:
			walkExpr(s.Expr)
		case IfStmt:
			walkExpr(s.Condition)
			walkBody(s.Then)
			if s.Else != nil {
				walkBody(s.Else)
			}
		case ForStmt:
			// F3: init and condition can hide a forbidden read just as easily
			// as the body/update.
			walkStmt(s.Init)
			walkExpr(s.Condition)
			walkStmt(s.Update)
			walkBody(s.Body)
		case ReturnStmt:
			if s.Value != nil {
				walkExpr(s.Value)
			}
		case VariableDeclStmt:
			if s.Init != nil {
				walkExpr(s.Init)
			}
		}
	}

	walkExpr = func(expr Expression) {
		switch e := expr.(type) {
		case CallExpr:
			name := calleeName(e.Callee)
			if name != "" {
				if hashPrevoutsReaders[name] {
					scan.hashPrevoutsReads = append(scan.hashPrevoutsReads, name)
				}
				if hashSequenceReaders[name] {
					scan.hashSequenceReads = append(scan.hashSequenceReads, name)
				}
				if hashOutputsReaders[name] {
					scan.hashOutputsReads = append(scan.hashOutputsReads, name)
				}
				if prevoutScriptIntrins[name] {
					scan.prevoutScriptRead = append(scan.prevoutScriptRead, name)
				}
				if outputAssertIntrins[name] {
					scan.outputAsserts = append(scan.outputAsserts, name)
				}
				if stateOutputIntrinsics[name] {
					scan.stateOutputCount++
				}
				if dataOutputIntrinsics[name] {
					scan.dataOutputCount++
				}
				// Recurse into a private helper so its usages surface here.
				if target, ok := privateByName[name]; ok && !visiting[name] {
					visiting[name] = true
					walkBody(target.Body)
					delete(visiting, name)
				}
			}
			for _, a := range e.Args {
				walkExpr(a)
			}
			if _, isID := e.Callee.(Identifier); !isID {
				walkExpr(e.Callee)
			}
		case BinaryExpr:
			walkExpr(e.Left)
			walkExpr(e.Right)
		case UnaryExpr:
			walkExpr(e.Operand)
		case TernaryExpr:
			walkExpr(e.Condition)
			walkExpr(e.Consequent)
			walkExpr(e.Alternate)
		case IndexAccessExpr:
			walkExpr(e.Object)
			walkExpr(e.Index)
		case MemberExpr:
			walkExpr(e.Object)
		case ArrayLiteralExpr:
			for _, el := range e.Elements {
				walkExpr(el)
			}
		}
	}

	walkBody(method.Body)
	return scan
}
