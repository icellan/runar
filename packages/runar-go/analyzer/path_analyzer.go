package analyzer

import (
	"fmt"
	"strconv"
	"strings"
)

// branchFrame is a closed IF/NOTIF/ELSE/ENDIF group.
type branchFrame struct {
	ifIndex    int // index into the opcode slice
	elseIndex  int // -1 if no ELSE
	endifIndex int
	isNotIf    bool
}

// openFrame is an in-flight IF/NOTIF.
type openFrame struct {
	ifIndex   int
	elseIndex int
	isNotIf   bool
}

// pathAnalysisResult bundles the path-analyzer outputs.
type pathAnalysisResult struct {
	paths    []ExecutionPath
	findings []Finding
}

// analyzePaths implements §7.
func analyzePaths(ops []Opcode) pathAnalysisResult {
	var (
		closed      []branchFrame
		open        []openFrame
		structErrs  []Finding
		numBranches int
	)

	for i, op := range ops {
		if op.IsRawSpan {
			continue
		}
		switch byte(op.Opcode) {
		case opIf, opNotIf:
			open = append(open, openFrame{ifIndex: i, elseIndex: -1, isNotIf: byte(op.Opcode) == opNotIf})
			numBranches++
		case opElse:
			if len(open) == 0 {
				structErrs = append(structErrs, Finding{
					Severity: SeverityError,
					Code:     "UNBALANCED_IF_ENDIF",
					Message:  "OP_ELSE without matching OP_IF",
				})
				continue
			}
			open[len(open)-1].elseIndex = i
		case opEndIf:
			if len(open) == 0 {
				structErrs = append(structErrs, Finding{
					Severity: SeverityError,
					Code:     "UNBALANCED_IF_ENDIF",
					Message:  "OP_ENDIF without matching OP_IF",
				})
				continue
			}
			frame := open[len(open)-1]
			open = open[:len(open)-1]
			closed = append(closed, branchFrame{
				ifIndex:    frame.ifIndex,
				elseIndex:  frame.elseIndex,
				endifIndex: i,
				isNotIf:    frame.isNotIf,
			})
		}
	}

	// Unclosed frames.
	for _, frame := range open {
		opName := "OP_IF"
		if frame.isNotIf {
			opName = "OP_NOTIF"
		}
		offset := ops[frame.ifIndex].Offset
		structErrs = append(structErrs, Finding{
			Severity: SeverityError,
			Code:     "UNBALANCED_IF_ENDIF",
			Message:  fmt.Sprintf("%s at offset %d has no matching OP_ENDIF", opName, offset),
		})
	}

	if len(structErrs) > 0 {
		return pathAnalysisResult{paths: nil, findings: structErrs}
	}

	// Collect all IF/NOTIF opcode indices in source order.
	var bps []branchPoint
	for i, op := range ops {
		if op.IsRawSpan {
			continue
		}
		if byte(op.Opcode) == opIf {
			bps = append(bps, branchPoint{opIndex: i, isNotIf: false, offset: op.Offset})
		} else if byte(op.Opcode) == opNotIf {
			bps = append(bps, branchPoint{opIndex: i, isNotIf: true, offset: op.Offset})
		}
	}

	if numBranches == 0 {
		// Linear path: collect everything except IF/ELSE/ENDIF.
		collected := collectLinearOps(ops)
		linear := analyzeStackLinear(collected, 0)
		path := ExecutionPath{
			ID:              0,
			Description:     "linear (no branches)",
			BranchChoices:   []bool{},
			Reachable:       true,
			HasCheckSig:     pathHasCheckSig(collected),
			StackDepthAtEnd: linear.depth,
		}
		findings := linear.findings
		for j := range findings {
			findings[j].Path = path.Description
			findings[j].HasPath = true
		}
		if isUnconditionalSucceed(collected) {
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Code:     "UNCONDITIONALLY_SUCCEEDS",
				Message:  "Execution path has no verification opcode — any unlocking input will satisfy it",
				Path:     path.Description,
				HasPath:  true,
			})
		}
		// Branch-depth findings come after per-path findings.
		bd := branchDepthFindings(ops, closed)
		findings = append(findings, bd...)
		return pathAnalysisResult{paths: []ExecutionPath{path}, findings: findings}
	}

	// Compute the requested combination count. For numBranches >= 53,
	// 2^numBranches overflows the JS safe-integer range used by the
	// canonical TS reference, so we render the count symbolically as
	// "more than 2^53 paths" instead of an exact decimal. (Spec v1.2.)
	const largeBranchThreshold = 53
	useExactCount := numBranches < largeBranchThreshold
	// Bound combo count by min(requested, maxPaths). When useExactCount
	// is false, the requested count is effectively infinite, so cap to
	// maxPaths directly.
	cap := maxPaths
	if useExactCount {
		exact := uint64(1) << uint(numBranches)
		if exact < uint64(maxPaths) {
			cap = int(exact)
		}
	}

	var findings []Finding

	// PATHS_TRUNCATED is emitted at enumeration time (before
	// per-path findings) to match the canonical goldens — see
	// ec-demo where it sorts first among warnings without an
	// offset.
	truncated := !useExactCount
	if useExactCount {
		exact := uint64(1) << uint(numBranches)
		truncated = exact > uint64(maxPaths)
	}
	if truncated {
		var pathsClause string
		if useExactCount {
			exact := uint64(1) << uint(numBranches)
			pathsClause = fmt.Sprintf("2^%d = %d paths", numBranches, exact)
		} else {
			pathsClause = fmt.Sprintf("more than 2^%d paths", largeBranchThreshold)
		}
		findings = append(findings, Finding{
			Severity: SeverityWarning,
			Code:     "PATHS_TRUNCATED",
			Message: fmt.Sprintf(
				"Script has %d branch points (%s); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.",
				numBranches, pathsClause,
			),
		})
	}

	paths := make([]ExecutionPath, 0, cap)
	for combo := 0; combo < cap; combo++ {
		choices := make([]bool, numBranches)
		for b := 0; b < numBranches; b++ {
			// `combo` is bounded by maxPaths = 256, so bits at positions
			// >= 8 are mathematically always 0. We explicitly clamp to
			// b < 31 to match the canonical TS reference, where JS `>>`
			// would otherwise mask the shift count to 5 bits and wrap.
			if b < 31 {
				choices[b] = ((int32(combo) >> uint(b)) & 1) == 1
			} else {
				choices[b] = false
			}
		}
		desc := buildPathDescription(bps, choices)
		collected := collectPathOps(ops, closed, choices)
		linear := analyzeStackLinear(collected, 0)
		path := ExecutionPath{
			ID:              combo,
			Description:     desc,
			BranchChoices:   choices,
			Reachable:       true,
			HasCheckSig:     pathHasCheckSig(collected),
			StackDepthAtEnd: linear.depth,
		}
		paths = append(paths, path)

		for j := range linear.findings {
			linear.findings[j].Path = desc
			linear.findings[j].HasPath = true
		}
		findings = append(findings, linear.findings...)
		if isUnconditionalSucceed(collected) {
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Code:     "UNCONDITIONALLY_SUCCEEDS",
				Message:  "Execution path has no verification opcode — any unlocking input will satisfy it",
				Path:     desc,
				HasPath:  true,
			})
		}
	}

	bd := branchDepthFindings(ops, closed)
	findings = append(findings, bd...)

	return pathAnalysisResult{paths: paths, findings: findings}
}

// buildPathDescription renders the §7.3 description string.
func buildPathDescription(bps []branchPoint, choices []bool) string {
	parts := make([]string, 0, len(bps))
	for i, bp := range bps {
		label := "IF"
		if bp.isNotIf {
			label = "NOTIF"
		}
		choice := "false"
		if i < len(choices) && choices[i] {
			choice = "true"
		}
		parts = append(parts, fmt.Sprintf("%s[%s] at %s", label, choice, strconv.Itoa(bp.offset)))
	}
	return strings.Join(parts, " -> ")
}

// branchPoint is the source-order anchor for each IF/NOTIF.
type branchPoint struct {
	opIndex int
	isNotIf bool
	offset  int
}

// collectLinearOps returns every non-IF/ELSE/ENDIF opcode in source
// order (for the no-branches case).
func collectLinearOps(ops []Opcode) []Opcode {
	out := make([]Opcode, 0, len(ops))
	for _, op := range ops {
		if !op.IsRawSpan {
			b := byte(op.Opcode)
			if b == opIf || b == opNotIf || b == opElse || b == opEndIf {
				continue
			}
		}
		out = append(out, op)
	}
	return out
}

// collectPathOps implements §7.4: traverse with branch-choice decisions
// and skip-jump to ELSE/ENDIF as appropriate.
//
// IMPORTANT semantic note: choices are consumed in *encounter* order,
// NOT source order. If a branch is skipped, the IFs nested inside the
// skipped body are never encountered dynamically and never consume a
// choice slot. So we do NOT advance choiceIdx past skipped IFs.
// (The path *description* is built separately from the full choices
// vector in source order — see buildPathDescription.) This matches
// the canonical fixture goldens (stateful-counter id=2 etc.).
func collectPathOps(ops []Opcode, closed []branchFrame, choices []bool) []Opcode {
	byIf := make(map[int]branchFrame, len(closed))
	for _, f := range closed {
		byIf[f.ifIndex] = f
	}
	choiceIdx := 0
	return collectPathOpsRange(ops, byIf, choices, &choiceIdx, 0, len(ops))
}

// collectPathOpsRange collects opcodes from a half-open range, honouring
// nested IF/NOTIF branches.
func collectPathOpsRange(ops []Opcode, byIf map[int]branchFrame, choices []bool, choiceIdx *int, lo, hi int) []Opcode {
	out := make([]Opcode, 0, hi-lo)
	i := lo
	for i < hi {
		op := ops[i]
		if !op.IsRawSpan {
			b := byte(op.Opcode)
			if b == opIf || b == opNotIf {
				frame, ok := byIf[i]
				if !ok {
					i++
					continue
				}
				take := true
				if *choiceIdx < len(choices) {
					take = choices[*choiceIdx]
				}
				*choiceIdx++
				if take {
					var bodyEnd int
					if frame.elseIndex < 0 {
						bodyEnd = frame.endifIndex
					} else {
						bodyEnd = frame.elseIndex
					}
					out = append(out, collectPathOpsRange(ops, byIf, choices, choiceIdx, frame.ifIndex+1, bodyEnd)...)
				} else if frame.elseIndex >= 0 {
					out = append(out, collectPathOpsRange(ops, byIf, choices, choiceIdx, frame.elseIndex+1, frame.endifIndex)...)
				}
				i = frame.endifIndex + 1
				continue
			}
			if b == opElse || b == opEndIf {
				i++
				continue
			}
		}
		out = append(out, op)
		i++
	}
	return out
}

// pathHasCheckSig — §7.5.
func pathHasCheckSig(ops []Opcode) bool {
	for _, op := range ops {
		if op.IsRawSpan {
			continue
		}
		switch byte(op.Opcode) {
		case opCheckSig, opCheckSigVerify, opCheckMultiSig, opCheckMultiSigVerify:
			return true
		}
	}
	return false
}

// isUnconditionalSucceed — §7.5.
func isUnconditionalSucceed(ops []Opcode) bool {
	if len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		if op.IsRawSpan {
			continue
		}
		switch byte(op.Opcode) {
		case opVerify, opReturn, opEqualVerify, opNumEqualVerify,
			opCheckSig, opCheckSigVerify, opCheckMultiSig, opCheckMultiSigVerify:
			return false
		}
	}
	return true
}

// branchDepthFindings — §7.6.
func branchDepthFindings(ops []Opcode, closed []branchFrame) []Finding {
	var out []Finding
	for _, frame := range closed {
		endifOp := ops[frame.endifIndex]
		if frame.elseIndex < 0 {
			delta, ok := flatDelta(ops, frame.ifIndex+1, frame.endifIndex)
			if !ok {
				continue
			}
			if delta != 0 {
				out = append(out, Finding{
					Severity:  SeverityWarning,
					Code:      "INCONSISTENT_BRANCH_DEPTH",
					Message:   fmt.Sprintf("OP_IF body has net stack delta %d; without an OP_ELSE the depth after OP_ENDIF depends on the branch condition", delta),
					Offset:    endifOp.Offset,
					HasOffset: true,
					Opcode:    "OP_ENDIF",
					HasOpcode: true,
				})
			}
		} else {
			thenDelta, ok1 := flatDelta(ops, frame.ifIndex+1, frame.elseIndex)
			elseDelta, ok2 := flatDelta(ops, frame.elseIndex+1, frame.endifIndex)
			if !ok1 || !ok2 {
				continue
			}
			if thenDelta != elseDelta {
				out = append(out, Finding{
					Severity:  SeverityWarning,
					Code:      "INCONSISTENT_BRANCH_DEPTH",
					Message:   fmt.Sprintf("IF/ELSE branches leave different stack depths (THEN: %d, ELSE: %d) — code after OP_ENDIF will see a depth that depends on which branch ran", thenDelta, elseDelta),
					Offset:    endifOp.Offset,
					HasOffset: true,
					Opcode:    "OP_ENDIF",
					HasOpcode: true,
				})
			}
		}
	}
	return out
}
