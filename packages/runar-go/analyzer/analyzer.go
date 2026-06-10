package analyzer

import (
	"sort"
)

// AnalyzeScript is the top-level entry point. It accepts a (possibly
// whitespaced) hex string and returns a normalized report. See §11.
func AnalyzeScript(hexScript string) (AnalyzerReport, error) {
	return AnalyzeScriptWithOptions(hexScript, AnalyzeOptions{})
}

// AnalyzeScriptWithOptions is the same as AnalyzeScript but accepts
// raw-script spans (spec §12).
func AnalyzeScriptWithOptions(hexScript string, opts AnalyzeOptions) (AnalyzerReport, error) {
	normalized := normalizeHex(hexScript)
	scriptSize := len(normalized) / 2

	if scriptSize == 0 {
		return AnalyzerReport{
			Script:     "",
			ScriptSize: 0,
			Findings: []Finding{{
				Severity: SeverityError,
				Code:     "INVALID_TERMINAL_STACK",
				Message:  "Empty script — no opcodes to execute",
			}},
			Paths: []ExecutionPath{},
			Summary: Summary{
				TotalPaths:           0,
				ReachablePaths:       0,
				PathsWithCheckSig:    0,
				PathsWithoutCheckSig: 0,
				MaxStackDepth:        0,
				ScriptSizeBytes:      0,
			},
		}, nil
	}

	ops, err := parseScript(normalized)
	if err != nil {
		return AnalyzerReport{}, err
	}
	if len(opts.RawScriptSpans) > 0 {
		ops = collapseRawScriptSpans(ops, opts.RawScriptSpans)
	}

	var allFindings []Finding

	pathRes := analyzePaths(ops)
	allFindings = append(allFindings, pathRes.findings...)

	// Linear-fallback only if zero paths AND no UNBALANCED_IF_ENDIF.
	if len(pathRes.paths) == 0 {
		hasStructErr := false
		for _, f := range pathRes.findings {
			if f.Code == "UNBALANCED_IF_ENDIF" {
				hasStructErr = true
				break
			}
		}
		if !hasStructErr {
			linear := analyzeStackLinear(ops, 0)
			allFindings = append(allFindings, linear.findings...)
		}
	}

	allFindings = append(allFindings, analyzeSigHygiene(ops, pathRes.paths)...)
	allFindings = append(allFindings, analyzeOpcodeConcerns(ops, scriptSize)...)

	// Summary.
	//
	// NOTE: maxStackDepth is `max(0, max-over-paths stackDepthAtEnd)`
	// — the reduction is seeded with 0 to match the canonical goldens
	// (see _review/GAP-008-spec-ambiguities.md).
	summary := Summary{ScriptSizeBytes: scriptSize}
	summary.TotalPaths = len(pathRes.paths)
	maxDepthSeen := 0
	for _, p := range pathRes.paths {
		if p.Reachable {
			summary.ReachablePaths++
			if p.HasCheckSig {
				summary.PathsWithCheckSig++
			} else {
				summary.PathsWithoutCheckSig++
			}
		}
		if p.StackDepthAtEnd > maxDepthSeen {
			maxDepthSeen = p.StackDepthAtEnd
		}
	}
	summary.MaxStackDepth = maxDepthSeen

	sortFindings(allFindings)

	if allFindings == nil {
		allFindings = []Finding{}
	}
	paths := pathRes.paths
	if paths == nil {
		paths = []ExecutionPath{}
	}

	return AnalyzerReport{
		Script:     normalized,
		ScriptSize: scriptSize,
		Findings:   allFindings,
		Paths:      paths,
		Summary:    summary,
	}, nil
}

func severityRank(s Severity) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// sortFindings is a stable sort by (severityRank, offsetRank). Findings
// without an offset sort to the end of their severity bucket. Ties
// preserve original order (§11.1).
func sortFindings(f []Finding) {
	const inf = int(^uint(0) >> 1) // math.MaxInt
	sort.SliceStable(f, func(i, j int) bool {
		ri := severityRank(f[i].Severity)
		rj := severityRank(f[j].Severity)
		if ri != rj {
			return ri < rj
		}
		oi := inf
		if f[i].HasOffset {
			oi = f[i].Offset
		}
		oj := inf
		if f[j].HasOffset {
			oj = f[j].Offset
		}
		return oi < oj
	})
}
