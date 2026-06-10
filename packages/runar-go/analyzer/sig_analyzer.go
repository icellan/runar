package analyzer

import "fmt"

// analyzeSigHygiene implements §9.
//
// - NO_SIG_CHECK: one warning per reachable path with hasCheckSig=false.
// - CHECKSIG_RESULT_DROPPED: one warning per OP_CHECKSIG or
//   OP_CHECKMULTISIG immediately followed by OP_DROP.
func analyzeSigHygiene(ops []Opcode, paths []ExecutionPath) []Finding {
	var out []Finding
	for _, p := range paths {
		if !p.Reachable || p.HasCheckSig {
			continue
		}
		out = append(out, Finding{
			Severity: SeverityWarning,
			Code:     "NO_SIG_CHECK",
			Message:  "Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)",
			Path:     p.Description,
			HasPath:  true,
		})
	}

	for i := 0; i+1 < len(ops); i++ {
		cur := ops[i]
		nxt := ops[i+1]
		if cur.IsRawSpan || nxt.IsRawSpan {
			continue
		}
		isSigOp := byte(cur.Opcode) == opCheckSig || byte(cur.Opcode) == opCheckMultiSig
		if !isSigOp {
			continue
		}
		if byte(nxt.Opcode) != opDrop {
			continue
		}
		out = append(out, Finding{
			Severity:  SeverityWarning,
			Code:      "CHECKSIG_RESULT_DROPPED",
			Message:   fmt.Sprintf("%s result is dropped by %s — signature check has no effect", cur.Name, nxt.Name),
			Offset:    cur.Offset,
			HasOffset: true,
			Opcode:    cur.Name,
			HasOpcode: true,
		})
	}
	return out
}
