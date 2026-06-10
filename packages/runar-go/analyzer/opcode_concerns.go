package analyzer

import (
	"fmt"
	"math"
)

// analyzeOpcodeConcerns implements §10.
func analyzeOpcodeConcerns(ops []Opcode, scriptSizeBytes int) []Finding {
	var out []Finding

	if scriptSizeBytes > largeScriptThreshold {
		kb := formatKilobytes(scriptSizeBytes)
		out = append(out, Finding{
			Severity: SeverityInfo,
			Code:     "LARGE_SCRIPT",
			Message:  fmt.Sprintf("Script is %d bytes (%s KB) — consider if this is intentional", scriptSizeBytes, kb),
		})
	}

	for _, op := range ops {
		if op.IsRawSpan {
			continue
		}
		if byte(op.Opcode) == opCodeSeparator {
			out = append(out, Finding{
				Severity:  SeverityInfo,
				Code:      "CODESEPARATOR_PRESENT",
				Message:   "OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise",
				Offset:    op.Offset,
				HasOffset: true,
				Opcode:    op.Name,
				HasOpcode: true,
			})
		}
		switch op.PushEncoding {
		case "pushdata1":
			n := len(op.Data)
			if n <= 75 {
				out = append(out, Finding{
					Severity:  SeverityInfo,
					Code:      "INEFFICIENT_PUSH",
					Message:   fmt.Sprintf("OP_PUSHDATA1 used for %d-byte data — direct push (opcode 0x%02x) would be more efficient", n, n),
					Offset:    op.Offset,
					HasOffset: true,
					Opcode:    op.Name,
					HasOpcode: true,
				})
			}
		case "pushdata2":
			n := len(op.Data)
			if n <= 255 {
				out = append(out, Finding{
					Severity:  SeverityInfo,
					Code:      "INEFFICIENT_PUSH",
					Message:   fmt.Sprintf("OP_PUSHDATA2 used for %d-byte data — OP_PUSHDATA1 would be more efficient", n),
					Offset:    op.Offset,
					HasOffset: true,
					Opcode:    op.Name,
					HasOpcode: true,
				})
			}
		case "pushdata4":
			n := len(op.Data)
			if n <= 65535 {
				out = append(out, Finding{
					Severity:  SeverityInfo,
					Code:      "INEFFICIENT_PUSH",
					Message:   fmt.Sprintf("OP_PUSHDATA4 used for %d-byte data — OP_PUSHDATA2 would be more efficient", n),
					Offset:    op.Offset,
					HasOffset: true,
					Opcode:    op.Name,
					HasOpcode: true,
				})
			}
		}
	}
	return out
}

// formatKilobytes renders n/1024 to one decimal digit using
// round-half-to-even, matching JS `(n/1024).toFixed(1)` semantics
// (spec §5.1 LARGE_SCRIPT).
func formatKilobytes(n int) string {
	scaled := float64(n) * 10.0 / 1024.0
	rounded := math.RoundToEven(scaled)
	// rounded is the tenths integer; integer part is rounded/10, tenth digit is rounded%10.
	intPart := int64(rounded) / 10
	tenth := int64(rounded) % 10
	if tenth < 0 {
		tenth = -tenth
	}
	return fmt.Sprintf("%d.%d", intPart, tenth)
}
