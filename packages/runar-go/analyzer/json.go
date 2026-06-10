package analyzer

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// MarshalReport renders an AnalyzerReport to the canonical
// 2-space-indented, LF-terminated JSON form mandated by
// spec/script-analyzer-format.md §3.5. The trailing newline IS
// included.
func MarshalReport(r AnalyzerReport) string {
	var b strings.Builder
	emitReport(&b, r)
	b.WriteByte('\n')
	return b.String()
}

func emitReport(b *strings.Builder, r AnalyzerReport) {
	b.WriteString("{\n")
	indent := "  "

	b.WriteString(indent)
	b.WriteString(`"script": `)
	emitJSONString(b, r.Script)
	b.WriteString(",\n")

	b.WriteString(indent)
	b.WriteString(`"scriptSize": `)
	b.WriteString(strconv.Itoa(r.ScriptSize))
	b.WriteString(",\n")

	b.WriteString(indent)
	b.WriteString(`"findings": `)
	emitFindings(b, r.Findings, indent)
	b.WriteString(",\n")

	b.WriteString(indent)
	b.WriteString(`"paths": `)
	emitPaths(b, r.Paths, indent)
	b.WriteString(",\n")

	b.WriteString(indent)
	b.WriteString(`"summary": `)
	emitSummary(b, r.Summary, indent)
	b.WriteString("\n")

	b.WriteString("}")
}

func emitFindings(b *strings.Builder, items []Finding, parentIndent string) {
	if len(items) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteString("[\n")
	inner := parentIndent + "  "
	for i, f := range items {
		b.WriteString(inner)
		emitFinding(b, f, inner)
		if i+1 < len(items) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(parentIndent)
	b.WriteString("]")
}

func emitFinding(b *strings.Builder, f Finding, parentIndent string) {
	b.WriteString("{\n")
	inner := parentIndent + "  "

	type kv struct {
		key string
		val func()
	}
	var fields []kv
	fields = append(fields, kv{"severity", func() { emitJSONString(b, string(f.Severity)) }})
	fields = append(fields, kv{"code", func() { emitJSONString(b, f.Code) }})
	fields = append(fields, kv{"message", func() { emitJSONString(b, f.Message) }})
	if f.HasOffset {
		fields = append(fields, kv{"offset", func() { b.WriteString(strconv.Itoa(f.Offset)) }})
	}
	if f.HasOpcode {
		fields = append(fields, kv{"opcode", func() { emitJSONString(b, f.Opcode) }})
	}
	if f.HasPath {
		fields = append(fields, kv{"path", func() { emitJSONString(b, f.Path) }})
	}

	for i, kv := range fields {
		b.WriteString(inner)
		emitJSONString(b, kv.key)
		b.WriteString(": ")
		kv.val()
		if i+1 < len(fields) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(parentIndent)
	b.WriteString("}")
}

func emitPaths(b *strings.Builder, paths []ExecutionPath, parentIndent string) {
	if len(paths) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteString("[\n")
	inner := parentIndent + "  "
	for i, p := range paths {
		b.WriteString(inner)
		emitPath(b, p, inner)
		if i+1 < len(paths) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(parentIndent)
	b.WriteString("]")
}

func emitPath(b *strings.Builder, p ExecutionPath, parentIndent string) {
	b.WriteString("{\n")
	inner := parentIndent + "  "

	b.WriteString(inner)
	b.WriteString(`"id": `)
	b.WriteString(strconv.Itoa(p.ID))
	b.WriteString(",\n")

	b.WriteString(inner)
	b.WriteString(`"description": `)
	emitJSONString(b, p.Description)
	b.WriteString(",\n")

	b.WriteString(inner)
	b.WriteString(`"branchChoices": `)
	emitBoolArray(b, p.BranchChoices, inner)
	b.WriteString(",\n")

	b.WriteString(inner)
	b.WriteString(`"reachable": `)
	b.WriteString(boolStr(p.Reachable))
	b.WriteString(",\n")

	b.WriteString(inner)
	b.WriteString(`"hasCheckSig": `)
	b.WriteString(boolStr(p.HasCheckSig))
	b.WriteString(",\n")

	b.WriteString(inner)
	b.WriteString(`"stackDepthAtEnd": `)
	b.WriteString(strconv.Itoa(p.StackDepthAtEnd))
	b.WriteString("\n")

	b.WriteString(parentIndent)
	b.WriteString("}")
}

func emitSummary(b *strings.Builder, s Summary, parentIndent string) {
	b.WriteString("{\n")
	inner := parentIndent + "  "
	rows := []struct {
		key string
		val int
	}{
		{"totalPaths", s.TotalPaths},
		{"reachablePaths", s.ReachablePaths},
		{"pathsWithCheckSig", s.PathsWithCheckSig},
		{"pathsWithoutCheckSig", s.PathsWithoutCheckSig},
		{"maxStackDepth", s.MaxStackDepth},
		{"scriptSizeBytes", s.ScriptSizeBytes},
	}
	for i, r := range rows {
		b.WriteString(inner)
		emitJSONString(b, r.key)
		b.WriteString(": ")
		b.WriteString(strconv.Itoa(r.val))
		if i+1 < len(rows) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(parentIndent)
	b.WriteString("}")
}

func emitBoolArray(b *strings.Builder, arr []bool, parentIndent string) {
	if len(arr) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteString("[\n")
	inner := parentIndent + "  "
	for i, v := range arr {
		b.WriteString(inner)
		b.WriteString(boolStr(v))
		if i+1 < len(arr) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(parentIndent)
	b.WriteString("]")
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// emitJSONString writes a JSON-escaped string surrounded by double
// quotes. Per spec §3.5: standard control-character escapes only; solidus
// is NOT escaped; non-ASCII passes through verbatim as UTF-8.
func emitJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
			i++
		case c == '\\':
			b.WriteString(`\\`)
			i++
		case c == '\b':
			b.WriteString(`\b`)
			i++
		case c == '\f':
			b.WriteString(`\f`)
			i++
		case c == '\n':
			b.WriteString(`\n`)
			i++
		case c == '\r':
			b.WriteString(`\r`)
			i++
		case c == '\t':
			b.WriteString(`\t`)
			i++
		case c < 0x20:
			// Other control characters → \u00XX.
			b.WriteString(`\u00`)
			const hexd = "0123456789abcdef"
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&0x0f])
			i++
		case c < 0x80:
			b.WriteByte(c)
			i++
		default:
			// Multi-byte UTF-8: copy verbatim.
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// Invalid byte — emit � escape.
				b.WriteString(`�`)
				i++
				continue
			}
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	b.WriteByte('"')
}
