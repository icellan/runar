package frontend

import "fmt"

// Severity represents the level of a compiler diagnostic.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Diagnostic represents a single compiler diagnostic (error or warning).
type Diagnostic struct {
	Message  string
	Loc      *SourceLocation
	Severity Severity
}

// MakeDiagnostic creates a diagnostic with the given message, severity, and optional location.
func MakeDiagnostic(message string, severity Severity, loc *SourceLocation) Diagnostic {
	return Diagnostic{Message: message, Severity: severity, Loc: loc}
}

// FormatMessage returns the diagnostic message with optional file:line:column prefix.
func (d Diagnostic) FormatMessage() string {
	if d.Loc != nil && d.Loc.File != "" {
		if d.Loc.Column > 0 {
			return fmt.Sprintf("%s:%d:%d: %s", d.Loc.File, d.Loc.Line, d.Loc.Column, d.Message)
		}
		return fmt.Sprintf("%s:%d: %s", d.Loc.File, d.Loc.Line, d.Message)
	}
	return d.Message
}

// UnterminatedStringLiteralMsg is F-011's shared diagnostic (the TS
// reference's UNTERMINATED_STRING_LITERAL): every hand-written tokenizer emits
// it, at the opening quote, for a quoted literal that reaches a line break or
// end of file before its closing quote. On .runar.rs and for Python
// triple-quoted strings, which may span lines, only end of file counts.
const UnterminatedStringLiteralMsg = "unterminated string literal"

// ZigListCommaMsg is F-026's refusal of a .runar.zig call argument list or
// array literal whose elements are not separated by commas (the TS reference's
// ZIG_LIST_COMMA).
const ZigListCommaMsg = "expected ',' between list elements"

// PyStatementLineBreakMsg is F-026's refusal of a second .runar.py statement
// on the same line (the TS reference's PY_STATEMENT_LINE_BREAK).
const PyStatementLineBreakMsg = "expected a line break between statements"

// JavaCharLiteralMsg is the TS reference's refusal of a Java char literal.
const JavaCharLiteralMsg = "char literals are unsupported in Rúnar Java contracts"

// UnsupportedStatementMsg is N-053's refusal of a .runar.rb / .runar.py
// statement whose first token can begin neither a statement nor an expression
// (the TS reference's unsupportedStatementMessage). `token` is the token's
// source text.
func UnsupportedStatementMsg(token string) string {
	return fmt.Sprintf("Unsupported statement starting with '%s'", token)
}

// StaticMethodMsg is N-050's refusal of a static or class-level method (the
// TS reference's staticMethodMessage): `static` on .runar.ts / .runar.java,
// `@staticmethod` / `@classmethod` on .runar.py, `def self.m` on .runar.rb,
// and a `pub fn` without a self receiver on .runar.rs / .runar.zig. `name` is
// the method name as written in the source.
func StaticMethodMsg(name string) string {
	return "static methods are not allowed in Rúnar contracts; method '" + name + "' is declared static"
}

// BareJavaPropertyAssignmentMsg is N-023's (R49) refusal, on the .runar.java
// surface, of an assignment (=, op=, ++, --) to a bare property name that no
// local or parameter shadows (the TS reference's
// bareJavaPropertyAssignmentMessage). In Java that bare name IS the field.
func BareJavaPropertyAssignmentMsg(name string) string {
	return "bare assignment to property '" + name + "' is not allowed; write `this." + name + " = ...`"
}

// lexDiag builds a tokenizer diagnostic located at line:col of file.
func lexDiag(msg, file string, line, col int) Diagnostic {
	return Diagnostic{Message: msg, Severity: SeverityError, Loc: &SourceLocation{File: file, Line: line, Column: col}}
}
