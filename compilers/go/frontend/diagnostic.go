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

// JavaCharLiteralMsg is the TS reference's refusal of a Java char literal.
const JavaCharLiteralMsg = "char literals are unsupported in Rúnar Java contracts"

// lexDiag builds a tokenizer diagnostic located at line:col of file.
func lexDiag(msg, file string, line, col int) Diagnostic {
	return Diagnostic{Message: msg, Severity: SeverityError, Loc: &SourceLocation{File: file, Line: line, Column: col}}
}
