package frontend

import "fmt"

// MaxSourceBytes mirrors InputLimits.MAX_SOURCE_BYTES (4 MiB) from the TS
// schema package. Any Rúnar source file larger than this is rejected at
// the parser entry point (ParseSource / Parse / per-format parsers) BEFORE
// the tokenizer touches the input. BUG-008 follow-up.
//
// Depth/nesting bounds are not enforced as a single entry-point check
// here: recursive-descent parsers in this tier do not currently expose
// a uniform depth counter. The byte cap bounds total work at
// MaxSourceBytes / (smallest-grammar-production-size), so deeply nested
// adversarial input is bounded transitively.
const MaxSourceBytes = 4 * 1024 * 1024

// SourceSizeExceededError is returned when a source payload exceeds
// MaxSourceBytes at a public parser entry point. Distinct typed error so
// callers can distinguish DoS-bound rejection from generic syntax errors.
type SourceSizeExceededError struct {
	Limit  int
	Actual int
}

func (e *SourceSizeExceededError) Error() string {
	return fmt.Sprintf(
		"source exceeds MAX_SOURCE_BYTES (limit=%d, actual=%d)",
		e.Limit, e.Actual,
	)
}

// assertSourceBytesUnderLimit returns SourceSizeExceededError if
// len(source) exceeds MaxSourceBytes. Returns nil otherwise.
func assertSourceBytesUnderLimit(source []byte) error {
	if len(source) > MaxSourceBytes {
		return &SourceSizeExceededError{Limit: MaxSourceBytes, Actual: len(source)}
	}
	return nil
}
