package ir

import "fmt"

// MaxIRBytes mirrors InputLimits.MAX_IR_BYTES (16 MiB) from the TS schema
// package. Any ANF IR JSON larger than this is rejected at the loader
// entry points (LoadIR / LoadIRFromBytes) BEFORE json.Unmarshal runs so
// a malicious caller cannot exhaust memory / CPU with a giant payload.
//
// Empirically the largest legitimate compiled-IR JSON observed during
// conformance is ~2 MiB (Mode 3 STARK contracts); 16 MiB is 8x headroom.
const MaxIRBytes = 16 * 1024 * 1024

// MaxSourceBytes mirrors InputLimits.MAX_SOURCE_BYTES (4 MiB) from the TS
// schema package. Any Rúnar source file larger than this is rejected at
// the parser entry point (frontend.ParseSource) BEFORE the tokenizer
// touches the input. BUG-008 follow-up.
const MaxSourceBytes = 4 * 1024 * 1024

// MaxIRNesting mirrors InputLimits.MAX_NESTING (512) from the TS schema
// package. ANF IR JSON whose structural nesting (objects + arrays)
// exceeds this is rejected. Prevents stack-exhaustion DoS via deeply
// nested JSON.
const MaxIRNesting = 512

// IRSizeExceededError is returned when an IR JSON payload exceeds
// MaxIRBytes at a public loader entry point. Distinct typed error so
// callers can distinguish DoS-bound rejection from generic
// json.Unmarshal failures.
type IRSizeExceededError struct {
	Limit  int
	Actual int
}

func (e *IRSizeExceededError) Error() string {
	return fmt.Sprintf(
		"IR JSON exceeds MAX_IR_BYTES (limit=%d, actual=%d)",
		e.Limit, e.Actual,
	)
}

// IRNestingExceededError is returned when an IR JSON payload's structural
// nesting (objects + arrays) exceeds MaxIRNesting. Distinct typed error
// so callers can distinguish DoS-bound rejection from generic
// json.Unmarshal failures.
type IRNestingExceededError struct {
	Limit int
}

func (e *IRNestingExceededError) Error() string {
	return fmt.Sprintf(
		"IR JSON nesting exceeds MAX_NESTING (limit=%d)",
		e.Limit,
	)
}

// assertIRBytesUnderLimit returns IRSizeExceededError if len(data) exceeds
// MaxIRBytes. Returns nil otherwise.
func assertIRBytesUnderLimit(data []byte) error {
	if len(data) > MaxIRBytes {
		return &IRSizeExceededError{Limit: MaxIRBytes, Actual: len(data)}
	}
	return nil
}

// assertIRNestingUnderLimit walks the raw JSON bytes and bails out the
// first time the nesting depth (objects + arrays) exceeds MaxIRNesting.
// Runs BEFORE json.Unmarshal so a deeply-nested payload cannot exhaust
// the Go runtime's recursion stack inside the stdlib JSON decoder.
//
// The walk is purely structural — it tracks `{`/`[` push and `}`/`]` pop
// and skips strings (respecting backslash-escapes) so a `{` inside a
// JSON string doesn't count toward depth.
func assertIRNestingUnderLimit(data []byte) error {
	depth := 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > MaxIRNesting {
				return &IRNestingExceededError{Limit: MaxIRNesting}
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}
