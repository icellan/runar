package ir

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadIRFromBytes_RejectsOversizedInput(t *testing.T) {
	// Construct a payload one byte over MaxIRBytes. The byte stream
	// does not need to be valid JSON — the size guard fires first.
	oversized := make([]byte, MaxIRBytes+1)
	for i := range oversized {
		oversized[i] = ' '
	}

	_, err := LoadIRFromBytes(oversized)
	if err == nil {
		t.Fatal("expected IRSizeExceededError, got nil")
	}
	var sizeErr *IRSizeExceededError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("expected *IRSizeExceededError, got %T: %v", err, err)
	}
	if sizeErr.Limit != MaxIRBytes {
		t.Errorf("expected Limit=%d, got %d", MaxIRBytes, sizeErr.Limit)
	}
	if sizeErr.Actual != MaxIRBytes+1 {
		t.Errorf("expected Actual=%d, got %d", MaxIRBytes+1, sizeErr.Actual)
	}
}

func TestLoadIRFromBytes_RejectsDeeplyNestedInput(t *testing.T) {
	// Build a JSON payload nested MaxIRNesting+50 levels deep
	// ({"n":{"n":{...}}}). Exceeds MaxIRNesting (512); the size cap
	// is comfortably not tripped because total bytes ~= 5*depth.
	depth := MaxIRNesting + 50
	body := "1"
	for i := 0; i < depth; i++ {
		body = "{\"n\":" + body + "}"
	}

	_, err := LoadIRFromBytes([]byte(body))
	if err == nil {
		t.Fatal("expected IRNestingExceededError, got nil")
	}
	var nestErr *IRNestingExceededError
	if !errors.As(err, &nestErr) {
		t.Fatalf("expected *IRNestingExceededError, got %T: %v", err, err)
	}
	if nestErr.Limit != MaxIRNesting {
		t.Errorf("expected Limit=%d, got %d", MaxIRNesting, nestErr.Limit)
	}
}

func TestLoadIRFromBytes_DepthCapIgnoresStringContents(t *testing.T) {
	// A JSON string containing 1000 `{` should NOT count toward
	// structural depth — the walk must respect string delimiters.
	// Wrap in a valid (but otherwise empty) IR shape so json.Unmarshal
	// proceeds to validation (which we expect to fail on missing
	// contractName — the *size guard* is what we're testing here:
	// it must NOT trip).
	openBraces := strings.Repeat("{", 1000)
	bad := `{"contractName":"X","properties":[],"methods":[],"_note":"` + openBraces + `"}`

	_, err := LoadIRFromBytes([]byte(bad))
	// We expect this to PARSE fine (size + depth caps clear) and then
	// proceed downstream. The exact downstream outcome (success or
	// validation error) is not the assertion here — only that we get
	// neither IRSizeExceededError nor IRNestingExceededError.
	var sizeErr *IRSizeExceededError
	if errors.As(err, &sizeErr) {
		t.Fatalf("size cap incorrectly tripped on string contents: %v", err)
	}
	var nestErr *IRNestingExceededError
	if errors.As(err, &nestErr) {
		t.Fatalf("nesting cap incorrectly tripped on string contents: %v", err)
	}
}
