package runar

import (
	"strings"
	"testing"
)

// R-062 / CL-BUG-105 — see sdk_unsound_primitives.go for the finding.
// Mirrors packages/runar-sdk/src/__tests__/unsound-primitives.test.ts.

func unsoundArtifact(primitives ...string) *RunarArtifact {
	return &RunarArtifact{
		Version:           "runar-v1.0.0-rc.1",
		CompilerVersion:   "1.0.0-rc.1-go",
		ContractName:      "Sp1Rollup",
		Script:            "51",
		ASM:               "OP_1",
		BuildTimestamp:    "2026-09-13T00:00:00Z",
		UnsoundPrimitives: primitives,
	}
}

func TestUnsoundGuard_OrdinaryArtifactPassesEitherWay(t *testing.T) {
	plain := unsoundArtifact()
	for _, ack := range [][]string{nil, {}, {"verifySP1FRI"}} {
		if err := assertUnsoundPrimitivesAcknowledged(plain, ack, "Counter.Deploy"); err != nil {
			t.Fatalf("ordinary artifact must deploy freely; got %v", err)
		}
	}
	if err := assertUnsoundPrimitivesAcknowledged(nil, nil, "Counter.Deploy"); err != nil {
		t.Fatalf("a nil artifact must not panic or refuse here; got %v", err)
	}
}

func TestUnsoundGuard_RefusesUnacknowledged(t *testing.T) {
	err := assertUnsoundPrimitivesAcknowledged(unsoundArtifact("verifySP1FRI"), nil, "Sp1Rollup.Deploy")
	if err == nil {
		t.Fatal("an unsound artifact must NOT deploy without acknowledgement")
	}
	if !strings.Contains(err.Error(), "verifySP1FRI") {
		t.Errorf("error must name the primitive; got %v", err)
	}
	if !strings.Contains(err.Error(), "Sp1Rollup.Deploy") {
		t.Errorf("error must name the call site; got %v", err)
	}
	if !strings.Contains(err.Error(), "AcknowledgeUnsound") {
		t.Errorf("error must say how to proceed; got %v", err)
	}
}

func TestUnsoundGuard_AcknowledgementMustNameEveryPrimitive(t *testing.T) {
	if err := assertUnsoundPrimitivesAcknowledged(
		unsoundArtifact("verifySP1FRI"), []string{"verifySP1FRI"}, "Sp1Rollup.Deploy",
	); err != nil {
		t.Fatalf("a complete acknowledgement must be accepted; got %v", err)
	}

	err := assertUnsoundPrimitivesAcknowledged(
		unsoundArtifact("verifySP1FRI", "someFutureStub"), []string{"verifySP1FRI"}, "Sp1Rollup.Deploy",
	)
	if err == nil {
		t.Fatal("a PARTIAL acknowledgement must be refused")
	}
	if !strings.Contains(err.Error(), "someFutureStub") {
		t.Errorf("error must name the unacknowledged one; got %v", err)
	}

	if err := assertUnsoundPrimitivesAcknowledged(
		unsoundArtifact("verifySP1FRI"), []string{"somethingElse"}, "Sp1Rollup.Deploy",
	); err == nil {
		t.Fatal("acknowledging a DIFFERENT primitive must not unlock this one")
	}
}
