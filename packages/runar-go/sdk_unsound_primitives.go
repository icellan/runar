package runar

import (
	"fmt"
	"strings"
)

// R-062 / CL-BUG-105 — deploy-time gate on builtins the project does not claim
// are sound.
//
// The compiler refuses to emit a script reaching `verifySP1FRI` unless the
// author wrote `@acknowledgeUnsoundSP1FriVerifier` or the invoker passed
// `--acknowledge-unsound-sp1-fri` (R-012). That acknowledgement stopped at
// whoever ran the compiler: the artifact handed on afterwards looked like any
// other, carried no marker of the gap, and every SDK funded it in silence —
// which is how an acknowledged proof-of-concept verifier reaches a
// value-bearing deployment with no friction.
//
// The compiler now stamps `unsoundPrimitives` into the artifact. This guard is
// the SDK half: the deploy path calls it BEFORE any signing or broadcast, and
// the caller must name each listed primitive to proceed.
//
// Deploy only, deliberately. Spending an already-deployed contract is how funds
// are RECOVERED from one, and refusing that would strand coins whose risk was
// taken at deploy time. The friction belongs where the value first enters.

// assertUnsoundPrimitivesAcknowledged returns an error unless every unsound
// primitive the artifact declares appears in acknowledged.
func assertUnsoundPrimitivesAcknowledged(
	artifact *RunarArtifact,
	acknowledged []string,
	context string,
) error {
	if artifact == nil || len(artifact.UnsoundPrimitives) == 0 {
		return nil
	}
	ok := make(map[string]struct{}, len(acknowledged))
	for _, a := range acknowledged {
		ok[a] = struct{}{}
	}
	var missing []string
	for _, p := range artifact.UnsoundPrimitives {
		if _, found := ok[p]; !found {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	plural := "s"
	if len(missing) == 1 {
		plural = ""
	}
	quoted := make([]string, len(missing))
	for i, m := range missing {
		quoted[i] = fmt.Sprintf("%q", m)
	}
	return fmt.Errorf(
		"%s: this artifact reaches %d builtin%s the compiler does not claim is sound: %s. "+
			"The compiler emitted it only because the gap was acknowledged at COMPILE time; "+
			"funding it is a second decision, and this SDK will not make it for you. "+
			"Set DeployOptions.AcknowledgeUnsound = []string{%s} to proceed",
		context, len(missing), plural, strings.Join(missing, ", "), strings.Join(quoted, ", "),
	)
}
