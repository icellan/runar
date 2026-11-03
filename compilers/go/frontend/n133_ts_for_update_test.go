package frontend

import (
	"strings"
	"testing"
)

// N-133. The Go .runar.ts parser's parseForUpdate intercepted
// `assignment_expression` and `augmented_assignment_expression` in the for
// header's update slot and desugared them into an Assignment statement, so
// `i += 1n`, `i -= 1n` and `i = i + 1n` compiled (938 hexchars, byte-identical
// to `i++`) on this tier alone. The TS reference's parseForUpdate accepts only
// the prefix/postfix `++`/`--` forms there and hands everything else to
// parseExpression, which refuses an assignment operator with
// "Unsupported binary operator: '<op>'". The other five non-TS tiers refuse the
// same shapes in their parsers.
//
// The comma shape `i++, this.count++` is the fail-open member of the family:
// before N-052 the sequence expression was zeroed and the per-iteration state
// write was silently DROPPED from the script. N-052 already refuses it via
// parseExpression; the case is pinned here so the for-update slot keeps
// routing through that refusal.
//
// Proves: each shape is refused by the Go .runar.ts parser with the TS
// reference's diagnostic text, and the unit-step `++`/`--` forms (prefix and
// postfix, up and down) still parse clean. Does not prove: other Go-tier
// surfaces (.runar.go/.sol/.zig/...), whose own update rules live elsewhere,
// nor byte-level codegen (covered by the conformance goldens and
// compiler/loop_update_clause_test.go's controls).

func n133Wrap(update, cond string) string {
	return `import { StatefulSmartContract, assert } from 'runar-lang';

class UpdateProbe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 3n; ` + cond + `; ` + update + `) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
`
}

func TestN133_ForUpdateRefusesWhatTheReferenceRefuses(t *testing.T) {
	for _, c := range []struct{ update, cond, want string }{
		{"i++, this.count++", "i < 6n", "Unsupported binary operator: ','"},
		{"i += 1n", "i < 6n", "Unsupported binary operator: '+='"},
		{"i -= 1n", "i > 0n", "Unsupported binary operator: '-='"},
		{"i = i + 1n", "i < 6n", "Unsupported binary operator: '='"},
		{"i = i - 1n", "i > 0n", "Unsupported binary operator: '='"},
		{"i += 2n", "i < 6n", "Unsupported binary operator: '+='"},
	} {
		t.Run(c.update, func(t *testing.T) {
			res := ParseSource([]byte(n133Wrap(c.update, c.cond)), "UpdateProbe.runar.ts")
			for _, e := range res.Errors {
				if strings.Contains(e.Message, c.want) {
					return
				}
			}
			t.Fatalf("for-update `%s` was not refused with %q; errors: %v", c.update, c.want, res.Errors)
		})
	}
}

func TestN133_UnitStepForUpdatesStillParse(t *testing.T) {
	for _, c := range []struct{ update, cond string }{
		{"i++", "i < 6n"},
		{"++i", "i < 6n"},
		{"i--", "i > 0n"},
		{"--i", "i > 0n"},
	} {
		res := ParseSource([]byte(n133Wrap(c.update, c.cond)), "UpdateProbe.runar.ts")
		if len(res.Errors) != 0 || res.Contract == nil {
			t.Errorf("for-update `%s` rejected: %v", c.update, res.Errors)
		}
	}
}
