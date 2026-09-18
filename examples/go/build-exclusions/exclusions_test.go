// Package buildexclusions holds the ratchet on `//go:build ignore` in
// examples/go. It has no production code; the test IS the artifact.
package buildexclusions

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RATCHET — exactly FIVE .runar.go ports are excluded from the Go build, and
// every one of them carries a written reason.
//
// WHY. A `.runar.go` contract is meant to be valid Go as well as valid Rúnar:
// `go test ./...` checks its business logic against the mock types in
// packages/runar-go while `runar.CompileCheck` checks it as Rúnar. A port
// carrying `//go:build ignore` gets only the second half, silently. 32 of the
// 84 ports carried the tag; 29 of those imported the module path `"runar"`,
// which resolves to nothing, and only 3 carried a written reason. Staging each
// one with the tag stripped and compiling it showed 23 were excluded by that
// dead import and nothing else. Drift, not a language limit.
//
// That is the exact shape this branch keeps finding: `pow` returned
// base^min(exp,32) for three review rounds, the Go surface silently dropped
// Sha256/Ripemd160 and made the public digest the spending key, a descending
// Move `while` dropped its body in all seven tiers. Each survived by not being
// run.
//
// WHY A SET AND NOT A COUNT. `len(excluded) <= 8` is a guard that stops being
// read: a bound that only has to be "not worse" absorbs the next exclusion
// without argument. This asserts the SET with reflect.DeepEqual, so a SIXTH
// exclusion fails here and has to justify itself in the same commit -- the way
// STALE_PIN_BUDGET === 0 forces a justification for a stale golden pin.
// Removing an exclusion fails here too, which is correct: it should be
// deliberate and it should say so.
//
// NON-VACUITY. The expected set is non-empty, so this cannot pass by matching
// nothing the way an empty `toEqual` can -- but the SCANNER still could, if its
// idea of "excluded" were wrong. TestScanner_FindsTagsAndNothingElse feeds it a
// synthetic tree and requires the right answer, including the two ways this
// scan has already been seen to go wrong: a file that merely MENTIONS the tag
// in prose is not excluded, and the constraint only counts on the first line.
// ---------------------------------------------------------------------------

// excludedPorts is the full, intentional set. Each entry is
// "<directory>/<file>" relative to examples/go, and each is justified in a
// comment at the top of the named file -- see TestEveryExclusion_CarriesAReason.
//
// The three root causes, from compiling each one and reading the error:
//
//	Go's unused-local rule vs a deliberately unused binding
//	  all-readonly-cleanstack
//
//	a Rúnar bigint LITERAL wider than int64 has no Go spelling. Go constants
//	are exact and must fit the type they land in, `runar.BigintBig` is
//	*big.Int and no constant converts to a pointer, and the arithmetic these
//	three fixtures perform on such a literal (`*`, `+`, a `within` bound) is
//	the part Go has no operator for. This is NOT the same as "the mock's
//	Bigint is int64": that was the cause behind p256-primitives and
//	p384-primitives, whose scalars are merely PASSED to a *big.Int parameter,
//	and both build now that they are typed `runar.BigintBig`
//	  go-dsl-bytestring-literal, integer-boundary, schnorr-zkp
//
//	the `[N]T{...}` composite literal three of the seven .runar.go parsers
//	require does not convert to the slice the mock's CheckMultiSig takes
//	  multisig-2of3
var excludedPorts = []string{
	"all-readonly-cleanstack/AllReadonlyCleanstack.runar.go",
	"go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go",
	"integer-boundary/IntegerBoundary.runar.go",
	"multisig-2of3/MultiSig2of3.runar.go",
	"schnorr-zkp/SchnorrZKP.runar.go",
}

// reasonMarker is the header every excluded file must carry. Requiring a fixed
// marker rather than "some comment" is what stops a future exclusion from being
// justified by whatever prose already happened to be at the top of the file.
const reasonMarker = "// EXCLUDED FROM THE GO BUILD"

// examplesRoot is examples/go, one level up from this package.
func examplesRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving examples/go: %v", err)
	}
	return abs
}

// hasIgnoreTag reports whether the file's build constraint excludes it.
//
// Go requires a `//go:build` line to appear before the package clause and to be
// followed by a blank line, so only the leading comment block can carry one.
// Scanning the whole file for the string instead is how an earlier pass of this
// work got a wrong answer: several of these files DISCUSS `//go:build ignore`
// in their rationale, and a whole-file grep counts those as exclusions.
func hasIgnoreTag(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			if strings.HasPrefix(line, "//go:build ") {
				return strings.Contains(line, "ignore")
			}
			continue
		}
		// Reached the package clause (or anything else): no constraint.
		return false
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return false
}

// scanExclusions walks root for *.runar.go and returns the excluded ones,
// sorted, relative to root.
func scanExclusions(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".runar.go") {
			return nil
		}
		if !hasIgnoreTag(t, path) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

func TestExcludedPorts_AreExactlyTheJustifiedFive(t *testing.T) {
	got := scanExclusions(t, examplesRoot(t))
	want := append([]string(nil), excludedPorts...)
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(`the set of .runar.go ports excluded from the Go build changed.

got  (%d): %v
want (%d): %v

A .runar.go contract is supposed to compile BOTH as Rúnar and as Go -- that is
what makes `+"`go test ./...`"+` check its business logic instead of only its syntax.
An exclusion gives up half of that, so the set is pinned rather than bounded.

Adding one: write the reason at the top of the contract file, starting with
%q, and add it to excludedPorts in the same commit. "It did not
compile" is not a reason; the compiler error and why the port cannot be
expressed in Go without weakening it, is. Note that 24 of the 32 ports that
once carried this tag turned out to need nothing but a corrected
`+"`import \"runar\"`"+` path.

Removing one: delete it from excludedPorts here. Make sure the port is fixed
rather than deleted -- the fix is the point.`,
			len(got), got, len(want), want, reasonMarker)
	}
}

func TestEveryExclusion_CarriesAReason(t *testing.T) {
	root := examplesRoot(t)
	for _, rel := range excludedPorts {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(rel))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s is listed as excluded but cannot be read: %v", rel, err)
			}
			src := string(raw)

			if !hasIgnoreTag(t, path) {
				t.Fatalf("%s is listed in excludedPorts but carries no ignore "+
					"constraint -- drop it from the list", rel)
			}

			idx := strings.Index(src, reasonMarker)
			if idx < 0 {
				t.Fatalf("%s carries a //go:build ignore constraint with no %q header. "+
					"An exclusion without a written reason is how this set grew "+
					"to 32 in the first place.", rel, reasonMarker)
			}

			// The reason must precede the package clause, so it is the first
			// thing a reader of the file sees rather than a footnote.
			pkg := strings.Index(src, "\npackage ")
			if pkg >= 0 && idx > pkg {
				t.Fatalf("%s has its %q header AFTER the package clause", rel, reasonMarker)
			}

			// A marker with nothing under it is a label, not a justification.
			// Require the reason block to actually say something: the compiler
			// diagnostic and the explanation around it do not fit in two lines.
			reason := src[idx:]
			if pkg > idx {
				reason = src[idx:pkg]
			}
			if lines := strings.Count(reason, "\n"); lines < 8 {
				t.Fatalf("%s has a %d-line reason block; that is a label, not a "+
					"justification. Name the compiler error and why the port "+
					"cannot be written in Go without weakening what it tests.",
					rel, lines)
			}
		})
	}
}

// TestScanner_FindsTagsAndNothingElse is the non-vacuity guard.
//
// The set assertion above is only as good as scanExclusions. A scanner that
// returned the hard-coded list, or that matched the tag anywhere in the file,
// would make TestExcludedPorts_AreExactlyTheJustifiedFive pass while telling
// nobody anything. This runs it over a synthetic tree whose answer is known,
// and includes the two cases that have actually gone wrong here: a file that
// only MENTIONS the tag in prose, and a constraint that is not in the leading
// comment block.
func TestScanner_FindsTagsAndNothingElse(t *testing.T) {
	root := t.TempDir()

	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("tagged/A.runar.go", "//go:build ignore\n\npackage contract\n")
	write("tagged-with-reason/B.runar.go",
		"//go:build ignore\n\n// EXCLUDED FROM THE GO BUILD — because.\n\npackage contract\n")
	write("plain/C.runar.go", "package contract\n")
	// Mentions the tag in prose only. A whole-file grep calls this excluded;
	// it is not, and several real files in this tree have exactly this shape.
	write("prose/D.runar.go",
		"package contract\n\n// This used to carry //go:build ignore and no longer does.\n")
	// A constraint that is not in the leading comment block is not a build
	// constraint at all -- Go ignores it, and so must the scan.
	write("late/E.runar.go", "package contract\n\n//go:build ignore\n")
	// A different constraint is not an exclusion.
	write("othertag/F.runar.go", "//go:build linux\n\npackage contract\n")
	// Not a .runar.go file.
	write("tagged/helper.go", "//go:build ignore\n\npackage contract\n")

	got := scanExclusions(t, root)
	want := []string{"tagged-with-reason/B.runar.go", "tagged/A.runar.go"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scanner is wrong on a tree whose answer is known:\ngot  %v\nwant %v", got, want)
	}
}

// TestUnexcludedPortsWereFixedNotDeleted keeps "the set shrank" honest.
//
// Every assertion above is satisfied by DELETING a port instead of fixing it.
// Each port below was un-excluded by a real fix, and each is checked for the
// construct that used to block it -- so a future cleanup that removes the
// contract, or quietly reverts the fix, fails here instead of looking like
// progress.
func TestUnexcludedPortsWereFixedNotDeleted(t *testing.T) {
	root := examplesRoot(t)

	for _, c := range []struct {
		rel      string
		contains []string
		why      string
	}{
		{
			rel:      "countdown-loop/CountdownLoop.runar.go",
			contains: []string{"for i := runar.Int(5); i > 1; i--"},
			why: "countdown-loop is the descending-loop fixture. A body-dropping " +
				"or silently-ascending lowering is a defect this repo has " +
				"shipped, and the native test pins the same sum (14) the " +
				"compiled script is spent against in conformance.",
		},
		{
			rel:      "ec-primitives/ECPrimitives.runar.go",
			contains: []string{"runar.EcPointX", "runar.EcOnCurve"},
			why: "ec-primitives is where un-excluding independently rediscovered " +
				"the recorded EcPointX/EcPointY int64 truncation. Losing the " +
				"port loses that demonstration.",
		},
		{
			rel:      "state-ripemd160/HashRegistry.runar.go",
			contains: []string{"runar.Ripemd160Hash"},
			why: "state-ripemd160 was excluded because `runar.Ripemd160` is the " +
				"hash FUNCTION and no tier's .runar.go type table mapped " +
				"`Ripemd160Hash`, the name packages/runar-go actually declares " +
				"for the digest TYPE -- while all seven mapped its SHA-256 peer " +
				"`Sha256Digest`. Reverting the field to the bare `runar.Ripemd160` " +
				"spelling stops the file compiling as Go, which is half of what " +
				"a .runar.go port is for.",
		},
		{
			rel: "byte-builtins/ByteBuiltins.runar.go",
			contains: []string{
				"runar.Ripemd160Hash",
				"runar.Sha256Digest",
				"runar.Ripemd160(preimage)",
				"runar.Sha256Hash(preimage)",
			},
			why: "byte-builtins is the fixture that needs BOTH halves of the " +
				"Sha256/Ripemd160 name collision in one file: the digest TYPES " +
				"in the property annotations and the hash FUNCTIONS in call " +
				"position. That is only expressible now that Ripemd160Hash is " +
				"mapped, and it is the only .runar.go port that carries all " +
				"four spellings at once -- the pairing is the demonstration, so " +
				"losing any one of them loses it. The mock's own coverage of " +
				"the two calls lives elsewhere (packages/runar-go/runar_test.go " +
				"and mock_script_agreement_test.go); what is unique here is " +
				"that a CONTRACT uses them.",
		},
	} {
		t.Run(c.rel, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(c.rel))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s is gone: %v\n%s", c.rel, err, c.why)
			}
			if hasIgnoreTag(t, path) {
				t.Fatalf("%s is excluded from the Go build again.\n%s", c.rel, c.why)
			}
			// Match against CODE only. Every one of these anchors also
			// appears in the file's own prose, and a check against the raw
			// bytes is satisfied by the comment alone -- so reverting the fix
			// while leaving the comment describing it would pass. That is the
			// "comment asserting a checkable fact" shape, one level down.
			code := stripLineComments(string(raw))
			for _, want := range c.contains {
				if !strings.Contains(code, want) {
					t.Fatalf("%s no longer contains %q in CODE (it may still be "+
						"mentioned in a comment).\n%s", c.rel, want, c.why)
				}
			}
		})
	}
}

// stripLineComments removes `//` comments so a source check cannot be satisfied
// by prose that merely quotes the code it is looking for. Crude on purpose: it
// does not need to understand strings, because every anchor it guards is a Go
// composite literal or call, never text inside a string literal.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
