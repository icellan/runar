package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the absolute path to the repo root, climbing two
// levels from this package's source directory (packages/runar-go/analyzer).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// packages/runar-go/analyzer → .../packages/runar-go → .../packages → .../<repo-root>
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

var conformanceFixtures = []string{
	"basic-p2pkh",
	"escrow",
	"stateful-counter",
	"auction",
	"covenant-vault",
	"ec-demo",
	"schnorr-zkp",
	"if-else",
}

func TestConformanceFixtures(t *testing.T) {
	root := repoRoot(t)
	for _, fixture := range conformanceFixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			hexPath := filepath.Join(root, "conformance", "tests", fixture, "expected-script.hex")
			goldenPath := filepath.Join(root, "conformance", "analyzer", fixture, "expected-analyzer-report.json")

			hexBytes, err := os.ReadFile(hexPath)
			if err != nil {
				t.Fatalf("read %s: %v", hexPath, err)
			}
			goldenBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read %s: %v", goldenPath, err)
			}

			report, err := AnalyzeScript(strings.TrimSpace(string(hexBytes)))
			if err != nil {
				t.Fatalf("AnalyzeScript: %v", err)
			}
			actual := MarshalReport(report)
			expected := string(goldenBytes)
			if actual != expected {
				// Find first divergent line for a useful message.
				aLines := strings.Split(actual, "\n")
				eLines := strings.Split(expected, "\n")
				n := len(aLines)
				if len(eLines) > n {
					n = len(eLines)
				}
				for i := 0; i < n; i++ {
					var a, e string
					if i < len(aLines) {
						a = aLines[i]
					}
					if i < len(eLines) {
						e = eLines[i]
					}
					if a != e {
						t.Fatalf("%s: golden mismatch at line %d\nexpected: %q\nactual:   %q",
							fixture, i+1, e, a)
					}
				}
				t.Fatalf("%s: length mismatch (actual=%d, expected=%d)",
					fixture, len(actual), len(expected))
			}
		})
	}
}
