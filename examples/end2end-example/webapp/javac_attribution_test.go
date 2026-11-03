package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// F-190 (CL-BUG-256) — a second, javac-invalid PriceBet.runar.java is the
// copy the playground serves.
//
// readContractSource(sourceLangs["java"]) is the SAME call compilePriceBet
// (the /api/compile path) and handleTemplate (the /api/template path) both
// make: whatever bytes it resolves to are both fed through the Rúnar Go
// frontend's Java parser for the demo AND handed back verbatim to a browser
// that asks for the Java starter template. The Rúnar frontends accept a
// looser surface than real Java — the Go tier's Java parser recognises
// Bigint-wrapper method names and ALSO treats bare comparison operators on
// Bigint operands as the canonical binary op, with no notion of Java's own
// static type rules. A developer who copies this "Java" source into a real
// IDE, or who runs plain `javac` on it, gets a compile error: `>` is not
// defined for the boxed `Bigint` type, and `num2bin` has no overload that
// takes a primitive `int`.
//
// This test shells out to the REAL `javac` (with the built runar-java
// runtime jar on the classpath, so the `runar.lang.*` imports resolve) and
// checks that the exact source the playground serves for "java" is ordinary,
// valid Java — not merely Rúnar-frontend-valid.
//
// What it proves: the bytes readContractSource resolves for lang "java"
// compile cleanly under real javac attribution (parse AND type-check), given
// the runar-java runtime classes on the classpath.
// What it does NOT prove: that the compiled contract is semantically
// equivalent to examples/end2end-example/java's reference copy (that is
// R-277's job — tests/r277-webapp-contract-copy-in-sync.test.ts) or that any
// OTHER per-language template is valid under that language's own toolchain.

// findRunarJavaJar locates the built runar-java runtime jar. Per the
// dispatcher's R50 instruction, an unavailable jar or javac binary FAILS this
// test rather than skipping it — a silent skip would let this exact bug slip
// back in unnoticed.
func findRunarJavaJar(t *testing.T, repoRoot string) string {
	t.Helper()
	libs := filepath.Join(repoRoot, "packages", "runar-java", "build", "libs")
	matches, err := filepath.Glob(filepath.Join(libs, "runar-java-*.jar"))
	if err != nil {
		t.Fatalf("glob %s: %v", libs, err)
	}
	for _, m := range matches {
		base := filepath.Base(m)
		if strings.Contains(base, "sources") || strings.Contains(base, "javadoc") || strings.Contains(base, "compiler") {
			continue
		}
		return m
	}
	t.Fatalf("no runar-java runtime jar found under %s (run `cd packages/runar-java && ./gradlew jar` first) -- failing rather than skipping (R50)", libs)
	return ""
}

func TestJavaTemplate_ServedSourceCompilesUnderRealJavac(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Fatalf("javac not found on PATH -- failing rather than skipping (R50): %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	webappDir := filepath.Dir(thisFile)
	repoRoot := filepath.Join(webappDir, "..", "..", "..")

	jar := findRunarJavaJar(t, repoRoot)

	spec, ok := sourceLangs["java"]
	if !ok {
		t.Fatalf(`no "java" entry in sourceLangs`)
	}
	source, err := readContractSource(spec)
	if err != nil {
		t.Fatalf("readContractSource(java): %v", err)
	}

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "PriceBet.java")
	if err := os.WriteFile(srcFile, source, 0o644); err != nil {
		t.Fatalf("write temp source: %v", err)
	}
	outDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}

	cmd := exec.Command("javac", "-d", outDir, "-cp", jar, srcFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real javac rejected the Java source the playground serves for lang=java (F-190):\n%s", out)
	}
}
