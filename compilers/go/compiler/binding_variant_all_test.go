package compiler

import (
	"strings"
	"testing"
)

// Compact `@bindingVariant all` blob from codegen/oppushtx.go (376 bytes).
// An in-tier compile-to-hex pin so `go test ./...` catches a Go-only drift
// without waiting for the TS R-105 matrix.
const checkPreimageBindingAllHex = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

func TestBindingVariantAll_EmitsCompactBlob(t *testing.T) {
	source := `
class StatefulBindingAll extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  /** @bindingVariant all */
  public bump() {
    const old = this.count++;
    assert(old >= 0n);
  }
}
`
	result := CompileFromSourceStrWithResult(source, "StatefulBindingAll.runar.ts")
	if !result.Success {
		var msgs []string
		for _, d := range result.Diagnostics {
			msgs = append(msgs, d.FormatMessage())
		}
		t.Fatalf("compile failed: %s", strings.Join(msgs, "; "))
	}
	if result.Artifact == nil || result.Artifact.Script == "" {
		t.Fatal("expected a compiled script")
	}
	hex := result.Artifact.Script
	if len(checkPreimageBindingAllHex)/2 != 376 {
		t.Fatalf("pin is %d B, want 376", len(checkPreimageBindingAllHex)/2)
	}
	if !strings.Contains(hex, checkPreimageBindingAllHex) {
		t.Fatalf("script (%d B) does not contain the 376-byte all blob", len(hex)/2)
	}
	if strings.Contains(hex, "01007e818b") {
		t.Fatal("lowS BIN2NUM pad leaked into an @bindingVariant all compile")
	}
}
