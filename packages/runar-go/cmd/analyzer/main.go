// Command analyzer is the Go-tier CLI shim for the Rúnar Bitcoin
// Script static analyzer conformance suite.
//
// Usage: analyzer <hex-file>
//
// Reads the hex script from the file at argv[1], runs AnalyzeScript,
// and writes the canonical JSON report (per spec §3.5) to stdout.
package main

import (
	"fmt"
	"os"

	"github.com/icellan/runar/packages/runar-go/analyzer"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <hex-file>\n", os.Args[0])
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	report, err := analyzer.AnalyzeScript(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.WriteString(analyzer.MarshalReport(report))
}
