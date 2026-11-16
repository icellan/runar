package runar

import (
	"fmt"
	"os"
	"strings"

	"github.com/icellan/runar/compilers/go/compiler"
	"github.com/icellan/runar/compilers/go/frontend"
)

// CompileCheck runs the Rúnar frontend (parse → validate → typecheck) on a
// .runar.go contract file. Returns nil if the contract is valid Rúnar.
//
// Use this in tests alongside business logic tests to ensure the contract
// will compile to Bitcoin Script:
//
//	func TestCompile(t *testing.T) {
//	    if err := runar.CompileCheck("MyContract.runar.go"); err != nil {
//	        t.Fatalf("Rúnar compile check failed: %v", err)
//	    }
//	}
//
// CompileCheck has no vk.json, so a method calling
// AssertGroth16WitnessAssistedWithMSM whose statement is bound only by the
// vk.json's pinnedPublicInputs is refused here; use CompileCheckWithGroth16VK
// for such a contract.
func CompileCheck(contractFile string) error {
	return compileCheck(contractFile, frontend.TypeCheckOptions{})
}

// CompileCheckWithGroth16VK is CompileCheck for a contract that will be
// compiled with a SP1-format Groth16 vk.json (CompileOptions.Groth16WAVKey /
// --groth16-wa-vk). The typecheck sees the vk.json's pinnedPublicInputs, so a
// method calling AssertGroth16WitnessAssistedWithMSM whose statement is bound
// only by those pins passes, exactly as it does in the compiler. A vk.json
// that pins nothing binds nothing: such a method is still refused unless its
// body binds the statement.
func CompileCheckWithGroth16VK(contractFile, vkPath string) error {
	opts, err := compiler.TypeCheckOptionsFor(compiler.CompileOptions{Groth16WAVKey: vkPath})
	if err != nil {
		return err
	}
	return compileCheck(contractFile, opts)
}

func compileCheck(contractFile string, opts frontend.TypeCheckOptions) error {
	source, err := os.ReadFile(contractFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", contractFile, err)
	}

	result := frontend.ParseSource(source, contractFile)
	if len(result.Errors) > 0 {
		return fmt.Errorf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		return fmt.Errorf("no contract found in %s", contractFile)
	}

	v := frontend.Validate(result.Contract)
	if len(v.Errors) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(v.ErrorStrings(), "; "))
	}

	tc := frontend.TypeCheckWithOptions(result.Contract, opts)
	if len(tc.Errors) > 0 {
		return fmt.Errorf("type check errors: %s", strings.Join(tc.ErrorStrings(), "; "))
	}

	return nil
}
