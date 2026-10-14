package frontend

import (
	"fmt"

	"github.com/icellan/runar/compilers/go/ir"
)

// CollectEmbedAlwaysDCEWarnings emits a warning when DCE strips an un-annotated
// readonly field (issue #109, Option 4). Such a field carries no compile-time
// value (no initializer) and is referenced by no method, so it is eliminated
// from the locking script entirely — silently dropping deploy-time metadata an
// author may intend to recover from the on-chain script later. `@embedAlways`
// fields were forced back in during ANF lowering (a load_prop + @ref alias), so
// they are "referenced" here and never warn.
//
// Faithful port of the check in the TS reference compile() (index.ts): it reads
// the set of props with a surviving load_prop from the (post-lowering) ANF
// program, exactly as `collectReferencedProps(optimizedAnf)` does.
func CollectEmbedAlwaysDCEWarnings(contract *ContractNode, program *ir.ANFProgram) []Diagnostic {
	if contract == nil || program == nil {
		return nil
	}
	referenced := collectReferencedProps(program)

	var diags []Diagnostic
	for _, prop := range contract.Properties {
		if prop.Readonly && !prop.EmbedAlways && prop.Initializer == nil && !referenced[prop.Name] {
			loc := prop.SourceLocation
			diags = append(diags, Diagnostic{
				Message: fmt.Sprintf(
					"readonly field '%s' is not referenced in any method body and may "+
						"be eliminated by DCE; annotate it /** @embedAlways */ to preserve it in the "+
						"on-chain script", prop.Name),
				Severity: SeverityWarning,
				Loc:      &loc,
			})
		}
	}
	return diags
}

// collectReferencedProps returns the set of property names that have a surviving
// load_prop binding anywhere in a REAL method body (all methods except the
// constructor, recursing into nested if/loop blocks). Mirrors the TS
// collectReferencedProps: it runs a probe dead-binding elimination first (so a
// field read only into a never-used local does NOT count as referenced), and
// skips the constructor (whose super(...) references every property but is never
// emitted as script code).
//
// The probe runs on a shallow copy of the Methods slice: EliminateDeadBindings
// only reassigns each method's top-level Body header to a freshly-filtered
// slice, so the caller's program.ANF is left untouched.
func collectReferencedProps(program *ir.ANFProgram) map[string]bool {
	probe := make([]ir.ANFMethod, len(program.Methods))
	copy(probe, program.Methods)
	for i := range probe {
		EliminateDeadBindings(&probe[i])
	}

	refs := make(map[string]bool)
	for i := range probe {
		if probe[i].Name == "constructor" {
			continue
		}
		collectLoadPropsInBindings(probe[i].Body, refs)
	}
	return refs
}

func collectLoadPropsInBindings(bindings []ir.ANFBinding, refs map[string]bool) {
	for i := range bindings {
		v := &bindings[i].Value
		if v.Kind == "load_prop" {
			refs[v.Name] = true
		}
		// Recurse into nested control-flow bodies.
		if len(v.Then) > 0 {
			collectLoadPropsInBindings(v.Then, refs)
		}
		if len(v.Else) > 0 {
			collectLoadPropsInBindings(v.Else, refs)
		}
		if len(v.Body) > 0 {
			collectLoadPropsInBindings(v.Body, refs)
		}
	}
}
