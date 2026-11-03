package frontend

import "sort"

// F-017 — the identifier-collision rule.
//
// Five surfaces rename identifiers on the way into the AST: .runar.py,
// .runar.rb, .runar.rs, .runar.move (snake_case -> camelCase) and .runar.go
// (PascalCase -> camelCase). None of those mappings is injective: `tmp` and
// `tmp_`, `a_b` and `aB`, `_tmp` and `tmp` (.py/.rb), `Tmp` and `tmp` (.go)
// each land on one Rúnar name. Before this rule both spellings were bound to
// ONE variable, so `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` — always
// false in the source language — compiled to a self-comparison that always
// passes.
//
// While parsing one contract, the surface parser records (source spelling,
// Rúnar name) for every identifier it DECLARES: properties / struct fields,
// method names (not the constructor), parameters (not receivers), locals at
// every declaration or bare-name assignment target, and loop variables. If
// two recorded pairs share a Rúnar name but differ in spelling, the contract
// is refused with exactly one error whose text is identical in all seven
// tiers. Mirrors packages/runar-compiler/src/passes/snake-to-camel.ts
// `identifierCollisionMessage`.

// declaredIdents records the (source spelling, Rúnar name) pairs of one
// contract. The zero value is ready to use.
type declaredIdents struct {
	raws  []string
	names []string
}

// declare records one declared identifier and returns its Rúnar name.
func (d *declaredIdents) declare(raw, name string) string {
	d.raws = append(d.raws, raw)
	d.names = append(d.names, name)
	return name
}

// collisionDiagnostics returns the single F-017 error, or nil.
func (d *declaredIdents) collisionDiagnostics() []Diagnostic {
	msg := identifierCollisionMessage(d.raws, d.names)
	if msg == "" {
		return nil
	}
	return []Diagnostic{{Message: msg, Severity: SeverityError}}
}

// identifierCollisionMessage reports the collision with the smallest Rúnar
// name and, for it, the two smallest source spellings (byte order), so the
// report does not depend on declaration order. Empty string when none.
func identifierCollisionMessage(raws, names []string) string {
	spellings := map[string]map[string]bool{}
	for i, name := range names {
		if spellings[name] == nil {
			spellings[name] = map[string]bool{}
		}
		spellings[name][raws[i]] = true
	}
	best := ""
	var bestPair []string
	for name, set := range spellings {
		if len(set) < 2 {
			continue
		}
		if bestPair != nil && !(name < best) {
			continue
		}
		sorted := make([]string, 0, len(set))
		for raw := range set {
			sorted = append(sorted, raw)
		}
		sort.Strings(sorted)
		best, bestPair = name, sorted[:2]
	}
	if bestPair == nil {
		return ""
	}
	return "identifier collision: '" + bestPair[0] + "' and '" + bestPair[1] +
		"' both convert to '" + best + "'; rename one of them"
}
