package ir

// N-065 / N-060 — compiler-reserved names. Mirrors
// packages/runar-compiler/src/passes/reserved-names.ts exactly (same families,
// same sentence); see that file for which pass mints each family and why the
// alpha-rename (`@`), EC-optimizer and codegen-tracker names are not reserved.
//
//   ANF lowering           t<digits>, __merge$<digits>
//   fixed-array expansion  <name>__<digits>, __idx_<digits>, __val_<digits>
//   stack lowering         _codePart, __param_*, __shadowed_*, _pub_<digits>
//   auto-injected params   _changePKH, _changeAmount, _newAmount,
//                          _serialisedOutputs, _prevOutScript_<digits>, and
//                          txPreimage in a StatefulSmartContract

import (
	"fmt"
	"regexp"
	"strings"
)

// ReservedNameMessage is the diagnostic shared verbatim by all seven tiers.
func ReservedNameMessage(name string) string {
	return fmt.Sprintf("'%s' is reserved for compiler-generated names and cannot be used as an identifier", name)
}

var (
	reDigitsSuffix  = regexp.MustCompile(`^t[0-9]+$`)
	reMergeTemp     = regexp.MustCompile(`^__merge\$[0-9]+$`)
	rePubSlot       = regexp.MustCompile(`^_pub_[0-9]+$`)
	reArraySlot     = regexp.MustCompile(`^.+__[0-9]+$`)
	reIdxTemp       = regexp.MustCompile(`^__idx_[0-9]+$`)
	reValTemp       = regexp.MustCompile(`^__val_[0-9]+$`)
	rePrevOutScript = regexp.MustCompile(`^_prevOutScript_[0-9]+$`)
)

func isStackLoweringReserved(name string) bool {
	return name == "_codePart" ||
		strings.HasPrefix(name, "__param_") ||
		strings.HasPrefix(name, "__shadowed_") ||
		rePubSlot.MatchString(name)
}

func isANFBindingReserved(name string) bool {
	return reDigitsSuffix.MatchString(name) || reMergeTemp.MatchString(name)
}

func isSourceOnlyReserved(name string) bool {
	switch name {
	case "_changePKH", "_changeAmount", "_newAmount", "_serialisedOutputs":
		return true
	}
	return reArraySlot.MatchString(name) || reIdxTemp.MatchString(name) ||
		reValTemp.MatchString(name) || rePrevOutScript.MatchString(name)
}

// IsReservedSourceName reports whether a source program may not declare
// `name` (property, method, parameter, local or loop variable), after the
// surface's name mapping.
func IsReservedSourceName(name string, stateful bool) bool {
	return isStackLoweringReserved(name) || isANFBindingReserved(name) ||
		isSourceOnlyReserved(name) || (stateful && name == "txPreimage")
}

// IsReservedIRName is the --ir rule. `declaration` is true for a property,
// method, parameter or loop-variable name and for the name a load_param /
// load_prop / update_prop addresses; false for binding names and references.
func IsReservedIRName(name string, declaration bool) bool {
	return isStackLoweringReserved(name) || (declaration && isANFBindingReserved(name))
}

// assertNoReservedIRNames mirrors TS assertNoReservedIrNames (index.ts).
// Runs after DecodeConstants so @ref aliases and assert / update_prop value
// references are decoded.
func assertNoReservedIRNames(p *ANFProgram) error {
	check := func(name string, decl bool) error {
		if name != "" && IsReservedIRName(name, decl) {
			return fmt.Errorf("%s", ReservedNameMessage(name))
		}
		return nil
	}
	var walk func(bindings []ANFBinding) error
	walk = func(bindings []ANFBinding) error {
		for i := range bindings {
			b := &bindings[i]
			if err := check(b.Name, false); err != nil {
				return err
			}
			v := &b.Value
			var refs []string
			switch v.Kind {
			case "load_param", "load_prop":
				if err := check(v.Name, true); err != nil {
					return err
				}
			case "update_prop":
				if err := check(v.Name, true); err != nil {
					return err
				}
				refs = append(refs, v.ValueRef)
			case "load_const":
				if v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
					refs = append(refs, (*v.ConstString)[5:])
				}
			case "loop":
				if err := check(v.IterVar, true); err != nil {
					return err
				}
			default:
				refs = append(refs, v.Left, v.Right, v.Operand, v.Cond, v.Object, v.Preimage, v.Satoshis, v.ScriptBytes)
				if v.Kind == "assert" {
					refs = append(refs, v.ValueRef)
				}
				refs = append(refs, v.Args...)
				refs = append(refs, v.StateValues...)
				refs = append(refs, v.Elements...)
			}
			for _, r := range refs {
				if err := check(r, false); err != nil {
					return err
				}
			}
			for _, nested := range [][]ANFBinding{v.Body, v.Then, v.Else} {
				if err := walk(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, prop := range p.Properties {
		if err := check(prop.Name, true); err != nil {
			return err
		}
	}
	for _, m := range p.Methods {
		if err := check(m.Name, true); err != nil {
			return err
		}
		for _, param := range m.Params {
			if err := check(param.Name, true); err != nil {
				return err
			}
		}
		if err := walk(m.Body); err != nil {
			return err
		}
	}
	return nil
}
