package ir

import (
	"fmt"
	"strings"
)

// N-205 (b): F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s rule
// for writes to a key property, re-asserted on --ir input. Port of
// packages/runar-compiler/src/ir/rabin-key-provenance.ts (see its header for
// the full rule); --ir skips the frontend, so without this a load_param
// modulus (n = 1, sig = 0 forges anything) or a load_param written into the
// mutable key property compiled.
//
// A ref is trusted when EVERY binding of that name in the method (flattened
// pre-order: a binding, then its then, else, body) is: load_prop; an integer
// load_const; load_const "@ref:<x>" with <x> trusted; load_param of a private
// method whose every method_call site (at least one) passes a trusted ref in
// that position (least fixed point); or an `if` with no results, both arms
// non-empty and each arm's last binding trusted. KEY properties are the
// load_prop names a verifyRabinSig 4th argument can come from, closed under
// trusted writes into a key property. Writes (non-constructor methods only)
// are update_prop and add_output.stateValues[i] -> i-th non-readonly property.
// Method by method, verifyRabinSig calls first, then writes; first wins.

const rabinPubKeyProvenanceMessage = "verifyRabinSig public key (4th argument) must be a contract property or a literal; " +
	"a spender-supplied Rabin modulus lets anyone forge a signature"

func rabinKeyWriteMessage(prop string) string {
	return "verifyRabinSig public key property '" + prop + "' may only be assigned a contract property or a literal " +
		"outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature"
}

func flattenRabin(bindings []ANFBinding, out *[]*ANFBinding) {
	for i := range bindings {
		b := &bindings[i]
		*out = append(*out, b)
		flattenRabin(b.Value.Then, out)
		flattenRabin(b.Value.Else, out)
		flattenRabin(b.Value.Body, out)
	}
}

type rabinCallSiteIR struct {
	args   []string
	method int
}

// AssertRabinKeyProvenance returns the first violation, or nil.
func AssertRabinKeyProvenance(program *ANFProgram) error {
	methods := program.Methods
	flat := make([][]*ANFBinding, len(methods))
	byName := make([]map[string][]*ANFValue, len(methods))
	for mi := range methods {
		flattenRabin(methods[mi].Body, &flat[mi])
		names := map[string][]*ANFValue{}
		for _, b := range flat[mi] {
			names[b.Name] = append(names[b.Name], &b.Value)
		}
		byName[mi] = names
	}

	isPrivate := func(mi int) bool { return !methods[mi].IsPublic && methods[mi].Name != "constructor" }
	privates := map[string]int{}
	var privateOrder []string
	for mi := range methods {
		if isPrivate(mi) {
			if _, seen := privates[methods[mi].Name]; !seen {
				privateOrder = append(privateOrder, methods[mi].Name)
			}
			privates[methods[mi].Name] = mi
		}
	}
	callSites := map[string][]rabinCallSiteIR{}
	for mi := range methods {
		for _, b := range flat[mi] {
			v := &b.Value
			if v.Kind == "method_call" {
				if _, ok := privates[v.Method]; ok {
					callSites[v.Method] = append(callSites[v.Method], rabinCallSiteIR{v.Args, mi})
				}
			}
		}
	}
	trustedParams := map[string]map[int]bool{}
	for name := range privates {
		trustedParams[name] = map[int]bool{}
	}
	paramIndex := func(mi int, name string) int {
		for i, p := range methods[mi].Params {
			if p.Name == name {
				return i
			}
		}
		return -1
	}
	refOf := func(v *ANFValue) (string, bool) {
		if v.Kind == "load_const" && v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
			return (*v.ConstString)[5:], true
		}
		return "", false
	}

	var isTrusted func(ref string, mi int, visiting map[string]bool) bool
	isTrusted = func(ref string, mi int, visiting map[string]bool) bool {
		values, ok := byName[mi][ref]
		if !ok || visiting[ref] {
			return false
		}
		visiting[ref] = true
		defer delete(visiting, ref)
		for _, v := range values {
			trusted := false
			switch v.Kind {
			case "load_prop":
				trusted = true
			case "load_const":
				if v.ConstBigInt != nil {
					trusted = true
				} else if r, ok := refOf(v); ok {
					trusted = isTrusted(r, mi, visiting)
				}
			case "load_param":
				if isPrivate(mi) {
					idx := paramIndex(mi, v.Name)
					trusted = idx >= 0 && trustedParams[methods[mi].Name][idx]
				}
			case "if":
				if len(v.Results) == 0 && len(v.Then) > 0 && len(v.Else) > 0 {
					trusted = isTrusted(v.Then[len(v.Then)-1].Name, mi, visiting) &&
						isTrusted(v.Else[len(v.Else)-1].Name, mi, visiting)
				}
			}
			if !trusted {
				return false
			}
		}
		return true
	}

	for changed := true; changed; {
		changed = false
		for _, name := range privateOrder {
			mi := privates[name]
			sites := callSites[name]
			if len(sites) == 0 {
				continue
			}
			for i := range methods[mi].Params {
				if trustedParams[name][i] {
					continue
				}
				all := true
				for _, s := range sites {
					if i >= len(s.args) || !isTrusted(s.args[i], s.method, map[string]bool{}) {
						all = false
						break
					}
				}
				if all {
					trustedParams[name][i] = true
					changed = true
				}
			}
		}
	}

	var sourcesOf func(ref string, mi int, out map[string]bool, visiting map[string]bool)
	sourcesOf = func(ref string, mi int, out map[string]bool, visiting map[string]bool) {
		key := methods[mi].Name + "\x00" + ref
		if visiting[key] {
			return
		}
		visiting[key] = true
		for _, v := range byName[mi][ref] {
			if v.Kind == "load_prop" {
				out[v.Name] = true
			} else if r, ok := refOf(v); ok {
				sourcesOf(r, mi, out, visiting)
			} else if v.Kind == "if" {
				for _, arm := range [][]ANFBinding{v.Then, v.Else} {
					if len(arm) > 0 {
						sourcesOf(arm[len(arm)-1].Name, mi, out, visiting)
					}
				}
			} else if v.Kind == "load_param" && isPrivate(mi) {
				idx := paramIndex(mi, v.Name)
				for _, s := range callSites[methods[mi].Name] {
					if idx >= 0 && idx < len(s.args) {
						sourcesOf(s.args[idx], s.method, out, visiting)
					}
				}
			}
		}
	}

	keyProps := map[string]bool{}
	for mi := range methods {
		for _, b := range flat[mi] {
			v := &b.Value
			if v.Kind == "call" && v.Func == "verifyRabinSig" && len(v.Args) >= 4 {
				sourcesOf(v.Args[3], mi, keyProps, map[string]bool{})
			}
		}
	}

	var mutableProps []string
	mutable := map[string]bool{}
	for _, p := range program.Properties {
		if !p.Readonly {
			mutableProps = append(mutableProps, p.Name)
			mutable[p.Name] = true
		}
	}
	type write struct {
		prop, value string
		method      int
	}
	var writes []write
	for mi := range methods {
		if methods[mi].Name == "constructor" {
			continue
		}
		for _, b := range flat[mi] {
			v := &b.Value
			if v.Kind == "update_prop" {
				writes = append(writes, write{v.Name, v.ValueRef, mi})
			}
			if v.Kind == "add_output" {
				for i, sv := range v.StateValues {
					if i < len(mutableProps) {
						writes = append(writes, write{mutableProps[i], sv, mi})
					}
				}
			}
		}
	}

	for grew := true; grew; {
		before := len(keyProps)
		for _, w := range writes {
			if keyProps[w.prop] && isTrusted(w.value, w.method, map[string]bool{}) {
				sourcesOf(w.value, w.method, keyProps, map[string]bool{})
			}
		}
		grew = len(keyProps) != before
	}

	for mi := range methods {
		for _, b := range flat[mi] {
			v := &b.Value
			if v.Kind == "call" && v.Func == "verifyRabinSig" && len(v.Args) >= 4 &&
				!isTrusted(v.Args[3], mi, map[string]bool{}) {
				return fmt.Errorf("IR validation: method '%s': %s", methods[mi].Name, rabinPubKeyProvenanceMessage)
			}
		}
		for _, w := range writes {
			if w.method != mi || !keyProps[w.prop] || !mutable[w.prop] {
				continue
			}
			if !isTrusted(w.value, mi, map[string]bool{}) {
				return fmt.Errorf("IR validation: method '%s': %s", methods[mi].Name, rabinKeyWriteMessage(w.prop))
			}
		}
	}
	return nil
}
