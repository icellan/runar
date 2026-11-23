package compiler

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// PqPubKeyParam is one entry of the artifact's `pqPubKeyParams` (PQ-F1): the
// constructor param at Index in abi.constructor.params, named Name, is passed
// directly as the public key of the Scheme verifier builtin, which needs
// exactly Length bytes. Field order is part of the cross-tier wire format.
type PqPubKeyParam struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Length int    `json:"length"`
}

// pqPubKeyBytes is the public-key length each post-quantum verifier's compiled
// script splits its pk operand into: WOTS+ pubSeed(32)||pkRoot(32), SLH-DSA
// PK.seed(n)||PK.root(n) with n = 16 / 24 / 32.
var pqPubKeyBytes = map[string]int{
	"verifyWOTS":             64,
	"verifySLHDSA_SHA2_128s": 32,
	"verifySLHDSA_SHA2_128f": 32,
	"verifySLHDSA_SHA2_192s": 48,
	"verifySLHDSA_SHA2_192f": 48,
	"verifySLHDSA_SHA2_256s": 64,
	"verifySLHDSA_SHA2_256f": 64,
}

// pqPubKeyParams computes `pqPubKeyParams` from the final ANF, exactly as the
// TS reference (packages/runar-ir-schema/src/pq-pubkey.ts) does: every method,
// nested if / loop bodies, `@ref:` aliases, pk = the verifier call's third
// arg; kept to properties that are constructor params, deduplicated on
// (name, scheme), sorted by (index, scheme). Not seen: a key passed to a
// private helper as an argument, or supplied at spend time.
func pqPubKeyParams(program *ir.ANFProgram, ctorParamNames []string) []PqPubKeyParam {
	ctorIdx := make(map[string]int, len(ctorParamNames))
	for i, n := range ctorParamNames {
		if _, dup := ctorIdx[n]; !dup {
			ctorIdx[n] = i
		}
	}
	var out []PqPubKeyParam
	seen := map[string]bool{}
	for _, m := range program.Methods {
		propOf := map[string]string{}
		var walk func(bindings []ir.ANFBinding)
		walk = func(bindings []ir.ANFBinding) {
			for _, b := range bindings {
				v := b.Value
				switch v.Kind {
				case "load_prop":
					propOf[b.Name] = v.Name
				case "load_const":
					if s, ok := anfConstString(v); ok && strings.HasPrefix(s, "@ref:") {
						if target, ok := propOf[strings.TrimPrefix(s, "@ref:")]; ok {
							propOf[b.Name] = target
						}
					}
				case "call":
					if want, isPQ := pqPubKeyBytes[v.Func]; isPQ && len(v.Args) > 2 {
						if prop, ok := propOf[v.Args[2]]; ok {
							key := prop + "\x00" + v.Func
							if idx, isCtor := ctorIdx[prop]; isCtor && !seen[key] {
								seen[key] = true
								out = append(out, PqPubKeyParam{Index: idx, Name: prop, Scheme: v.Func, Length: want})
							}
						}
					}
				}
				walk(v.Then)
				walk(v.Else)
				walk(v.Body)
			}
		}
		walk(m.Body)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Index != out[j].Index {
			return out[i].Index < out[j].Index
		}
		return out[i].Scheme < out[j].Scheme
	})
	return out
}

// anfConstString returns a load_const's string value, decoded or raw.
func anfConstString(v ir.ANFValue) (string, bool) {
	if v.ConstString != nil {
		return *v.ConstString, true
	}
	if len(v.RawValue) > 0 && v.RawValue[0] == '"' {
		var s string
		if json.Unmarshal(v.RawValue, &s) == nil {
			return s, true
		}
	}
	return "", false
}
