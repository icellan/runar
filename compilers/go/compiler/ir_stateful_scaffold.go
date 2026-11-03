package compiler

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// N-101: --ir input skips the frontend, so a program labelled (or, per N-087,
// inferred) StatefulSmartContract could omit or fake the scaffolding ANF
// lowering injects into every public method and compile to an anyone-can-spend
// script: F-107's attack body compiled to 76767b8777. For each public method
// this re-derives what the frontend would inject (the TypeScript reference is
// packages/runar-compiler/src/passes/stateful-scaffold.ts):
//
//	prologue      assert(checkPreimage(txPreimage)), the sighash-type assert
//	              and, when the contract has mutable properties,
//	              deserialize_state
//	user code     free
//	continuation  when the method mutates state or declares outputs: the
//	              _newAmount floor (single-output form), the change output and
//	              the hashOutputs comparison over every output in order
//
// and refuses the program, with the diagnostics all seven tiers share
// (conformance/negatives/ir-stateful-scaffold-cases.json), when (1) the
// auto-injected parameters, (2) the prologue or (3) the continuation differ,
// or (4) a scaffolding binding, or an output the continuation commits to, is
// bound more than once or shares a property or parameter name.

type scaffoldEmitter struct {
	taken map[string]bool
	next  *int
	out   []ir.ANFBinding
}

func (e *scaffoldEmitter) emit(v ir.ANFValue) string {
	var name string
	for {
		name = fmt.Sprintf("$scaffold%d", *e.next)
		*e.next++
		if !e.taken[name] {
			break
		}
	}
	e.out = append(e.out, ir.ANFBinding{Name: name, Value: v})
	return name
}

func (e *scaffoldEmitter) sub() *scaffoldEmitter {
	return &scaffoldEmitter{taken: e.taken, next: e.next}
}

func scaffoldConstInt(n int64) ir.ANFValue {
	i := n
	return ir.ANFValue{Kind: "load_const", ConstBigInt: big.NewInt(n), ConstInt: &i}
}

func scaffoldConstString(s string) ir.ANFValue {
	str := s
	return ir.ANFValue{Kind: "load_const", ConstString: &str}
}

func scaffoldCall(fn string, args ...string) ir.ANFValue {
	return ir.ANFValue{Kind: "call", Func: fn, Args: args}
}

func scaffoldPrologue(e *scaffoldEmitter, sighashMode int, hasMutableState bool) {
	pre := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
	check := ir.ANFValue{Kind: "check_preimage", Preimage: pre}
	if sighashMode != frontend.SighashDefault {
		check.SighashFlag = sighashMode
	}
	e.emit(ir.ANFValue{Kind: "assert", ValueRef: e.emit(check)})
	p2 := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
	typ := e.emit(scaffoldCall("extractSigHashType", p2))
	want := e.emit(scaffoldConstInt(int64(sighashMode)))
	e.emit(ir.ANFValue{Kind: "assert", ValueRef: e.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: typ, Right: want})})
	if hasMutableState {
		p3 := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
		e.emit(ir.ANFValue{Kind: "deserialize_state", Preimage: p3})
	}
}

func scaffoldContinuation(e *scaffoldEmitter, needsChange, includesChange bool, stateRefs, dataRefs []string) {
	if !needsChange {
		return
	}
	if len(stateRefs) == 0 {
		p := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
		in := e.emit(scaffoldCall("extractAmount", p))
		na := e.emit(ir.ANFValue{Kind: "load_param", Name: "_newAmount"})
		e.emit(ir.ANFValue{Kind: "assert", ValueRef: e.emit(ir.ANFValue{Kind: "bin_op", Op: ">=", Left: na, Right: in})})
	}
	// N-038: no change segment under a SIGHASH_SINGLE base.
	change := ""
	if includesChange {
		pkh := e.emit(ir.ANFValue{Kind: "load_param", Name: "_changePKH"})
		amt := e.emit(ir.ANFValue{Kind: "load_param", Name: "_changeAmount"})
		zero := e.emit(scaffoldConstInt(0))
		nonZero := e.emit(ir.ANFValue{Kind: "bin_op", Op: "!==", Left: amt, Right: zero})
		thenE := e.sub()
		thenE.emit(scaffoldCall("buildChangeOutput", pkh, amt))
		elseE := e.sub()
		elseE.emit(scaffoldConstString(""))
		change = e.emit(ir.ANFValue{Kind: "if", Cond: nonZero, Then: thenE.out, Else: elseE.out})
	}

	var acc string
	if len(stateRefs) > 0 {
		acc = stateRefs[0]
		for _, r := range stateRefs[1:] {
			acc = e.emit(scaffoldCall("cat", acc, r))
		}
	} else {
		script := e.emit(ir.ANFValue{Kind: "get_state_script"})
		p := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
		na := e.emit(ir.ANFValue{Kind: "load_param", Name: "_newAmount"})
		acc = e.emit(scaffoldCall("computeStateOutput", p, script, na))
	}
	for _, r := range dataRefs {
		acc = e.emit(scaffoldCall("cat", acc, r))
	}
	if change != "" {
		acc = e.emit(scaffoldCall("cat", acc, change))
	}
	hash := e.emit(scaffoldCall("hash256", acc))
	p := e.emit(ir.ANFValue{Kind: "load_param", Name: "txPreimage"})
	outHash := e.emit(scaffoldCall("extractOutputHash", p))
	eq := e.emit(ir.ANFValue{Kind: "bin_op", Op: "===", Left: hash, Right: outHash, ResultType: "bytes"})
	e.emit(ir.ANFValue{Kind: "assert", ValueRef: eq, IsAutoInjectedStateCheck: true})
}

func scaffoldNested(v *ir.ANFValue) [][]ir.ANFBinding {
	return [][]ir.ANFBinding{v.Then, v.Else, v.Body}
}

func scaffoldContains(bindings []ir.ANFBinding, kinds map[string]bool) bool {
	for i := range bindings {
		if kinds[bindings[i].Value.Kind] {
			return true
		}
		for _, n := range scaffoldNested(&bindings[i].Value) {
			if scaffoldContains(n, kinds) {
				return true
			}
		}
	}
	return false
}

var scaffoldStateOutputKinds = map[string]bool{"add_output": true, "add_raw_output": true}
var scaffoldDataOutputKinds = map[string]bool{"add_data_output": true}

// The frontend's side-effect summary, read off the IR (update_prop is a state
// mutation, add_output / add_raw_output a state output, add_data_output a data
// output) at any depth and through method_calls to private methods.
func scaffoldShape(program *ir.ANFProgram, m *ir.ANFMethod) (needsChange, includesChange, needsNewAmount bool) {
	privates := map[string]*ir.ANFMethod{}
	for i := range program.Methods {
		if !program.Methods[i].IsPublic && program.Methods[i].Name != "constructor" {
			privates[program.Methods[i].Name] = &program.Methods[i]
		}
	}
	mutates, stateOut, dataOut := false, false, false
	visited := map[string]bool{}
	var walk func([]ir.ANFBinding)
	walk = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			v := &bindings[i].Value
			switch {
			case v.Kind == "update_prop":
				mutates = true
			case scaffoldStateOutputKinds[v.Kind]:
				stateOut = true
			case v.Kind == "add_data_output":
				dataOut = true
			case v.Kind == "method_call":
				if t, ok := privates[v.Method]; ok && !visited[t.Name] {
					visited[t.Name] = true
					walk(t.Body)
				}
			}
			for _, n := range scaffoldNested(v) {
				walk(n)
			}
		}
	}
	walk(m.Body)
	needsChange = mutates || stateOut || dataOut
	sighashMode := frontend.SighashDefault
	if m.SigHashType != nil {
		sighashMode = *m.SigHashType
	}
	return needsChange, frontend.IncludesChangeOutput(needsChange, sighashMode), (mutates || dataOut) && !stateOut
}

func scaffoldDescribe(v *ir.ANFValue) string {
	switch v.Kind {
	case "load_param":
		return "load_param " + v.Name
	case "load_const":
		if v.ConstString != nil {
			b, _ := json.Marshal(*v.ConstString)
			return "load_const " + string(b)
		}
		return "load_const " + v.ConstBigInt.String()
	case "call":
		return "call " + v.Func
	case "bin_op":
		return "bin_op " + v.Op
	}
	return v.Kind
}

func scaffoldAssertRef(v *ir.ANFValue) string {
	if v.ValueRef != "" {
		return v.ValueRef
	}
	var s string
	if len(v.RawValue) > 0 && json.Unmarshal(v.RawValue, &s) == nil {
		return s
	}
	return ""
}

func scaffoldConstBig(v *ir.ANFValue) *big.Int {
	if v.ConstBigInt != nil {
		return v.ConstBigInt
	}
	if v.ConstInt != nil {
		return big.NewInt(*v.ConstInt)
	}
	return nil
}

type scaffoldMatcher struct {
	m      map[string]string
	mapped map[string]bool
}

func (s *scaffoldMatcher) ref(e, a string) bool {
	if want, ok := s.m[e]; ok {
		return want == a
	}
	return e == a
}

func sighashOrDefault(f int) int {
	if f == 0 {
		return frontend.SighashDefault
	}
	return f
}

func (s *scaffoldMatcher) binding(exp, act *ir.ANFBinding) bool {
	e, a := &exp.Value, &act.Value
	if e.Kind != a.Kind {
		return false
	}
	ok := false
	switch e.Kind {
	case "load_param":
		ok = e.Name == a.Name
	case "load_const":
		if e.ConstString != nil {
			ok = a.ConstString != nil && *a.ConstString == *e.ConstString && a.ConstBool == nil
		} else {
			ab := scaffoldConstBig(a)
			ok = a.ConstString == nil && a.ConstBool == nil && ab != nil && ab.Cmp(e.ConstBigInt) == 0
		}
	case "check_preimage":
		ok = s.ref(e.Preimage, a.Preimage) && sighashOrDefault(e.SighashFlag) == sighashOrDefault(a.SighashFlag)
	case "assert":
		ok = s.ref(e.ValueRef, scaffoldAssertRef(a))
	case "call":
		ok = e.Func == a.Func && len(e.Args) == len(a.Args)
		for i := 0; ok && i < len(e.Args); i++ {
			ok = s.ref(e.Args[i], a.Args[i])
		}
	case "bin_op":
		ok = e.Op == a.Op && s.ref(e.Left, a.Left) && s.ref(e.Right, a.Right) && e.ResultType == a.ResultType
	case "deserialize_state":
		ok = s.ref(e.Preimage, a.Preimage)
	case "get_state_script":
		ok = true
	case "if":
		ok = s.ref(e.Cond, a.Cond) && len(a.Results) == 0 &&
			s.sequence(e.Then, a.Then) == -1 && s.sequence(e.Else, a.Else) == -1
	}
	if !ok || s.mapped[act.Name] {
		return false
	}
	s.m[exp.Name] = act.Name
	s.mapped[act.Name] = true
	return true
}

// sequence returns the index of the first binding that differs (a missing one
// included), or -1.
func (s *scaffoldMatcher) sequence(exp, act []ir.ANFBinding) int {
	for i := range exp {
		if i >= len(act) || !s.binding(&exp[i], &act[i]) {
			return i
		}
	}
	if len(act) == len(exp) {
		return -1
	}
	return len(exp)
}

func scaffoldCollectNames(bindings []ir.ANFBinding, counts map[string]int) {
	for i := range bindings {
		counts[bindings[i].Name]++
		v := &bindings[i].Value
		for _, r := range v.Results {
			counts[r]++
		}
		if v.IterVar != "" {
			counts[v.IterVar]++
		}
		for _, n := range scaffoldNested(v) {
			scaffoldCollectNames(n, counts)
		}
	}
}

func scaffoldError(method, detail string) error {
	return fmt.Errorf("IR validation: stateful method '%s' does not carry the scaffolding StatefulSmartContract lowering injects: %s", method, detail)
}

func checkIRStatefulScaffolding(program *ir.ANFProgram) error {
	hasMutable := false
	props := map[string]bool{}
	for _, p := range program.Properties {
		props[p.Name] = true
		if !p.Readonly {
			hasMutable = true
		}
	}
	for mi := range program.Methods {
		m := &program.Methods[mi]
		if !m.IsPublic || m.Name == "constructor" {
			continue
		}
		needsChange, includesChange, needsNewAmount := scaffoldShape(program, m)

		// (1) the parameters, contiguous and once each.
		var required [][2]string
		if includesChange {
			required = append(required, [2]string{"_changePKH", "Ripemd160"}, [2]string{"_changeAmount", "bigint"})
		}
		if needsNewAmount {
			required = append(required, [2]string{"_newAmount", "bigint"})
		}
		required = append(required, [2]string{"txPreimage", "SigHashPreimage"})
		start := -1
		for i, p := range m.Params {
			if p.Name == required[0][0] {
				start = i
				break
			}
		}
		paramsOK := start >= 0
		for i, r := range required {
			if !paramsOK {
				break
			}
			if start+i >= len(m.Params) || m.Params[start+i].Name != r[0] || m.Params[start+i].Type != r[1] {
				paramsOK = false
			}
			n := 0
			for _, p := range m.Params {
				if p.Name == r[0] {
					n++
				}
			}
			paramsOK = paramsOK && n == 1
		}
		if !paramsOK {
			parts := make([]string, len(required))
			for i, r := range required {
				parts[i] = r[0] + ": " + r[1]
			}
			return fmt.Errorf("IR validation: stateful method '%s' must declare the auto-injected parameters (%s) contiguously and once each, as StatefulSmartContract lowering does", m.Name, strings.Join(parts, ", "))
		}

		counts := map[string]int{}
		scaffoldCollectNames(m.Body, counts)
		taken := map[string]bool{}
		for n := range counts {
			taken[n] = true
		}
		next := 0
		match := &scaffoldMatcher{m: map[string]string{}, mapped: map[string]bool{}}

		// (2) the prologue.
		sighashMode := frontend.SighashDefault
		if m.SigHashType != nil {
			sighashMode = *m.SigHashType
		}
		pro := &scaffoldEmitter{taken: taken, next: &next}
		scaffoldPrologue(pro, sighashMode, hasMutable)
		headLen := len(pro.out)
		if headLen > len(m.Body) {
			headLen = len(m.Body)
		}
		head := m.Body[:headLen]
		if i := match.sequence(pro.out, head); i != -1 {
			return scaffoldError(m.Name, fmt.Sprintf("prologue binding %d must be %s", i, scaffoldDescribe(&pro.out[i].Value)))
		}

		// (3) the continuation, over the outputs the method's own top-level
		// bindings declare (an `if` counts once, as a state output when either
		// arm holds one, else as a data output), in order.
		rest := m.Body[len(pro.out):]
		var stateOut, dataOut []*ir.ANFBinding
		for i := range rest {
			b := &rest[i]
			switch {
			case scaffoldStateOutputKinds[b.Value.Kind]:
				stateOut = append(stateOut, b)
			case b.Value.Kind == "add_data_output":
				dataOut = append(dataOut, b)
			case b.Value.Kind == "if":
				if scaffoldContains(b.Value.Then, scaffoldStateOutputKinds) || scaffoldContains(b.Value.Else, scaffoldStateOutputKinds) || scaffoldContains(b.Value.Body, scaffoldStateOutputKinds) {
					stateOut = append(stateOut, b)
				} else if scaffoldContains(b.Value.Then, scaffoldDataOutputKinds) || scaffoldContains(b.Value.Else, scaffoldDataOutputKinds) || scaffoldContains(b.Value.Body, scaffoldDataOutputKinds) {
					dataOut = append(dataOut, b)
				}
			}
		}
		names := func(bs []*ir.ANFBinding) []string {
			out := make([]string, len(bs))
			for i, b := range bs {
				out[i] = b.Name
			}
			return out
		}
		tail := &scaffoldEmitter{taken: taken, next: &next}
		scaffoldContinuation(tail, needsChange, includesChange, names(stateOut), names(dataOut))
		offset := len(rest) - len(tail.out)
		for i := range tail.out {
			if offset+i < 0 || !match.binding(&tail.out[i], &rest[offset+i]) {
				return scaffoldError(m.Name, fmt.Sprintf("continuation binding %d must be %s", i, scaffoldDescribe(&tail.out[i].Value)))
			}
		}

		// (4) unique, unshadowed names for what the scaffolding binds or
		// commits to. A binding's own arms may reuse its name (an
		// output-carrying `if` is named after its arm's last binding).
		params := map[string]bool{}
		for _, p := range m.Params {
			params[p.Name] = true
		}
		var checked []*ir.ANFBinding
		var preorder func([]ir.ANFBinding)
		preorder = func(bs []ir.ANFBinding) {
			for i := range bs {
				checked = append(checked, &bs[i])
				for _, n := range scaffoldNested(&bs[i].Value) {
					preorder(n)
				}
			}
		}
		preorder(head)
		if offset >= 0 {
			preorder(rest[offset:])
		}
		checked = append(checked, stateOut...)
		checked = append(checked, dataOut...)
		for _, b := range checked {
			inner := map[string]int{}
			for _, n := range scaffoldNested(&b.Value) {
				scaffoldCollectNames(n, inner)
			}
			if counts[b.Name]-inner[b.Name] != 1 || props[b.Name] || params[b.Name] {
				return fmt.Errorf("IR validation: stateful method '%s' must bind '%s' exactly once, under a name no property or parameter uses: the injected scaffolding binds it or the continuation commits to it", m.Name, b.Name)
			}
		}
	}
	return nil
}
