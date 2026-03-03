// Compile PriceBet.runar.ts through the Go compiler and dump every
// intermediate representation:
//
//  1. Parsed AST (contract structure)
//  2. ANF IR (flattened let-bindings)
//  3. Stack IR (stack machine ops per method)
//  4. Bitcoin Script ASM (human-readable opcodes)
//  5. Bitcoin Script Hex (raw bytes)
//  6. Artifact JSON (deployment bundle)
//  7. Annotated walkthrough
//  8. Transaction structure
//  9. Opcode-by-opcode stack trace (cancel path)
//  10. Size comparison
//
// Run:  cd end2end-example/go && GOWORK=off go run ./cmd/dump-compiled
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

const sep = "══════════════════════════════════════════════════════════════════════════════"

func main() {
	source, err := os.ReadFile("PriceBet.runar.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read source: %v\n", err)
		os.Exit(1)
	}

	// ── Pass 1: Parse ───────────────────────────────────────────────────────
	parseResult := frontend.ParseSource(source, "PriceBet.runar.go")
	if len(parseResult.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Parse errors:\n  %s\n", strings.Join(parseResult.Errors, "\n  "))
		os.Exit(1)
	}
	contract := parseResult.Contract

	// ── Pass 2: Validate ────────────────────────────────────────────────────
	validResult := frontend.Validate(contract)
	if len(validResult.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Validation errors:\n  %s\n", strings.Join(validResult.Errors, "\n  "))
		os.Exit(1)
	}

	// ── Pass 3: Type-check ──────────────────────────────────────────────────
	tcResult := frontend.TypeCheck(contract)
	if len(tcResult.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "Type-check errors:\n  %s\n", strings.Join(tcResult.Errors, "\n  "))
		os.Exit(1)
	}

	// ── Pass 4: ANF lowering ────────────────────────────────────────────────
	program := frontend.LowerToANF(contract)

	// Bake constructor args so the hex output contains real pubkeys
	for i := range program.Properties {
		switch program.Properties[i].Name {
		case "alicePubKey":
			program.Properties[i].InitialValue = "02" + strings.Repeat("aa", 32)
		case "bobPubKey":
			program.Properties[i].InitialValue = "02" + strings.Repeat("bb", 32)
		case "oraclePubKey":
			program.Properties[i].InitialValue = float64(12345)
		case "strikePrice":
			program.Properties[i].InitialValue = float64(50000)
		}
	}

	// ── Pass 5: Stack lowering ──────────────────────────────────────────────
	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stack lowering error: %v\n", err)
		os.Exit(1)
	}

	// ── Pass 6: Emit ────────────────────────────────────────────────────────
	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Emit error: %v\n", err)
		os.Exit(1)
	}

	// ═════════════════════════════════════════════════════════════════════════
	//  1. PARSED AST
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  1. PARSED AST  (Pass 1: Source → Rúnar AST)  [Go compiler]")
	fmt.Println(sep)
	fmt.Printf("Contract:    %s\n", contract.Name)
	fmt.Printf("Base class:  %s\n", contract.ParentClass)
	props := make([]string, len(contract.Properties))
	for i, p := range contract.Properties {
		ro := ""
		if p.Readonly {
			ro = "readonly "
		}
		props[i] = fmt.Sprintf("%s%s: %s", ro, p.Name, typeStr(p.Type))
	}
	fmt.Printf("Properties:  %s\n", strings.Join(props, ", "))
	fmt.Println("Methods:")
	for _, m := range contract.Methods {
		params := make([]string, len(m.Params))
		for j, p := range m.Params {
			params[j] = fmt.Sprintf("%s: %s", p.Name, typeStr(p.Type))
		}
		fmt.Printf("  %s %s(%s)\n", m.Visibility, m.Name, strings.Join(params, ", "))
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  2. ANF IR
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  2. ANF IR  (Pass 4: AST → A-Normal Form)  [Go compiler]")
	fmt.Println(sep)
	fmt.Printf("Contract: %s\n", program.ContractName)
	propNames := make([]string, len(program.Properties))
	for i, p := range program.Properties {
		propNames[i] = p.Name
	}
	fmt.Printf("Properties: %s\n", strings.Join(propNames, ", "))
	for _, m := range program.Methods {
		vis := "private"
		if m.IsPublic {
			vis = "public"
		}
		paramNames := make([]string, len(m.Params))
		for j, p := range m.Params {
			paramNames[j] = p.Name
		}
		fmt.Printf("\n  method %s %s(%s):\n", vis, m.Name, strings.Join(paramNames, ", "))
		printBindings(m.Body, "    ")
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  3. STACK IR
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  3. STACK IR  (Pass 5: ANF → Stack Machine Ops)  [Go compiler]")
	fmt.Println(sep)
	for _, sm := range stackMethods {
		if sm.Name == "constructor" {
			continue
		}
		fmt.Printf("\n  method %s  (%d ops, max stack depth %d):\n", sm.Name, len(sm.Ops), sm.MaxStackDepth)
		printStackOps(sm.Ops, "    ")
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  4. BITCOIN SCRIPT ASM
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  4. BITCOIN SCRIPT ASM  (Pass 6: Stack IR → Opcodes)  [Go compiler]")
	fmt.Println(sep)
	asmParts := strings.Split(emitResult.ScriptAsm, " ")
	indent := 0
	for i, part := range asmParts {
		if part == "OP_ELSE" || part == "OP_ENDIF" {
			indent--
			if indent < 0 {
				indent = 0
			}
		}
		fmt.Printf("  %3d: %s%s\n", i+1, strings.Repeat("  ", indent), part)
		if part == "OP_IF" || part == "OP_ELSE" {
			indent++
		}
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  5. BITCOIN SCRIPT HEX
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  5. BITCOIN SCRIPT HEX  (raw locking script bytes)  [Go compiler]")
	fmt.Println(sep)
	scriptHex := emitResult.ScriptHex
	fmt.Printf("Length: %d bytes\n", len(scriptHex)/2)
	for i := 0; i < len(scriptHex); i += 64 {
		end := i + 64
		if end > len(scriptHex) {
			end = len(scriptHex)
		}
		fmt.Printf("  %04x: %s\n", i/2, scriptHex[i:end])
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  6. ARTIFACT JSON
	// ═════════════════════════════════════════════════════════════════════════
	fmt.Println(sep)
	fmt.Println("  6. ARTIFACT  (deployment JSON)  [Go compiler]")
	fmt.Println(sep)
	artifact := buildArtifact(program, emitResult)
	fmt.Printf("  version:       %s\n", artifact.Version)
	fmt.Printf("  compiler:      %s\n", artifact.CompilerVersion)
	fmt.Printf("  contract:      %s\n", artifact.ContractName)
	fmt.Printf("  script length: %d bytes\n", len(artifact.Script)/2)
	fmt.Println("  ABI:")
	ctorParams := make([]string, len(artifact.ABI.Constructor.Params))
	for i, p := range artifact.ABI.Constructor.Params {
		ctorParams[i] = fmt.Sprintf("%s: %s", p.Name, p.Type)
	}
	fmt.Printf("    constructor(%s)\n", strings.Join(ctorParams, ", "))
	for _, m := range artifact.ABI.Methods {
		vis := "private"
		if m.IsPublic {
			vis = "public"
		}
		mParams := make([]string, len(m.Params))
		for j, p := range m.Params {
			mParams[j] = fmt.Sprintf("%s: %s", p.Name, p.Type)
		}
		fmt.Printf("    %s %s(%s)\n", vis, m.Name, strings.Join(mParams, ", "))
	}
	fmt.Println()

	// ═════════════════════════════════════════════════════════════════════════
	//  7-10. NARRATIVE SECTIONS (same as TypeScript dump)
	// ═════════════════════════════════════════════════════════════════════════
	printNarrative(scriptHex)
}

func typeStr(t frontend.TypeNode) string {
	switch v := t.(type) {
	case frontend.PrimitiveType:
		return v.Name
	case frontend.CustomType:
		return v.Name
	default:
		return "?"
	}
}

func printBindings(bindings []ir.ANFBinding, indent string) {
	for _, b := range bindings {
		v := b.Value
		switch v.Kind {
		case "load_param":
			fmt.Printf("%slet %s = param(%s)\n", indent, b.Name, v.Name)
		case "load_prop":
			fmt.Printf("%slet %s = this.%s\n", indent, b.Name, v.Name)
		case "load_const":
			fmt.Printf("%slet %s = %v\n", indent, b.Name, fmtConst(v))
		case "bin_op":
			fmt.Printf("%slet %s = %s %s %s\n", indent, b.Name, v.Left, v.Op, v.Right)
		case "call":
			fmt.Printf("%slet %s = %s(%s)\n", indent, b.Name, v.Func, strings.Join(v.Args, ", "))
		case "assert":
			fmt.Printf("%sassert(%s)\n", indent, v.ValueRef)
		case "if":
			fmt.Printf("%sif (%s) {\n", indent, v.Cond)
			printBindings(v.Then, indent+"  ")
			if len(v.Else) > 0 {
				fmt.Printf("%s} else {\n", indent)
				printBindings(v.Else, indent+"  ")
			}
			fmt.Printf("%s}\n", indent)
		case "update_prop":
			fmt.Printf("%sthis.%s = %s\n", indent, v.Name, v.ValueRef)
		default:
			raw, _ := json.Marshal(v)
			s := string(raw)
			if len(s) > 80 {
				s = s[:80] + "..."
			}
			fmt.Printf("%slet %s = %s(%s)\n", indent, b.Name, v.Kind, s)
		}
	}
}

func fmtConst(v ir.ANFValue) string {
	if v.ConstBigInt != nil {
		return v.ConstBigInt.String()
	}
	if v.ConstInt != nil {
		return fmt.Sprintf("%d", *v.ConstInt)
	}
	if v.ConstString != nil {
		s := *v.ConstString
		if len(s) > 20 {
			s = s[:20] + "..."
		}
		return fmt.Sprintf("%q", s)
	}
	if v.ConstBool != nil {
		return fmt.Sprintf("%t", *v.ConstBool)
	}
	return "?"
}

func printStackOps(ops []codegen.StackOp, indent string) {
	for _, op := range ops {
		switch op.Op {
		case "push":
			fmt.Printf("%spush %s\n", indent, fmtPushValue(op.Value))
		case "opcode":
			fmt.Printf("%s%s\n", indent, op.Code)
		case "dup":
			fmt.Printf("%sOP_DUP\n", indent)
		case "swap":
			fmt.Printf("%sOP_SWAP\n", indent)
		case "drop":
			fmt.Printf("%sOP_DROP\n", indent)
		case "roll":
			fmt.Printf("%sOP_ROLL (depth %d)\n", indent, op.Depth)
		case "pick":
			fmt.Printf("%sOP_PICK (depth %d)\n", indent, op.Depth)
		case "nip":
			fmt.Printf("%sOP_NIP\n", indent)
		case "over":
			fmt.Printf("%sOP_OVER\n", indent)
		case "rot":
			fmt.Printf("%sOP_ROT\n", indent)
		case "tuck":
			fmt.Printf("%sOP_TUCK\n", indent)
		case "if":
			fmt.Printf("%sIF {\n", indent)
			printStackOps(op.Then, indent+"  ")
			if len(op.Else) > 0 {
				fmt.Printf("%s} ELSE {\n", indent)
				printStackOps(op.Else, indent+"  ")
			}
			fmt.Printf("%s}\n", indent)
		default:
			fmt.Printf("%s%s\n", indent, op.Op)
		}
	}
}

func fmtPushValue(v codegen.PushValue) string {
	switch v.Kind {
	case "bigint":
		return v.BigInt.String()
	case "bool":
		return fmt.Sprintf("%t", v.Bool)
	case "bytes":
		return fmt.Sprintf("<%s> (%d bytes)", hex.EncodeToString(v.Bytes), len(v.Bytes))
	default:
		return "?"
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type abiParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type abiConstructor struct {
	Params []abiParam `json:"params"`
}
type abiMethod struct {
	Name     string     `json:"name"`
	Params   []abiParam `json:"params"`
	IsPublic bool       `json:"isPublic"`
}
type abi struct {
	Constructor abiConstructor `json:"constructor"`
	Methods     []abiMethod    `json:"methods"`
}
type artifact struct {
	Version         string `json:"version"`
	CompilerVersion string `json:"compilerVersion"`
	ContractName    string `json:"contractName"`
	ABI             abi    `json:"abi"`
	Script          string `json:"script"`
	ASM             string `json:"asm"`
}

func buildArtifact(program *ir.ANFProgram, emit *codegen.EmitResult) *artifact {
	ctorParams := make([]abiParam, len(program.Properties))
	for i, p := range program.Properties {
		ctorParams[i] = abiParam{Name: p.Name, Type: p.Type}
	}
	methods := make([]abiMethod, 0)
	for _, m := range program.Methods {
		if m.Name == "constructor" {
			continue
		}
		params := make([]abiParam, len(m.Params))
		for j, p := range m.Params {
			params[j] = abiParam{Name: p.Name, Type: p.Type}
		}
		methods = append(methods, abiMethod{Name: m.Name, Params: params, IsPublic: m.IsPublic})
	}
	return &artifact{
		Version:         "runar-v0.1.0",
		CompilerVersion: "0.1.0-go",
		ContractName:    program.ContractName,
		ABI:             abi{Constructor: abiConstructor{Params: ctorParams}, Methods: methods},
		Script:          emit.ScriptHex,
		ASM:             emit.ScriptAsm,
	}
}

func printNarrative(scriptHex string) {
	fmt.Println(sep)
	fmt.Println("  7. ANNOTATED SCRIPT WALKTHROUGH  [Go compiler]")
	fmt.Println(sep)
	fmt.Printf(`
This is a STATELESS contract (extends SmartContract), so the entire
contract logic lives in a SINGLE locking script placed in a UTXO.

The contract has 2 public methods: settle() and cancel().
The compiler emits a METHOD DISPATCH preamble that checks a numeric
selector pushed by the spending transaction:

  selector = 0  →  settle()
  selector = 1  →  cancel()

CONSTRUCTOR ARGS ARE BAKED IN:
  alicePubKey  = 02aaaaaaaaaaaaaa...  (33-byte compressed pubkey)
  bobPubKey    = 02bbbbbbbbbbbbbb...  (33-byte compressed pubkey)
  oraclePubKey = 12345  (Rabin public key, integer)
  strikePrice  = 50000  (price threshold)

Inside settle(price, rabinSig, padding, aliceSig, bobSig):
  1. Computes msg = num2bin(price, 8)
  2. Calls verifyRabinSig(msg, rabinSig, padding, oraclePubKey) → OP_VERIFY
  3. Asserts price > 0
  4. OP_IF/OP_ELSE branch: if price > strikePrice
       → OP_CHECKSIGVERIFY with aliceSig + alicePubKey
     else
       → OP_CHECKSIGVERIFY with bobSig + bobPubKey

Inside cancel(aliceSig, bobSig):
  1. OP_CHECKSIGVERIFY with aliceSig + alicePubKey
  2. OP_CHECKSIG with bobSig + bobPubKey
`)

	fmt.Println(sep)
	fmt.Println("  8. BITCOIN TRANSACTIONS ON-CHAIN  [Go compiler]")
	fmt.Println(sep)
	fmt.Printf(`
┌─────────────────────────────────────────────────────────────────┐
│  TX 1: FUNDING (creates the bet UTXO)                          │
├─────────────────────────────────────────────────────────────────┤
│  Inputs:                                                        │
│    [0] Alice funds (1 BSV)                                      │
│    [1] Bob funds   (1 BSV)                                      │
│  Outputs:                                                       │
│    [0] PriceBet UTXO                                            │
│        satoshis:       200,000,000  (2 BSV combined)            │
│        locking script: <compiled PriceBet>  (%d bytes)          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  TX 2a: SETTLEMENT (oracle price, winner claims)                │
├─────────────────────────────────────────────────────────────────┤
│  scriptSig: <bobSig> <aliceSig> <padding> <rabinSig> <price> 0 │
│  → verifyRabinSig, price > 0, branch on price vs strike,       │
│    OP_CHECKSIG with winner's key                                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  TX 2b: CANCELLATION (mutual refund)                            │
├─────────────────────────────────────────────────────────────────┤
│  scriptSig: <bobSig> <aliceSig> 1                               │
│  → OP_CHECKSIGVERIFY(aliceSig, alicePK)                         │
│    OP_CHECKSIG(bobSig, bobPK)                                   │
└─────────────────────────────────────────────────────────────────┘
`, len(scriptHex)/2)

	fmt.Println(sep)
	fmt.Println("  9. OPCODE-BY-OPCODE STACK TRACE  (cancel path)  [Go compiler]")
	fmt.Println(sep)
	fmt.Print(`
scriptSig pushes: <bobSig> <aliceSig> <1>
Stack after scriptSig (top on right): [ bobSig, aliceSig, 1 ]

 Op#  Opcode                Stack (top → right)
 ───  ─────────────────────  ─────────────────────────────────────────────
  1   OP_DUP                [ bobSig, aliceSig, 1, 1 ]
  2   OP_0                  [ bobSig, aliceSig, 1, 1, 0 ]
  3   OP_NUMEQUAL           [ bobSig, aliceSig, 1, false ]
  4   OP_IF                 [ bobSig, aliceSig, 1 ]
                            false → jump to OP_ELSE (cancel branch)

       ── skips settle() body (ops 5-54) ──

 55   OP_ELSE               [ bobSig, aliceSig, 1 ]
 56   OP_DROP               [ bobSig, aliceSig ]
 57   OP_SWAP               [ aliceSig, bobSig ]
 58   push <alicePK>        [ aliceSig, bobSig, alicePK ]
 59   OP_CHECKSIGVERIFY     [ aliceSig ]
 60   push <bobPK>          [ aliceSig, bobPK ]
 61   OP_CHECKSIG           [ true ]
 62   OP_ENDIF              [ true ]

      Final stack: TRUE → script SUCCEEDS → TX is valid.
`)

	fmt.Println()
	fmt.Println(sep)
	fmt.Println("  10. SIZE COMPARISON  [Go compiler]")
	fmt.Println(sep)
	scriptLen := len(scriptHex) / 2
	fmt.Printf(`
  PriceBet locking script:  %d bytes

  For reference:
    Standard P2PKH script:    25 bytes
    2-of-3 multisig:          ~105 bytes
    PriceBet (this contract): %d bytes

  At BSV fee rates (~0.05 sat/byte), deployment costs ~%d satoshis.
`, scriptLen, scriptLen, (scriptLen*5+99)/100)
}
