import RunarVerification.ANF.Json
import RunarVerification.Script.Parse
import RunarVerification.Stack.Eval
import RunarVerification.Stack.TxContext

/-!
# Tier 4.6 — Differential testing harness

For each of the 49 conformance fixtures:

1. Read `expected-script.hex`.
2. Decode hex → `ByteArray`.
3. Run `parseScript` (Tier 2.3) to recover the `List StackOp` operand
   sequence emitted by the TS reference compiler.
4. Build a placeholder `TxContext` (Tier 4.3) that supplies the
   syntactic preimage every `OP_CHECKSIG` lowering expects.
5. Evaluate `runOps` (Stack VM) starting from a freshly-constructed
   `StackState` with the BIP-143 preimage installed.
6. Record `(success, stackTopHex, errorTag)` per fixture.

Output is written to the path in `RUNAR_DIFFERENTIAL_OUT`, or to
`/tmp/runar-verification-differential-results.json` by default, with
the schema:

```
{ "fixtures": [
    {"name": "<fixture>",
     "success": true|false,
     "finalStackTop": "<hex>" | null,
     "error": "<tag>" | null}
  ]
}
```

The Lean side is the **baseline** of the differential: the actual
cross-verifier diff happens in `scripts/differential.sh` which runs an
external Bitcoin Script reference (svnode-cli / libbitcoin / python-
bitcoinlib) against the same fixtures and fails on any mismatch with
this file's recorded outcome.

## TCB impact

* +0 axioms / +0 opaques (this exe is a test harness, not a new claim).
* The Tier 4.3 `TxContext` `_buildPreimage` companion axioms remain
  the only sighash-related axioms; the placeholder context just
  exercises them with concrete values.

Run via `lake build && lake env ./.lake/build/bin/differential`.
-/

open RunarVerification.ANF (parseHex?)
open RunarVerification.ANF.Eval (Value EvalError)
open RunarVerification.Script.Parse (parseScript ParseError)
open RunarVerification.Stack (StackOp TxContext)
open RunarVerification.Stack.Eval (StackState runOps)

namespace RunarVerification.Differential

def expectedFixtureTotal : Nat := 49

/-! ## Hex helpers -/

/-- Render one `UInt8` as two lowercase hex chars. -/
private def byteToHex (b : UInt8) : String :=
  let n := b.toNat
  let hi := n / 16
  let lo := n % 16
  let digit (k : Nat) : Char :=
    if k < 10 then Char.ofNat ('0'.toNat + k)
    else Char.ofNat ('a'.toNat + (k - 10))
  String.ofList [digit hi, digit lo]

/-- Render a `ByteArray` as a lowercase hex string (no `0x` prefix). -/
def renderBytes (b : ByteArray) : String := Id.run do
  let mut s := ""
  for byte in b.toList do
    s := s ++ byteToHex byte
  return s

/-! ## Result encoding -/

/-- Per-fixture differential record. -/
structure FixtureResult where
  name          : String
  success       : Bool
  finalStackTop : Option String
  error         : Option String
  deriving Inhabited

/-- Render one `Value` as a hex-encoded stack-top witness.

The Bitcoin Script convention used in `python-bitcoinlib` and
`svnode-cli` is that the final stack top is reported as raw
script-number bytes for booleans / integers and as raw bytes for
byte-strings. We mirror that convention here so the differential diff
is meaningful across implementations.
-/
def stackTopHex (v : Value) : String :=
  match v with
  | .vBigint i =>
      if i = 0 then ""
      else Id.run do
        let neg := i < 0
        let mut n := i.natAbs
        let mut acc : List UInt8 := []
        while n > 0 do
          acc := (UInt8.ofNat (n &&& 0xff)) :: acc
          n := n / 256
        let bytes := acc.reverse
        -- Place sign bit on the high byte; if it would clash with the
        -- magnitude, prepend an extra byte (Bitcoin script-number rule).
        let last := bytes.getLast!
        let body := bytes.dropLast
        let final :=
          if last &&& 0x80 ≠ 0 then
            let sign : UInt8 := if neg then 0x80 else 0x00
            body ++ [last, sign]
          else if neg then
            body ++ [last ||| 0x80]
          else
            bytes
        let mut s := ""
        for b in final do s := s ++ byteToHex b
        return s
  | .vBool true  => "01"
  | .vBool false => ""
  | .vBytes b    => renderBytes b
  | .vOpaque b   => renderBytes b
  | .vThis       => "<this>"

/-- Render an `EvalError` as a short tag + message for the JSON report.
External references (python-bitcoinlib, svnode-cli) report errors via
exception names like `EvalScriptError`, `MissingOpArgumentsError`,
etc. We use stable tags so the diff is comparable. -/
def errorTag : EvalError → String
  | .unboundName n     => s!"unboundName:{n}"
  | .unboundProperty n => s!"unboundProperty:{n}"
  | .typeError msg     => s!"typeError:{msg}"
  | .assertFailed      => "assertFailed"
  | .unsupported msg   => s!"unsupported:{msg}"
  | .divByZero         => "divByZero"

/-! ## Placeholder TxContext

A constant context used for every fixture. The values satisfy
syntactic constraints (32-byte hashes, 36-byte outpoint, 4-byte
sighash type) without claiming to be a consensus-valid spending
transaction. The differential harness records `success` based on
whether the script reaches a non-empty stack with a truthy top OR
fails with a specific error category — the placeholder context
exercises the same surface in Lean and the external reference. -/

private def zeroBytes (n : Nat) : ByteArray :=
  ByteArray.mk (Array.replicate n 0)

def placeholderCtx : TxContext where
  version      := 2
  hashPrevouts := zeroBytes 32
  hashSequence := zeroBytes 32
  outpoint     := zeroBytes 36
  inputIndex   := 0
  scriptCode   := ByteArray.empty
  amount       := 100000
  sequence     := 0xffffffff
  hashOutputs  := zeroBytes 32
  locktime     := 0
  sigHashType  := 0x41

/-- Initial state: empty stack, BIP-143 preimage installed via
`buildPreimage placeholderCtx`. -/
def initialState : StackState :=
  { (default : StackState) with preimage := TxContext.buildPreimage placeholderCtx }

/-! ## Per-fixture runner

The Rúnar `expected-script.hex` artifact is the **locking script** —
it consumes unlock arguments that real spending transactions push
onto the stack first. Running it against an empty stack reliably
fails with `OP_DUP empty stack` / `OP_OVER < 2 elements` /
`stack underflow` etc.; these are deterministic, repeatable
outcomes that an external Bitcoin Script reference reaches via the
exact same opcode trace.

Differential value: even though most fixtures fail, every fixture
fails with a *specific* error category that the external reference
must reproduce byte-for-byte. A divergence (e.g., Lean reports
`OP_DUP empty stack` but svnode-cli reports `OP_HASH160 empty stack`)
indicates an opcode-table mismatch, a parser disagreement on what
opcode each byte decodes to, or a semantic bug in stack pops.

The few fixtures that DO leave a witness on the stack (e.g. those
whose locking script begins with a constant push or a `0` arm)
provide additional differential coverage for the success path. -/

/-- Render a `ParseError` as a stable tag string. -/
def parseErrorTag : ParseError → String
  | .unexpectedEnd     => "parseError:unexpectedEnd"
  | .unknownOpcode b   => s!"parseError:unknownOpcode:0x{byteToHex b}"
  | .shortPushdata d a => s!"parseError:shortPushdata:{d}:{a}"
  | .unmatchedIf       => "parseError:unmatchedIf"
  | .outOfFuel         => "parseError:outOfFuel"

/-- Run one fixture: parse `expected-script.hex` and evaluate via
`runOps`. Returns the structured result. -/
def runFixture (name : String) (hexBody : String) : FixtureResult :=
  let trimmed := hexBody.trimAscii.toString
  match parseHex? trimmed with
  | none =>
      { name, success := false, finalStackTop := none,
        error := some "decodeError:not-hex" }
  | some bs =>
      match parseScript bs with
      | .error e =>
          { name, success := false, finalStackTop := none,
            error := some (parseErrorTag e) }
      | .ok ops =>
          match runOps ops initialState with
          | .error e =>
              { name, success := false, finalStackTop := none,
                error := some (errorTag e) }
          | .ok finalState =>
              match finalState.stack with
              | []       =>
                  { name, success := false, finalStackTop := none,
                    error := some "evalError:emptyStack" }
              | top :: _ =>
                  { name, success := true,
                    finalStackTop := some (stackTopHex top),
                    error := none }

/-! ## JSON report writer -/

/-- Render an `Option String` field as a JSON literal. -/
private def optStr : Option String → String
  | none     => "null"
  | some s   =>
      -- Escape backslashes and double-quotes for JSON; the error tags we
      -- produce above never contain control characters or unicode, so
      -- a minimal escaper suffices here.
      let escaped := s.replace "\\" "\\\\" |>.replace "\"" "\\\""
      "\"" ++ escaped ++ "\""

private def renderResult (r : FixtureResult) : String :=
  let nameJ  := "\"" ++ r.name ++ "\""
  let succJ  := if r.success then "true" else "false"
  let topJ   := optStr r.finalStackTop
  let errJ   := optStr r.error
  "    {\"name\": " ++ nameJ ++
    ", \"success\": " ++ succJ ++
    ", \"finalStackTop\": " ++ topJ ++
    ", \"error\": " ++ errJ ++ "}"

def renderReport (rs : List FixtureResult) : String :=
  let sorted := rs.toArray.qsort (fun a b => a.name < b.name) |>.toList
  let body   := String.intercalate ",\n" (sorted.map renderResult)
  "{\n  \"fixtures\": [\n" ++ body ++ "\n  ]\n}\n"

end RunarVerification.Differential

/-! ## Entry point -/

open RunarVerification.Differential

def main : IO Unit := do
  -- Mirror tests/PipelineGolden.lean's fixture-discovery pattern.
  let dir := "../conformance/tests"
  let entries ← System.FilePath.readDir dir
  let mut results : List FixtureResult := []
  let mut total := 0
  let mut succ  := 0
  for e in entries do
    let path := e.path
    let hexPath := path / "expected-script.hex"
    if (← System.FilePath.pathExists hexPath) then
      total := total + 1
      let body ← IO.FS.readFile hexPath.toString
      let r := runFixture e.fileName body
      if r.success then succ := succ + 1
      results := r :: results
  if total != expectedFixtureTotal then
    IO.eprintln s!"DIFFERENTIAL FAIL: discovered {total} fixtures, expected {expectedFixtureTotal}"
    IO.Process.exit 1
  let report := renderReport results
  let outPath :=
    match (← IO.getEnv "RUNAR_DIFFERENTIAL_OUT") with
    | some p => p
    | none => "/tmp/runar-verification-differential-results.json"
  IO.FS.writeFile outPath report
  IO.println s!"DIFFERENTIAL: {succ}/{total} fixtures evaluated successfully"
  IO.println s!"  report written to {outPath}"
