import RunarVerification.ANF.Json
import RunarVerification.ANF.TypeCheck

/-!
# Task 9 — Type-system fidelity sweep

Loads every `conformance/tests/*/expected-ir.json` fixture with the ANF JSON
deserializer (the same `ANFProgram.fromString` path `tests/GoldenLoad.lean`
uses) and runs `programWellTypedBool` (the whole-program type checker in
`RunarVerification.ANF.TypeCheck`) on each.

For every fixture it prints one line:

```
<fixture>: <PASS|FAIL>
```

and, for a `FAIL`, the FIRST offending construct — the first binding whose
`typeOfValue` (or `if`/`loop` branch rule) returns `none`, reported as
`method <m> / binding <name> = <kind>[:<func>]`.

The offending-construct walker `firstFailure` re-threads the typing environment
exactly like `TypeCheck.checkBody` (contract properties + method params seed the
env; each well-typed binding extends it), so the construct it points at is the
*same* binding `checkBody` first rejects. It is a diagnostic only — it makes no
typing claim of its own and adds nothing to the verified `TypeCheck.lean`.

Run with `lake exe typecheckSweep`.
-/

open RunarVerification.ANF
open RunarVerification.ANF.TypeCheck
open RunarVerification.ANF.Typed (TypeEnv)

namespace RunarVerification.TypeCheckSweep

/-- Path to the conformance/tests directory, relative to the repo root.
Same anchor as `tests/GoldenLoad.lean`. -/
def conformanceTestsDir : System.FilePath :=
  ".." / "conformance" / "tests"

/-- Find all `expected-ir.json` files under `root` (copied from GoldenLoad). -/
def findGoldens (root : System.FilePath) : IO (Array System.FilePath) := do
  let mut acc : Array System.FilePath := #[]
  let mut pending : List System.FilePath := [root]
  while !pending.isEmpty do
    match pending with
    | [] => pure ()
    | dir :: rest =>
        pending := rest
        for entry in (← dir.readDir) do
          let path := entry.path
          if (← path.isDir) then
            pending := path :: pending
          else if entry.fileName == "expected-ir.json" then
            acc := acc.push path
  return acc

/-- A short, human-readable label for an `ANFValue` constructor. For a `.call`
the builtin/`super` `func` is appended (it is the discriminator that decides
whether a construct is a missing-builtin gap, a Go-only crypto builtin, or
something structural). -/
def valueKindName : ANFValue → String
  | .loadParam _          => "load_param"
  | .loadProp _           => "load_prop"
  | .loadConst _          => "load_const"
  | .binOp op _ _ _       => s!"bin_op:{op}"
  | .unaryOp op _ _       => s!"unary_op:{op}"
  | .call func _          => s!"call:{func}"
  | .methodCall _ m _     => s!"method_call:{m}"
  | .ifVal _ _ _ _          => "if"
  | .loop _ _ _ _ _ => "loop"
  | .assert _             => "assert"
  | .updateProp _ _       => "update_prop"
  | .getStateScript       => "get_state_script"
  | .checkPreimage _      => "check_preimage"
  | .deserializeState _   => "deserialize_state"
  | .addOutput _ _ _      => "add_output"
  | .addRawOutput _ _     => "add_raw_output"
  | .addDataOutput _ _    => "add_data_output"
  | .arrayLiteral _       => "array_literal"
  | .rawScript _ _ _      => "raw_script"

/-- The first binding (by `checkBody` order) whose value fails to type-check,
together with a kind label. Re-threads `Γ` exactly as `TypeCheck.checkBody`
does, so the reported binding is precisely the one `checkBody` first rejects.

Returns `(bindingName, kindLabel)`; `none` if the whole list type-checks.

`ifVal` / `loop` mirror `checkBody`'s branch rules: if the construct itself is
ill-formed (bad condition, branch mismatch, ill-typed body) we descend to find
the deepest concrete offender; if a branch/body is internally well-typed but
the *join* fails we report the `if`/`loop` binding itself. -/
partial def firstFailure (retEnv : List (String × ANFType)) (Γ : TypeEnv) :
    List ANFBinding → Option (String × String)
  | [] => none
  | .mk name v _ :: rest =>
    match v with
    | .ifVal cond thenBranch elseBranch _ =>
        -- Condition must be `.bool`.
        if Γ.lookup cond != some .bool then
          some (name, s!"if (condition `{cond}` not bool)")
        else
          -- A failing branch: surface the deepest concrete offender.
          match firstFailure retEnv Γ thenBranch with
          | some f => some f
          | none =>
          match firstFailure retEnv Γ elseBranch with
          | some f => some f
          | none =>
            -- Both branches type-check internally; replicate the (relaxed)
            -- if-as-statement join: no branch-type agreement required, bind the
            -- if-name to THEN's last type (then ELSE, then `.bool`).
            match checkBody retEnv Γ thenBranch, checkBody retEnv Γ elseBranch with
            | some envT, some envE =>
                let τThen := match thenBranch.getLast? with
                  | some b => envT.lookup b.name
                  | none   => none
                let τElse := match elseBranch.getLast? with
                  | some b => envE.lookup b.name
                  | none   => none
                let τIf := τThen.orElse (fun _ => τElse) |>.getD .bool
                firstFailure retEnv (Γ.extend name τIf) rest
            | _, _ => some (name, "if (branch failed to check)")
    | .loop _count body iterVar _ _ =>
        match firstFailure retEnv (Γ.extend iterVar .bigint) body with
        | some f => some f
        | none =>
          match checkBody retEnv (Γ.extend iterVar .bigint) body with
          | some _ => firstFailure retEnv (Γ.extend name .bool) rest
          | none   => some (name, "loop (body failed to check)")
    | other =>
        match typeOfValue retEnv Γ other with
        | some τ => firstFailure retEnv (Γ.extend name τ) rest
        | none   => some (name, valueKindName other)

/-- The first offending `(method, binding, kind)` across a whole program, found
by replaying `programWellTypedBool`'s per-method discipline (seed env from
properties + params, then `firstFailure`). `none` ⇒ the program type-checks. -/
def firstProgramFailure (p : ANFProgram) : Option (String × String × String) :=
  let retEnv := programReturnEnv p
  let rec go : List ANFMethod → Option (String × String × String)
    | [] => none
    | m :: ms =>
      match firstFailure retEnv (TypeEnv.ofParamsProps p.properties m.params) m.body with
      | some (bname, kind) => some (m.name, bname, kind)
      | none => go ms
  go p.methods

end RunarVerification.TypeCheckSweep

open RunarVerification.TypeCheckSweep

def main : IO UInt32 := do
  let goldenDir ← IO.FS.realPath conformanceTestsDir
  let files ← findGoldens goldenDir
  let sorted := files.qsort (fun a b => a.toString < b.toString)
  IO.println s!"type-check fidelity sweep over {sorted.size} fixtures\n"
  let mut pass := 0
  let mut fail := 0
  let mut parseFail := 0
  for f in sorted do
    -- Fixture name = the directory containing expected-ir.json.
    let fixture := (f.parent.map (·.fileName)).getD (some f.toString) |>.getD f.toString
    let src ← IO.FS.readFile f
    match ANFProgram.fromString src with
    | .error e =>
        parseFail := parseFail + 1
        IO.println s!"{fixture}: PARSE-FAIL ({e})"
    | .ok p =>
        if programWellTypedBool p then
          pass := pass + 1
          IO.println s!"{fixture}: PASS"
        else
          fail := fail + 1
          match firstProgramFailure p with
          | some (m, bname, kind) =>
              IO.println s!"{fixture}: FAIL  [method {m} / binding {bname} = {kind}]"
          | none =>
              -- programWellTypedBool=false but no single binding pinned: the
              -- failure is in a method-result / retEnv interaction.
              IO.println s!"{fixture}: FAIL  [no single offending binding — retEnv/method-result interaction]"
  IO.println s!"\nsummary: {pass} PASS, {fail} FAIL, {parseFail} PARSE-FAIL  (total {sorted.size})"
  return 0
