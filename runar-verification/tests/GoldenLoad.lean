import RunarVerification

/-!
# Golden file load test

Walks `conformance/tests/*/expected-ir.json` and parses every file with
the ANF JSON deserializer. Fails fast on the first parse error.

Run with `lake exe goldenLoad`.
-/

open RunarVerification.ANF

/-- Path to the conformance/tests directory, relative to the repo root. -/
def conformanceTestsDir : System.FilePath :=
  ".." / "conformance" / "tests"

/-- Find all `expected-ir.json` files under `conformanceTestsDir`. -/
partial def findGoldens (root : System.FilePath) : IO (Array System.FilePath) := do
  let mut acc : Array System.FilePath := #[]
  for entry in (← root.readDir) do
    let path := entry.path
    if (← path.isDir) then
      acc := acc ++ (← findGoldens path)
    else if entry.fileName == "expected-ir.json" then
      acc := acc.push path
  return acc

def main : IO UInt32 := do
  let goldenDir ← IO.FS.realPath conformanceTestsDir
  IO.println s!"loading goldens from: {goldenDir}"
  let files ← findGoldens goldenDir
  IO.println s!"found {files.size} expected-ir.json files"
  let mut failures : Nat := 0
  let mut wfFailures : Nat := 0
  for f in files do
    let src ← IO.FS.readFile f
    match ANFProgram.fromString src with
    | .ok p =>
        if WF.programIsWF p then
          pure ()
        else
          IO.eprintln s!"  WF FAIL: {f.toString} (contract {p.contractName})"
          wfFailures := wfFailures + 1
    | .error e =>
        IO.eprintln s!"  PARSE FAIL: {f.toString}\n    {e}"
        failures := failures + 1
  if failures > 0 || wfFailures > 0 then
    IO.eprintln s!"\n{failures} parse failures, {wfFailures} WF failures"
    return 1
  IO.println s!"\nall {files.size} goldens parsed and satisfy WF"
  return 0
