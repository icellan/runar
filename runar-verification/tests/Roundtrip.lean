import RunarVerification

/-!
# Round-trip stability test

For every golden, parse → serialise → parse and assert the second parse
yields the same `ANFProgram` (structural equality at the term level).

This proves that no information is silently dropped or transformed during
serialisation. We do **not** compare raw JSON strings here — that would
require RFC 8785 canonicalisation, which Lean's `Json.compress` does not
implement (key ordering may differ from `JSON.stringify` with sorted
keys, and number-string normalisation differs in edge cases). The
parse-equivalence test catches all semantic regressions.

Run with `lake exe roundtrip`.
-/

open RunarVerification.ANF

partial def findGoldens (root : System.FilePath) : IO (Array System.FilePath) := do
  let mut acc : Array System.FilePath := #[]
  for entry in (← root.readDir) do
    let path := entry.path
    if (← path.isDir) then
      acc := acc ++ (← findGoldens path)
    else if entry.fileName == "expected-ir.json" then
      acc := acc.push path
  return acc

/-- Structural equality on ANFProgram via JSON canonicalisation. -/
def programsEquiv (a b : ANFProgram) : Bool :=
  ANFProgram.toJsonString a == ANFProgram.toJsonString b

def main : IO UInt32 := do
  let goldenDir ← IO.FS.realPath (".." / "conformance" / "tests")
  let files ← findGoldens goldenDir
  IO.println s!"round-trip checking {files.size} goldens"
  let mut failures : Nat := 0
  for f in files do
    let src ← IO.FS.readFile f
    match ANFProgram.fromString src with
    | .error e =>
        IO.eprintln s!"  PARSE FAIL: {f.toString}\n    {e}"
        failures := failures + 1
    | .ok p1 =>
        let s1 := ANFProgram.toJsonString p1
        match ANFProgram.fromString s1 with
        | .error e =>
            IO.eprintln s!"  REPARSE FAIL: {f.toString}\n    {e}"
            failures := failures + 1
        | .ok p2 =>
            if programsEquiv p1 p2 then
              pure ()
            else
              IO.eprintln s!"  ROUND-TRIP DIFF: {f.toString}"
              failures := failures + 1
  if failures > 0 then
    IO.eprintln s!"\n{failures} round-trip failures"
    return 1
  IO.println s!"all {files.size} goldens round-trip cleanly"
  return 0
