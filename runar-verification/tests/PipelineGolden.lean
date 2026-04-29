import RunarVerification.Pipeline
import RunarVerification.ANF.Json
open RunarVerification ANF Pipeline

/--
Phase 3 baseline: 25 fixtures that compile byte-exact through the verified
Lean pipeline. Any of these fixtures regressing (i.e. dropping out of
byte-exact match) MUST fail CI. New fixtures becoming byte-exact bumps the
count past the threshold but does not fail.

If the count grows, ratchet `expectedByteExact` upward (and add the new names
to `baselineMatches`) so we lock in progress.
-/
def expectedByteExact : Nat := 25

def baselineMatches : List String := [
  "add-raw-output",
  "auction",
  "bitwise-ops",
  "cross-covenant",
  "stateful-bytestring",
  "state-ripemd160",
  "bounded-loop",
  "oracle-price",
  "property-initializers",
  "shift-ops",
  "multi-method",
  "covenant-vault",
  "stateful",
  "go-dsl-bytestring-literal",
  "add-data-output",
  "token-nft",
  "basic-p2pkh",
  "function-patterns",
  "if-without-else",
  "stateful-counter",
  "token-ft",
  "arithmetic",
  "escrow",
  "boolean-logic",
  "if-else"
]

def main : IO Unit := do
  let dir := "/Users/siggioskarsson/gitcheckout/runar/conformance/tests"
  let entries ← System.FilePath.readDir dir
  let mut total := 0
  let mut matched := 0
  let mut matchedNames : List String := []
  for e in entries do
    let path := e.path
    let ir := path / "expected-ir.json"
    let hex := path / "expected-script.hex"
    if (← System.FilePath.pathExists ir) && (← System.FilePath.pathExists hex) then
      try
        let irJson ← IO.FS.readFile ir.toString
        let expected := (← IO.FS.readFile hex.toString).trim
        match ANFProgram.fromString irJson with
        | .ok p =>
            total := total + 1
            let actual := compileHex p
            if expected == actual then
              matched := matched + 1
              matchedNames := e.fileName :: matchedNames
        | _ => pure ()
      catch _ => pure ()
  IO.println s!"PIPELINE GOLDEN: {matched}/{total} byte-exact"

  -- Gate 1: total byte-exact count must not regress below the Phase 3 baseline.
  if matched < expectedByteExact then
    IO.eprintln s!"FAIL: byte-exact match regressed: {matched} < {expectedByteExact}"
    IO.Process.exit 1

  -- Gate 2: every fixture from the Phase 3 baseline must still match. This
  -- guards against a swap (e.g. a new fixture becomes byte-exact while one
  -- of the original 25 silently breaks, leaving the count unchanged).
  let mut regressions : List String := []
  for name in baselineMatches do
    if !(matchedNames.contains name) then
      regressions := name :: regressions
  if !regressions.isEmpty then
    IO.eprintln "FAIL: previously byte-exact fixtures regressed:"
    for n in regressions.reverse do
      IO.eprintln s!"  - {n}"
    IO.Process.exit 1

  IO.println s!"OK: {expectedByteExact} baseline fixtures still byte-exact"
