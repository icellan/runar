import RunarVerification.Pipeline
import RunarVerification.ANF.Json
open RunarVerification ANF Pipeline

def main : IO Unit := do
  let dir := "/Users/siggioskarsson/gitcheckout/runar/conformance/tests"
  let entries ← System.FilePath.readDir dir
  let mut total := 0
  let mut matched := 0
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
            if expected == actual then matched := matched + 1
        | _ => pure ()
      catch _ => pure ()
  IO.println s!"PIPELINE GOLDEN: {matched}/{total} byte-exact"
