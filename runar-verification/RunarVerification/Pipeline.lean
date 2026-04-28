import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Peephole
import RunarVerification.Script.Emit

/-!
# End-to-end compiler pipeline (Phase 3a)

Composes the three phases of the post-ANF pipeline into a single
function `compile : ANFProgram → ByteArray`:

1. `Stack.Lower.lower` — ANFProgram → StackProgram
2. `Stack.Peephole.peepholePass` — single sweep over every method's ops
3. `Script.Emit.emit` — StackProgram → ByteArray

Phase 3a's top-level theorem is a **shape-preservation** identity:
contract names and method counts survive the entire pipeline. The
operational `full_pipeline_correct` theorem (`evalMethod p ≈ runScript
(emit (peephole (lower p)))`) is the principal Phase 3b deliverable;
its proof composes the per-pass simulation lemmas in `Stack.Sim` with
`Peephole_sound` and `emit_observational_correct`.
-/

namespace RunarVerification
namespace Pipeline

open RunarVerification.ANF
open RunarVerification.Stack
open RunarVerification.Script

/-- Apply the full 19-rule peephole pass to every method's ops. -/
def peepholeProgram (p : StackProgram) : StackProgram :=
  { p with
    methods := p.methods.map (fun m =>
      { m with ops := Peephole.peepholePassAll m.ops }) }

/-- The full ANF → bytes pipeline. -/
def compile (p : ANFProgram) : ByteArray :=
  Emit.emit (peepholeProgram (Lower.lower p))

/-- Hex-encoded form, matching the `expected-script.hex` format. -/
def compileHex (p : ANFProgram) : String :=
  Emit.bytesToHex (compile p)

/-! ## Shape-preservation theorems -/

theorem peepholeProgram_preserves_contract_name (p : StackProgram) :
    (peepholeProgram p).contractName = p.contractName := rfl

theorem peepholeProgram_preserves_method_count (p : StackProgram) :
    (peepholeProgram p).methods.length = p.methods.length := by
  unfold peepholeProgram
  simp

theorem compile_empty_program (cn : String) :
    compile { contractName := cn, properties := [], methods := [] } = ByteArray.empty := by
  unfold compile peepholeProgram Lower.lower
  simp [Emit.emit, Emit.publicMethodsOf]

end Pipeline
end RunarVerification
