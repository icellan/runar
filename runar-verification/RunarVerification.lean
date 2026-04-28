import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Json
import RunarVerification.ANF.WF
import RunarVerification.ANF.Typed
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Peephole
import RunarVerification.Script.Syntax
import RunarVerification.Script.Eval
import RunarVerification.Script.Emit
import RunarVerification.Script.EmitCorrect
import RunarVerification.Pipeline

/-!
# RunarVerification

Public surface of the `runar-verification` package. Re-exports every
ANF, Stack, Script, and Pipeline module so consumers can `import
RunarVerification` and get the full surface: syntax, well-formedness,
typing, evaluation, lowering, peephole, emission, and end-to-end
pipeline.
-/
