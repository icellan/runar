import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Json
import RunarVerification.ANF.WF
import RunarVerification.ANF.Typed
import RunarVerification.ANF.Eval
import RunarVerification.Crypto.Secp256k1
import RunarVerification.Crypto.NistEC
import RunarVerification.Crypto.Spec
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.AgreesA3
import RunarVerification.Stack.AgreesA4
import RunarVerification.Stack.AgreesA5
import RunarVerification.Stack.AgreesA6
import RunarVerification.Stack.AgreesA7
import RunarVerification.Stack.AgreesA8
import RunarVerification.Stack.OutputTrace
import RunarVerification.Stack.Peephole
import RunarVerification.Stack.TxContext
import RunarVerification.Stack.NumEncoding
import RunarVerification.Stack.BabyBear
import RunarVerification.Stack.Blake3
import RunarVerification.Stack.Merkle
import RunarVerification.Stack.Ec
import RunarVerification.Stack.HashOps
import RunarVerification.Stack.P256P384
import RunarVerification.Stack.Rabin
import RunarVerification.Stack.SlhDsa
import RunarVerification.Stack.Wots
import RunarVerification.Script.Syntax
import RunarVerification.Script.Eval
import RunarVerification.Script.Emit
import RunarVerification.Script.EmitCorrect
import RunarVerification.Script.Parse
import RunarVerification.Pipeline

/-!
# RunarVerification

Public surface of the `runar-verification` package. Re-exports every
ANF, Stack, Script, and Pipeline module so consumers can `import
RunarVerification` and get the full surface: syntax, well-formedness,
typing, evaluation, lowering, peephole, emission, and end-to-end
pipeline.
-/
