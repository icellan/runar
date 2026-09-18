import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Typed

/-!
# ANF Builtin Signature Table

A list-based mirror of the `BUILTIN_FUNCTIONS` map in
`packages/runar-compiler/src/passes/03-typecheck.ts` (125 entries).

The list form is used instead of a match-expression so that downstream
tasks can iterate over the table (e.g. for fidelity checks in Task 9)
and the `builtinSig` function (a O(n) lookup) is easily derivable from
it via `List.find?`.

## Type-mapping conventions

The TS table uses string type-names; the mapping to `ANFType` is:

  'bigint'          → .bigint
  'boolean'         → .bool
  'ByteString'      → .byteString
  'Sha256'          → .sha256
  'Ripemd160'       → .ripemd160
  'PubKey'          → .pubKey
  'Sig'             → .sig
  'Addr'            → .addr
  'SigHashPreimage' → .sigHashPreimage
  'Point'           → .point
  'P256Point'       → .p256Point
  'P384Point'       → .p384Point
  'RabinPubKey'     → .rabinPubKey
  'RabinSig'        → .rabinSig

Two TS return types do not have `ANFType` constructors:

* `'void'` — used by `assert`, `exit`, `requireOutputP2PKH`. These
  builtins are never the source of a typed binding in the compiler's ANF
  (they are statement-level, not expression-level). We render `void`
  as `.bool` — the same convention used in `Typed.lean` — so the table
  remains total and downstream typing rules can assign a uniform type to
  these nodes when they do appear as bindings.
* `'Sig[]'` / `'PubKey[]'` — used only by `checkMultiSig`. These map to
  the recursive `ANFType.array` constructor (`.array .sig` / `.array
  .pubKey`); the entry is present (all 125 TS entries are represented).
  An `array_literal` ANF value is typed in `typeOfValue` to `.array τ`
  for homogeneous element type `τ`.
-/

namespace RunarVerification.ANF.TypeCheck

open RunarVerification.ANF (ANFType)

/-- Per-builtin (paramTypes, returnType). Row-for-row mirror of
`packages/runar-compiler/src/passes/03-typecheck.ts` `BUILTIN_FUNCTIONS`
(125 entries, all represented here — `checkMultiSig`'s `Sig[]` / `PubKey[]`
operands map to `ANFType.array`; see module-level note). -/
def builtinTable : List (String × (List ANFType × ANFType)) :=
  [ -- Hashes
    ("sha256",                  ([.byteString],                                                               .sha256)),
    ("ripemd160",               ([.byteString],                                                               .ripemd160)),
    ("hash160",                 ([.byteString],                                                               .ripemd160)),
    ("hash256",                 ([.byteString],                                                               .sha256)),
    -- Signature / preimage / multisig
    ("checkSig",                ([.sig, .pubKey],                                                             .bool)),
    ("checkMultiSig",           ([.array .sig, .array .pubKey],                                               .bool)),
    ("assert",                  ([.bool],                                                                     .bool)),
    -- Byte-string primitives
    ("len",                     ([.byteString],                                                               .bigint)),
    ("cat",                     ([.byteString, .byteString],                                                  .byteString)),
    ("substr",                  ([.byteString, .bigint, .bigint],                                             .byteString)),
    ("num2bin",                 ([.bigint, .bigint],                                                          .byteString)),
    ("bin2num",                 ([.byteString],                                                               .bigint)),
    ("checkPreimage",           ([.sigHashPreimage],                                                          .bool)),
    -- Rabin / WOTS+ / SLH-DSA verifiers
    ("verifyRabinSig",          ([.byteString, .rabinSig, .byteString, .rabinPubKey],                        .bool)),
    ("verifyWOTS",              ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_128s",  ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_128f",  ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_192s",  ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_192f",  ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_256s",  ([.byteString, .byteString, .byteString],                                     .bool)),
    ("verifySLHDSA_SHA2_256f",  ([.byteString, .byteString, .byteString],                                     .bool)),
    -- Partial-hash primitives
    ("sha256Compress",          ([.byteString, .byteString],                                                  .byteString)),
    ("sha256Finalize",          ([.byteString, .byteString, .bigint],                                         .byteString)),
    ("blake3Compress",          ([.byteString, .byteString],                                                  .byteString)),
    ("blake3Hash",              ([.byteString],                                                               .byteString)),
    -- Math
    ("abs",                     ([.bigint],                                                                   .bigint)),
    ("min",                     ([.bigint, .bigint],                                                          .bigint)),
    ("max",                     ([.bigint, .bigint],                                                          .bigint)),
    ("within",                  ([.bigint, .bigint, .bigint],                                                 .bool)),
    ("safediv",                 ([.bigint, .bigint],                                                          .bigint)),
    ("safemod",                 ([.bigint, .bigint],                                                          .bigint)),
    ("clamp",                   ([.bigint, .bigint, .bigint],                                                 .bigint)),
    ("sign",                    ([.bigint],                                                                   .bigint)),
    ("pow",                     ([.bigint, .bigint],                                                          .bigint)),
    ("mulDiv",                  ([.bigint, .bigint, .bigint],                                                 .bigint)),
    ("percentOf",               ([.bigint, .bigint],                                                          .bigint)),
    ("sqrt",                    ([.bigint],                                                                   .bigint)),
    ("gcd",                     ([.bigint, .bigint],                                                          .bigint)),
    ("divmod",                  ([.bigint, .bigint],                                                          .bigint)),
    ("log2",                    ([.bigint],                                                                   .bigint)),
    ("bool",                    ([.bigint],                                                                   .bool)),
    -- Byte-string slicing helpers
    ("split",                   ([.byteString, .bigint],                                                      .byteString)),
    ("reverseBytes",            ([.byteString],                                                               .byteString)),
    ("left",                    ([.byteString, .bigint],                                                      .byteString)),
    ("right",                   ([.byteString, .bigint],                                                      .byteString)),
    ("int2str",                 ([.bigint, .bigint],                                                          .byteString)),
    ("toByteString",            ([.byteString],                                                               .byteString)),
    ("exit",                    ([.bool],                                                                     .bool)),
    ("pack",                    ([.bigint],                                                                   .byteString)),
    ("unpack",                  ([.byteString],                                                               .bigint)),
    -- secp256k1 EC
    ("ecAdd",                   ([.point, .point],                                                            .point)),
    ("ecMul",                   ([.point, .bigint],                                                           .point)),
    ("ecMulGen",                ([.bigint],                                                                   .point)),
    ("ecNegate",                ([.point],                                                                    .point)),
    ("ecOnCurve",               ([.point],                                                                    .bool)),
    ("ecModReduce",             ([.bigint, .bigint],                                                          .bigint)),
    ("ecEncodeCompressed",      ([.point],                                                                    .byteString)),
    ("ecMakePoint",             ([.bigint, .bigint],                                                          .point)),
    ("ecPointX",                ([.point],                                                                    .bigint)),
    ("ecPointY",                ([.point],                                                                    .bigint)),
    -- NIST P-256
    ("p256Add",                 ([.p256Point, .p256Point],                                                    .p256Point)),
    ("p256Mul",                 ([.p256Point, .bigint],                                                       .p256Point)),
    ("p256MulGen",              ([.bigint],                                                                   .p256Point)),
    ("p256Negate",              ([.p256Point],                                                                .p256Point)),
    ("p256OnCurve",             ([.p256Point],                                                                .bool)),
    ("p256EncodeCompressed",    ([.p256Point],                                                                .byteString)),
    ("verifyECDSA_P256",        ([.byteString, .byteString, .byteString],                                     .bool)),
    -- NIST P-384
    ("p384Add",                 ([.p384Point, .p384Point],                                                    .p384Point)),
    ("p384Mul",                 ([.p384Point, .bigint],                                                       .p384Point)),
    ("p384MulGen",              ([.bigint],                                                                   .p384Point)),
    ("p384Negate",              ([.p384Point],                                                                .p384Point)),
    ("p384OnCurve",             ([.p384Point],                                                                .bool)),
    ("p384EncodeCompressed",    ([.p384Point],                                                                .byteString)),
    ("verifyECDSA_P384",        ([.byteString, .byteString, .byteString],                                     .bool)),
    -- BabyBear field arithmetic
    ("bbFieldAdd",              ([.bigint, .bigint],                                                          .bigint)),
    ("bbFieldSub",              ([.bigint, .bigint],                                                          .bigint)),
    ("bbFieldMul",              ([.bigint, .bigint],                                                          .bigint)),
    ("bbFieldInv",              ([.bigint],                                                                   .bigint)),
    -- BabyBear quartic extension field
    ("bbExt4Mul0",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("bbExt4Mul1",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("bbExt4Mul2",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("bbExt4Mul3",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("bbExt4Inv0",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("bbExt4Inv1",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("bbExt4Inv2",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("bbExt4Inv3",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    -- KoalaBear field arithmetic
    ("kbFieldAdd",              ([.bigint, .bigint],                                                          .bigint)),
    ("kbFieldSub",              ([.bigint, .bigint],                                                          .bigint)),
    ("kbFieldMul",              ([.bigint, .bigint],                                                          .bigint)),
    ("kbFieldInv",              ([.bigint],                                                                   .bigint)),
    -- KoalaBear quartic extension field
    ("kbExt4Mul0",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("kbExt4Mul1",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("kbExt4Mul2",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("kbExt4Mul3",              ([.bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint, .bigint],    .bigint)),
    ("kbExt4Inv0",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("kbExt4Inv1",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("kbExt4Inv2",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    ("kbExt4Inv3",              ([.bigint, .bigint, .bigint, .bigint],                                        .bigint)),
    -- BN254 field arithmetic
    ("bn254FieldAdd",           ([.bigint, .bigint],                                                          .bigint)),
    ("bn254FieldSub",           ([.bigint, .bigint],                                                          .bigint)),
    ("bn254FieldMul",           ([.bigint, .bigint],                                                          .bigint)),
    ("bn254FieldInv",           ([.bigint],                                                                   .bigint)),
    ("bn254FieldNeg",           ([.bigint],                                                                   .bigint)),
    -- BN254 G1 curve operations
    ("bn254G1Add",              ([.point, .point],                                                            .point)),
    ("bn254G1ScalarMul",        ([.point, .bigint],                                                           .point)),
    ("bn254G1Negate",           ([.point],                                                                    .point)),
    ("bn254G1OnCurve",          ([.point],                                                                    .bool)),
    -- Merkle proof verification
    ("merkleRootSha256",        ([.byteString, .byteString, .bigint, .bigint],                                .byteString)),
    ("merkleRootHash256",       ([.byteString, .byteString, .bigint, .bigint],                                .byteString)),
    -- Preimage extractors
    ("extractVersion",          ([.sigHashPreimage],                                                          .bigint)),
    ("extractHashPrevouts",     ([.sigHashPreimage],                                                          .sha256)),
    ("extractHashSequence",     ([.sigHashPreimage],                                                          .sha256)),
    ("extractOutpoint",         ([.sigHashPreimage],                                                          .byteString)),
    ("extractInputIndex",       ([.sigHashPreimage],                                                          .bigint)),
    ("extractScriptCode",       ([.sigHashPreimage],                                                          .byteString)),
    ("extractAmount",           ([.sigHashPreimage],                                                          .bigint)),
    ("extractSequence",         ([.sigHashPreimage],                                                          .bigint)),
    ("extractOutputHash",       ([.sigHashPreimage],                                                          .sha256)),
    ("extractOutputs",          ([.sigHashPreimage],                                                          .sha256)),
    ("extractLocktime",         ([.sigHashPreimage],                                                          .bigint)),
    ("extractSigHashType",      ([.sigHashPreimage],                                                          .bigint)),
    ("buildChangeOutput",       ([.byteString, .bigint],                                                      .byteString)),
    -- Intent sub-covenant intrinsics
    ("extractPrevOutputScript", ([.bigint, .byteString],                                                      .byteString)),
    ("requireOutputP2PKH",      ([.bigint, .byteString, .bigint],                                             .bool)),
    ("currentBlockHeight",      ([],                                                                          .bigint)),
    -- Compiler-internal state-continuation helper. NOT a `BUILTIN_FUNCTIONS`
    -- entry in `03-typecheck.ts` — it is emitted by ANF lowering
    -- (`04-anf-lower.ts:239`) *after* the TS type-check runs, so the source-AST
    -- checker never sees it. It builds the contract's own state-output bytes
    -- from `(txPreimage, stateScript, newAmount)` and is immediately `cat`/
    -- `hash256`'d, so its result is a `ByteString`. Listed here so the
    -- whole-program checker accepts the lowered ANF of every stateful fixture.
    ("computeStateOutput",      ([.sigHashPreimage, .byteString, .bigint],                                    .byteString))
  ]

/-- Look up a builtin's (paramTypes, returnType) from the table. -/
def builtinSig (name : String) : Option (List ANFType × ANFType) :=
  (builtinTable.find? (·.1 == name)).map (·.2)

/-! ## The functional whole-program type checker

This is THE typing judgment for Rúnar ANF programs: a decidable, executable
`Bool`-valued whole-program checker. There is no relational `HasType` to match
against here — `Typed.lean`'s `HasType` only covers a starter fragment, while
this checker handles every `ANFValue` constructor the corpus emits.

The design mirrors the *operational* `Eval.lean` evaluator so that the typing
rules and the dynamic semantics agree shape-for-shape:

* a single non-recursive `typeOfValue` types every leaf / one-level value
  (`ifVal` / `loop` return `none` — they need binding-list recursion, handled
  by `checkBody`);
* `checkBody` threads a `TypeEnv` through a binding list exactly like
  `Eval.evalBindings` threads a `State`, recursing into `ifVal` branches and
  `loop` bodies. The "value" of an `ifVal` binding is the type of the last
  binding of the active branch (mirroring `Eval.evalValue`'s
  `thenBs.getLast?` convention); both branches must agree.

`checkBody` is structurally recursive on the mutual `ANFValue` / `List
ANFBinding` term — the same recursion `Eval.evalBindings` / `Eval.evalValue`
use — so no `partial def` and no explicit `termination_by` are required.
-/

open RunarVerification.ANF
  (ANFValue ANFBinding ConstValue ANFParam ANFProperty ANFMethod ANFProgram)
open RunarVerification.ANF.Typed (TypeEnv)

/-- Build the initial typing context for a method body: contract properties
first, then method parameters (parameters shadow same-named properties, which
matches the most-recent-wins `TypeEnv.extend` discipline). -/
def TypeEnv.ofParamsProps (props : List ANFProperty) (params : List ANFParam) : TypeEnv :=
  let g := props.foldl (fun Γ p => Γ.extend p.name p.type) Typed.TypeEnv.empty
  params.foldl (fun Γ pp => Γ.extend pp.name pp.type) g

/-- Is `op` an arithmetic binary operator (`+ - * / %`)? Result type `.bigint`. -/
def isArithOp (op : String) : Bool :=
  op == "+" || op == "-" || op == "*" || op == "/" || op == "%"

/-- Is `op` a comparison / logical binary operator? Result type `.bool`.
Mirrors `03-typecheck.ts`: numeric comparisons + `&&` / `||`. -/
def isBoolBinOp (op : String) : Bool :=
  op == "==" || op == "===" || op == "!=" || op == "!==" ||
  op == "<"  || op == "<="  || op == ">"  || op == ">=" ||
  op == "&&" || op == "||"

/-! ### Subtyping lattice (mirror `03-typecheck.ts` `isSubtype`)

The TS checker (`03-typecheck.ts:242-281`) groups the stack representations into
two families:

* `BYTESTRING_SUBTYPES` — `ByteString`, `PubKey`, `Sig`, `Sha256`, `Ripemd160`,
  `Addr`, `SigHashPreimage`, `Point`, `P256Point`, `P384Point` (all live on the
  stack as byte strings);
* `BIGINT_SUBTYPES` — `bigint`, `RabinSig`, `RabinPubKey` (all live as integers).

`isSubtype actual expected` is true when the two types are equal, when both lie
in the byte family, when both lie in the bigint family, or (for `checkMultiSig`'s
`Sig[]` / `PubKey[]`) when their element types are subtype-compatible. The TS
`<inferred>` / `<unknown>` always-compatible cases are intentionally omitted:
every lowered-ANF binding carries a concrete `ANFType`, so those sentinels never
arise here. -/

/-- `t` is in the byte-string family (`BYTESTRING_SUBTYPES`). -/
def isByteFamily : ANFType → Bool
  | .byteString | .pubKey | .sig | .sha256 | .ripemd160
  | .addr | .sigHashPreimage | .point | .p256Point | .p384Point => true
  | _ => false

/-- `t` is in the bigint family (`BIGINT_SUBTYPES`). -/
def isBigintFamily : ANFType → Bool
  | .bigint | .rabinSig | .rabinPubKey => true
  | _ => false

/-- Subtype compatibility, mirroring `03-typecheck.ts`'s `isSubtype`. Reflexive;
both-in-byte-family ⇒ compatible; both-in-bigint-family ⇒ compatible; arrays
compatible element-wise. (Note: TS's three separate ByteString rules collapse to
"both in byte family", and likewise for bigint.) -/
def isSubtype : ANFType → ANFType → Bool
  | .array a, .array b => isSubtype a b
  | sub, sup =>
      sub == sup
        || (isByteFamily sub && isByteFamily sup)
        || (isBigintFamily sub && isBigintFamily sup)

/-! ### Binary-operator typing (mirror `checkBinaryExpr`)

`binOpResultType lt rt op` returns the result type of `op` applied to operands of
types `lt` / `rt`, following `03-typecheck.ts:890-1023` (operand-type-driven; the
ANF `result_type` discriminator is metadata only — the TS checker ignores it too):

* `+` — byte family × byte family ⇒ `ByteString` (OP_CAT); else bigint × bigint ⇒ `bigint`;
* `- * / %` — bigint × bigint ⇒ `bigint`;
* `< <= > >=` — bigint × bigint ⇒ `bool`;
* `== === != !==` — subtype-compatible (either direction) ⇒ `bool`;
* `&& ||` — bool × bool ⇒ `bool`;
* `<< >>` — bigint × bigint ⇒ `bigint`;
* `& | ^` — byte family × byte family ⇒ `ByteString`; else bigint × bigint ⇒ `bigint`.

The arith fragment (`+ - * / %` on `bigint × bigint`) is preserved bit-for-bit
from the original `typeOfValue` so the Task 6 / Task 7 soundness proofs still
hold (they only constrain the `some .bigint, some .bigint` arith path). -/
def binOpResultType (lt rt : ANFType) (op : String) : Option ANFType :=
  if op == "+" then
    if isByteFamily lt && isByteFamily rt then some .byteString
    else if isBigintFamily lt && isBigintFamily rt then some .bigint
    else none
  else if op == "-" || op == "*" || op == "/" || op == "%" then
    if isBigintFamily lt && isBigintFamily rt then some .bigint else none
  else if op == "<" || op == "<=" || op == ">" || op == ">=" then
    if isBigintFamily lt && isBigintFamily rt then some .bool else none
  else if op == "==" || op == "===" || op == "!=" || op == "!==" then
    if isSubtype lt rt || isSubtype rt lt then some .bool else none
  else if op == "&&" || op == "||" then
    if lt == .bool && rt == .bool then some .bool else none
  else if op == "<<" || op == ">>" then
    if isBigintFamily lt && isBigintFamily rt then some .bigint else none
  else if op == "&" || op == "|" || op == "^" then
    if isByteFamily lt && isByteFamily rt then some .byteString
    else if isBigintFamily lt && isBigintFamily rt then some .bigint
    else none
  else none

/-- Do the actual args (resolved against `Γ`) satisfy a builtin's parameter
types under subtyping? Mirrors `checkCallArgs`'s per-arg `isSubtype(argType,
expectedType)` loop (plus the implicit arity check): same length, and each arg
resolves to a type that is a subtype of the corresponding parameter. -/
def argsMatchParams (Γ : TypeEnv) (args : List String) (ptys : List ANFType) : Bool :=
  args.length == ptys.length &&
    (List.zip args ptys).all (fun (a, p) =>
      match Γ.lookup a with
      | some t => isSubtype t p
      | none   => false)

/--
Type a single `ANFValue` in environment `Γ`. Returns the result type when the
value is well-typed, `none` otherwise.

`retEnv` maps each method name to the result type of its body (the type of its
last binding); it is consulted only by `.methodCall`. Built only once per
program by `programWellTypedBool`.

`ifVal` / `loop` are NOT typed here (they return `none`) — they require
binding-list recursion and are handled by `checkBody`.
-/
def typeOfValue (retEnv : List (String × ANFType)) (Γ : TypeEnv) : ANFValue → Option ANFType
  | .loadParam name => Γ.lookup name
  | .loadProp name  => Γ.lookup name
  | .loadConst (.int _)      => some .bigint
  | .loadConst (.bool _)     => some .bool
  | .loadConst (.bytes _)    => some .byteString
  | .loadConst (.refAlias n) => Γ.lookup n
  | .loadConst .thisRef      => some .addr
  | .binOp op l r _ =>
      match Γ.lookup l, Γ.lookup r with
      | some .bigint, some .bigint =>
          -- ARITH FRAGMENT — kept byte-for-byte for the Task 6 / Task 7 proofs:
          -- `isArithOp op ⇒ some .bigint` is the FIRST conditional so the
          -- preservation proof's `rw [hFrag]` still reduces it to `some .bigint`.
          -- The trailing `binOpResultType` adds the new bigint × bigint ops
          -- (`<< >> & | ^`, and the comparisons `< <= > >=`, equality, logical)
          -- without disturbing that head.
          if isArithOp op then some .bigint
          else if isBoolBinOp op then some .bool
          else binOpResultType .bigint .bigint op
      | some lt, some rt =>
          -- BYTE / MIXED families (subtyping-aware): `+` & `& | ^` concat byte
          -- operands to `ByteString`; `=== !== == !=` compare subtype-compatible
          -- operands to `bool`. Mirrors `checkBinaryExpr`'s operand-type logic.
          --
          -- The arith ops (`isArithOp`) are EXCLUDED from this arm: they are
          -- typed exclusively by the `some .bigint, some .bigint` arm above, so
          -- `typeOfValue (binOp arith) = some _` ⇒ both operands are exactly
          -- `.bigint` — the invariant the Task 6 preservation proof relies on.
          -- (No conformance fixture ever applies an arith op to a bigint-family
          -- subtype like `RabinSig`, so this loses no fidelity.)
          if isArithOp op then none else binOpResultType lt rt op
      | _, _ => none
  | .unaryOp op operand _ =>
      match Γ.lookup operand with
      | some .bigint => if op == "-" || op == "~" then some .bigint else none
      | some .bool   => if op == "!" then some .bool else none
      | _            => none
  | .call func args =>
      -- `super(...)` is special-cased exactly as in `03-typecheck.ts`
      -- (`checkCallExpr`): a constructor's `super(...)` call is NOT matched
      -- against any signature — a separate validator guarantees it passes all
      -- properties. The TS checker only `inferExprType`s each argument (i.e.
      -- requires each arg to be in scope) and returns `VOID`. We mirror that:
      -- every arg ref must resolve in `Γ`, and the result is `.bool` (the
      -- file's void convention). This is the only ANF `.call` whose `func` is
      -- not a `BUILTIN_FUNCTIONS` entry.
      if func == "super" then
        if args.all (fun r => (Γ.lookup r).isSome) then some .bool else none
      else
      match builtinSig func with
      | some (ptys, rty) =>
          -- Subtype-aware arg matching (mirrors `checkCallArgs`): each arg's
          -- resolved type must be `isSubtype` of the parameter type (e.g.
          -- `hash160(pubKey : PubKey)` where the param is `ByteString`).
          if argsMatchParams Γ args ptys then some rty else none
      | none => none
  | .methodCall _obj method _args =>
      (retEnv.find? (·.1 == method)).map (·.2)
  | .ifVal _ _ _ _ => none   -- handled in `checkBody`
  | .loop _ _ _ _ _ => none    -- handled in `checkBody`
  | .assert ref =>
      if Γ.lookup ref == some .bool then some .bool else none
  | .updateProp name src =>
      match Γ.lookup name, Γ.lookup src with
      | some τprop, some τsrc => if τprop == τsrc then some τprop else none
      | _, _ => none
  | .getStateScript => some .byteString
  | .checkPreimage preimage =>
      if Γ.lookup preimage == some .sigHashPreimage then some .bool else none
  | .deserializeState preimage =>
      if Γ.lookup preimage == some .sigHashPreimage then some .bool else none
  -- `add_output` is ALWAYS emitted with `preimage:""` (`04-anf-lower.ts:1291,
  -- 1332`), and `Γ.lookup "" = none`: the preimage is injected at
  -- stack-lowering, not threaded as an ANF ref. So the preimage conjunct is
  -- dropped (it would always fail). We keep the satoshis (bigint) + state-value
  -- (all resolve) checks. The result is `.byteString`: at runtime `add_output`
  -- produces the serialized output bytes (`Eval` binds `.vOpaque`), which the
  -- continuation always `cat`/`hash256`'s — never a bool context (verified
  -- across the corpus: output-intrinsic results flow only into `cat`/`hash256`).
  | .addOutput sats stateValues _preimage =>
      if Γ.lookup sats == some .bigint
         && stateValues.all (fun r => (Γ.lookup r).isSome)
      then some .byteString else none
  | .addRawOutput sats scriptBytes =>
      if Γ.lookup sats == some .bigint
         && (match Γ.lookup scriptBytes with | some t => isSubtype t .byteString | none => false)
      then some .byteString else none
  | .addDataOutput sats scriptBytes =>
      if Γ.lookup sats == some .bigint
         && (match Γ.lookup scriptBytes with | some t => isSubtype t .byteString | none => false)
      then some .byteString else none
  -- A homogeneous `array_literal` of elements all of type `τ` has type
  -- `.array τ`. Mirrors `03-typecheck.ts`'s `array_literal` rule: the element
  -- type is taken from the first element and every other element must agree
  -- (TS allows a subtype; Lean has no subtyping, so we require strict
  -- equality — which holds for every conformance fixture, whose arrays are
  -- homogeneous, e.g. `checkMultiSig`'s `Sig[]` / `PubKey[]`). An empty array
  -- has no inferable element type and is left un-typeable (`none`).
  | .arrayLiteral elements =>
      match elements with
      | []      => none
      | e :: es =>
          match Γ.lookup e with
          | none   => none
          | some τ =>
              if es.all (fun r => Γ.lookup r == some τ)
              then some (.array τ) else none
  | .rawScript _ _ _ => some .byteString

/--
Type-check a binding list, threading the environment. Returns the final
environment (the input `Γ` extended with one entry per binding) on success, or
`none` if any binding is ill-typed.

Mirrors `Eval.evalBindings`: structurally recursive on the binding-list spine,
descending into `ifVal` branches and `loop` bodies (which are structural
sub-terms of the head binding's value). `bodyWellTypedBool` is its `isSome`
projection.

`ifVal` rule (mirrors `03-typecheck.ts`, where `if` is a *statement*): the
condition must be `.bool` and BOTH branches must type-check, but their
last-binding types need NOT agree — TS pushes/pops a fresh scope per branch and
imposes no join constraint. We bind the if-binding's name to the THEN branch's
last-binding type (falling back to the ELSE last type, then `.bool`, when a
branch is empty). This matches the runtime, where the if-value is the active
branch's last binding (`Eval.evalValue`'s `.ifVal` arm), and — since the output
intrinsics (`add_output` &c.) are typed `.byteString` — yields the byte type the
state-continuation's downstream `cat`/`hash256` expects. `loop` rule: the body
type-checks with `iterVar : bigint` in scope; the loop binding itself is `.bool`
(matching `Eval`'s `vBool true`). -/
def checkBody (retEnv : List (String × ANFType)) (Γ : TypeEnv) :
    List ANFBinding → Option TypeEnv
  | [] => some Γ
  | .mk name v _ :: rest =>
    match v with
    | .ifVal cond thenBranch elseBranch _ =>
        if Γ.lookup cond == some .bool then
          match checkBody retEnv Γ thenBranch, checkBody retEnv Γ elseBranch with
          | some envT, some envE =>
              -- if-as-statement: no branch-type agreement required. Bind the
              -- if-name to the THEN last type (then ELSE, then `.bool`).
              let τThen := match thenBranch.getLast? with
                | some b => envT.lookup b.name
                | none   => none
              let τElse := match elseBranch.getLast? with
                | some b => envE.lookup b.name
                | none   => none
              let τIf := τThen.orElse (fun _ => τElse) |>.getD .bool
              checkBody retEnv (Γ.extend name τIf) rest
          | _, _ => none
        else none
    | .loop _count body iterVar _ _ =>
        match checkBody retEnv (Γ.extend iterVar .bigint) body with
        | some _ => checkBody retEnv (Γ.extend name .bool) rest
        | none   => none
    | other =>
        match typeOfValue retEnv Γ other with
        | some τ => checkBody retEnv (Γ.extend name τ) rest
        | none   => none

/-- `true` iff `bs` type-checks in `Γ` (the decidable body-typing judgment). -/
def bodyWellTypedBool (retEnv : List (String × ANFType)) (Γ : TypeEnv)
    (bs : List ANFBinding) : Bool :=
  (checkBody retEnv Γ bs).isSome

/-- The result type a method body produces: the type of its last binding in the
fully-threaded environment (`none` if the body is ill-typed or empty). Used to
populate `retEnv` so `methodCall`s can be typed by the callee's result. -/
def methodResultType (retEnv : List (String × ANFType)) (props : List ANFProperty)
    (m : ANFMethod) : Option ANFType :=
  match checkBody retEnv (TypeEnv.ofParamsProps props m.params) m.body with
  | some env =>
      match m.body.getLast? with
      | some b => env.lookup b.name
      | none   => none
  | none => none

/-- `true` iff method `m` type-checks against contract `props` and the
program-level method-return environment `retEnv`. -/
def methodWellTypedBool (retEnv : List (String × ANFType)) (props : List ANFProperty)
    (m : ANFMethod) : Bool :=
  bodyWellTypedBool retEnv (TypeEnv.ofParamsProps props m.params) m.body

/--
The program-level method-return environment: each method name mapped to the
type of its body's last binding. Methods whose body is empty or ill-typed
contribute no entry (so a `methodCall` to them stays un-typeable).

Note: this is computed with an empty `retEnv` for the inner `methodResultType`,
i.e. methods are typed without resolving *other* methods' return types. This is
sufficient for the v0.x corpus (the conformance ANF inlines private-method
calls before this checker would run on cross-method `methodCall`s), and keeps
the construction non-recursive. A program that genuinely needs callee return
types for a surviving `methodCall` is out of scope here and would simply fail
to type that node.
-/
def programReturnEnv (p : ANFProgram) : List (String × ANFType) :=
  p.methods.foldr
    (fun m acc =>
      match methodResultType [] p.properties m with
      | some τ => (m.name, τ) :: acc
      | none   => acc)
    []

/-- THE whole-program typing judgment: `true` iff every method of `p`
type-checks. Decidable and executable (`native_decide`-friendly). -/
def programWellTypedBool (p : ANFProgram) : Bool :=
  let retEnv := programReturnEnv p
  p.methods.all (fun m => methodWellTypedBool retEnv p.properties m)

end RunarVerification.ANF.TypeCheck

-- Smoke tests (elaborated by `lake build`)
example : RunarVerification.ANF.TypeCheck.builtinSig "sha256" = some ([.byteString], .sha256) := by native_decide
example : RunarVerification.ANF.TypeCheck.builtinSig "ecMul" = some ([.point, .bigint], .point) := by native_decide
example : RunarVerification.ANF.TypeCheck.builtinSig "within" = some ([.bigint, .bigint, .bigint], .bool) := by native_decide
example : RunarVerification.ANF.TypeCheck.builtinSig "not_a_builtin" = none := by native_decide

/-! ## Whole-program checker smoke tests -/

open RunarVerification.ANF in
/-- A well-typed program: `add(a : bigint, b : bigint) { let t = a + b }`. -/
def smokeWellTyped : ANFProgram :=
  { contractName := "Adder"
  , properties := []
  , methods :=
      [ { name := "add"
        , params := [⟨"a", .bigint⟩, ⟨"b", .bigint⟩]
        , body := [ANFBinding.mk "t" (.binOp "+" "a" "b" none)]
        , isPublic := true } ] }

open RunarVerification.ANF in
/-- An ill-typed program: `bad(f : boolean, a : bigint) { let t = f + a }`.
A `bool` operand to `+` is rejected (both operands must be `bigint`). -/
def smokeIllTyped : ANFProgram :=
  { contractName := "BadAdder"
  , properties := []
  , methods :=
      [ { name := "bad"
        , params := [⟨"f", .bool⟩, ⟨"a", .bigint⟩]
        , body := [ANFBinding.mk "t" (.binOp "+" "f" "a" none)]
        , isPublic := true } ] }

example : RunarVerification.ANF.TypeCheck.programWellTypedBool smokeWellTyped = true := by native_decide
example : RunarVerification.ANF.TypeCheck.programWellTypedBool smokeIllTyped = false := by native_decide

open RunarVerification.ANF in
/-- A program with a `constructor` that calls `super(...)` with an in-scope
property value — mirrors the canonical conformance shape (e.g. `arithmetic`).
`super` type-checks unconditionally (returns the `.bool` void marker) without
matching its argument against any signature. -/
def smokeSuper : ANFProgram :=
  { contractName := "Ctor"
  , properties := [⟨"target", .bigint, false, none⟩]
  , methods :=
      [ { name := "constructor"
        , params := [⟨"target", .bigint⟩]
        , body :=
            [ ANFBinding.mk "t0" (.loadProp "target")
            , ANFBinding.mk "t1" (.call "super" ["t0"]) ]
        , isPublic := true } ] }

example : RunarVerification.ANF.TypeCheck.programWellTypedBool smokeSuper = true := by native_decide
-- `super` with an out-of-scope argument is rejected (the arg-in-scope check,
-- the analog of the TS `inferExprType(arg)`, fails).
example :
    RunarVerification.ANF.TypeCheck.typeOfValue []
      RunarVerification.ANF.Typed.TypeEnv.empty
      (.call "super" ["nope"]) = none := by native_decide
