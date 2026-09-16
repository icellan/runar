# Rúnar Compiled Artifact Format

**Version:** 1.0.0-rc.1
**Status:** Draft

This document specifies the JSON artifact produced by the Rúnar compiler. The artifact contains everything needed to deploy and interact with a compiled smart contract on Bitcoin SV.

---

## 1. Overview

When the Rúnar compiler processes a `.ts` source file, it produces a `.json` artifact file. This artifact is consumed by the Rúnar SDK at runtime to:

1. Deploy the contract (create the locking script with constructor parameters).
2. Call public methods (construct unlocking scripts).
3. Manage stateful contract interactions (encode/decode state).

---

## 2. Artifact Schema

```json
{
    "version": "string",
    "compilerVersion": "string",
    "contractName": "string",
    "abi": { ... },
    "script": "string",
    "asm": "string",
    "parentClass": "string",
    "sourceMap": { ... },
    "ir": { ... },
    "anf": { ... },
    "stateFields": [ ... ],
    "constructorSlots": [ ... ],
    "templateDigest": { ... },
    "codeSepIndexSlots": [ ... ],
    "codeSeparatorIndex": 0,
    "codeSeparatorIndices": [ ... ],
    "rawScriptSpans": [ ... ],
    "unsoundPrimitives": [ ... ],
    "buildTimestamp": "string"
}
```

> **`ir.anf` and top-level `anf` are different fields and are not
> interchangeable.** `ir` is an optional debugging snapshot, written only when
> the compiler is invoked with `--ir`. Top-level `anf` is written whenever the
> contract has mutable state, and it is the one the SDKs read to compute state
> transitions. An SDK that looked under `ir.anf` would work on artifacts built
> with `--ir` and fail on every ordinary build of the same contract.

---

## 3. Field Definitions

### 3.1 `version`

- **Type**: `string`
- **Required**: Yes
- **Description**: Artifact format version. Uses `runar-v` prefix followed by semantic versioning.
- **Example**: `"runar-v1.0.0-rc.1"` (the value `ARTIFACT_VERSION` in `packages/runar-compiler/src/artifact/assembler.ts` stamps today)
- **Rules**: The SDK SHOULD reject artifacts with a major version it does not support.
- **Status**: **Not enforced by any tier.** No SDK currently inspects this field; an artifact carrying any `version` string, or a future major version, is accepted and deployed. The rule is stated as a requirement on future work, not as a description of current behaviour — treat a version mismatch as undetected, not as rejected.

### 3.2 `compilerVersion`

- **Type**: `string`
- **Required**: Yes
- **Description**: Version of the Rúnar compiler that produced this artifact.
- **Example**: `"1.0.0-rc.1"` (the value `DEFAULT_COMPILER_VERSION` in `packages/runar-compiler/src/artifact/assembler.ts` stamps today)
- **Rules**: Informational. The SDK MAY warn if the compiler version is significantly older or newer than the SDK version.

### 3.3 `contractName`

- **Type**: `string`
- **Required**: Yes
- **Description**: The name of the contract class.
- **Example**: `"P2PKH"`
- **Rules**: Must match the class name in the source file.

### 3.4 `abi`

- **Type**: `ABI` object (see `abi.md` for full specification)
- **Required**: Yes
- **Description**: The Application Binary Interface describing the constructor and all public methods.
- **Example**:

```json
{
    "constructor": {
        "params": [
            { "name": "pubKeyHash", "type": "Addr" }
        ]
    },
    "methods": [
        {
            "name": "unlock",
            "params": [
                { "name": "sig", "type": "Sig" },
                { "name": "pubKey", "type": "PubKey" }
            ],
            "isPublic": true
        }
    ]
}
```

### 3.5 `script`

- **Type**: `string` (hexadecimal)
- **Required**: Yes
- **Description**: The compiled locking script as a hex-encoded byte string. This is the **script template** -- it contains `OP_0` (`00`) byte placeholders at positions where constructor parameter values will be spliced in during deployment.
- **Example**: `"76a9140088ac"` (the `00` at byte offset 3 is a placeholder for `pubKeyHash`)

#### Placeholder Mechanism

The compiler emits `OP_0` (hex `00`) as a 1-byte placeholder wherever a constructor parameter value belongs. The byte offset of each placeholder is recorded in the `constructorSlots` array (see section 3.10). At deployment time, the SDK replaces the 2-hex-char `00` at each recorded byte offset with the encoded argument value (push data opcode + serialized value).

For example, given `constructorSlots: [{ "paramIndex": 0, "byteOffset": 3 }]`, the SDK knows to replace the `00` at byte offset 3 in the script hex with the serialized `pubKeyHash` value.

### 3.6 `asm`

- **Type**: `string`
- **Required**: Yes
- **Description**: Human-readable assembly representation of the script. Uses standard Bitcoin Script opcode mnemonics.
- **Example**: `"OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG"`
- **Rules**: Opcodes are separated by single spaces. Constructor parameter placeholders appear as `OP_0` in the assembly. Literal data is shown as hex.

### 3.7 `sourceMap`

- **Type**: `SourceMap` object
- **Required**: No (may be omitted for production builds)
- **Description**: Maps byte offsets in the compiled script back to source locations for debugging.

```json
{
    "mappings": [
        {
            "opcodeIndex": 0,
            "sourceFile": "P2PKH.ts",
            "line": 12,
            "column": 8
        },
        {
            "opcodeIndex": 1,
            "sourceFile": "P2PKH.ts",
            "line": 12,
            "column": 8
        }
    ]
}
```

#### SourceMap Mapping Entry

| Field | Type | Description |
|---|---|---|
| `opcodeIndex` | `number` | Index of the opcode in the compiled script |
| `sourceFile` | `string` | Source file name |
| `line` | `number` | 1-based line number in source |
| `column` | `number` | 0-based column in source |

### 3.8 `ir`

- **Type**: `{ anf?: ANFProgram; stack?: StackProgram }` (see `ir-format.md` and `stack-ir.md`)
- **Required**: No (optional, included when compiler flag `--ir` is set)
- **Description**: Optional IR snapshots for debugging and conformance checking. Contains optional `anf` (the canonical ANF IR) and optional `stack` (the Stack IR) sub-fields.

### 3.9 `stateFields`

- **Type**: `StateField[]`
- **Required**: No (optional; omitted for stateless contracts)
- **Description**: Describes the mutable state fields of the contract, their types, and their order in the state serialization. Only present for stateful contracts.

```json
[
    {
        "name": "counter",
        "type": "bigint",
        "index": 0
    },
    {
        "name": "owner",
        "type": "PubKey",
        "index": 1
    }
]
```

#### StateField Entry

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Property name |
| `type` | `string` | Rúnar type |
| `index` | `number` | Position in state serialization (0-based) |

For stateless contracts (no mutable properties), this field is omitted.

### 3.10 `constructorSlots`

- **Type**: `ConstructorSlot[]`
- **Required**: No (omitted when there are no constructor parameter placeholders)
- **Description**: Specifies byte offsets within the `script` hex string where constructor parameter values should be spliced in during deployment. Each slot identifies which constructor parameter it corresponds to and the exact byte offset in the compiled script.

```json
[
    {
        "paramIndex": 0,
        "byteOffset": 3
    }
]
```

#### ConstructorSlot Entry

| Field | Type | Description |
|---|---|---|
| `paramIndex` | `number` | Index into the constructor's `params` array (0-based) |
| `byteOffset` | `number` | Byte offset in the compiled script hex where this parameter's push data begins |

The SDK uses these offsets to splice serialized constructor argument values directly into the script bytes, rather than relying on string-based placeholder replacement. This is the preferred mechanism for deployment as it is more robust than textual substitution.

### 3.11 `parentClass`

- **Type**: `"SmartContract" | "StatefulSmartContract" | "UnsafeSmartContract"`
- **Required**: No (present on artifacts produced by current compilers)
- **Description**: The base class the contract extends. This is the authoritative stateful signal: a `StatefulSmartContract` with zero mutable fields still needs the terminal sighash subscript trim, and `stateFields` being absent does not distinguish it from a stateless contract.

### 3.12 `anf`

- **Type**: `ANFProgram` (see `ir-format.md`)
- **Required**: No — present whenever the contract has mutable state
- **Description**: The canonical ANF IR, at the TOP LEVEL of the artifact. This is the field the seven SDKs read to compute state transitions without a caller-supplied `newState`. It is emitted independently of the `--ir` flag and is **not** the same field as `ir.anf` (§3.8), which is an optional debugging snapshot.

### 3.13 `templateDigest`

- **Type**: `TemplateDigest`
- **Required**: No (present whenever `constructorSlots` is)
- **Description**: The recipe for recomputing the slot-excised template identity hash — the digest of the locking script with every constructor-argument slot removed. Two deployments of the same contract with different constructor arguments share a template digest; this is what lets a verifier recognise the contract behind an on-chain script.

### 3.14 `codeSepIndexSlots`

- **Type**: `CodeSepIndexSlot[]`
- **Required**: No (omitted when the script contains no codeSepIndex placeholder)
- **Description**: Byte offsets of `push_codesep_index` placeholders in the script, in the same shape and for the same reason as `constructorSlots`: the value is not known until byte offsets exist, so the emitter reserves space and records where to patch.

### 3.15 `codeSeparatorIndex` / `codeSeparatorIndices`

- **Type**: `number` / `number[]`
- **Required**: No (present only for stateful contracts)
- **Description**: Byte offset(s) of `OP_CODESEPARATOR` in the locking script, needed to compute the BIP-143 sighash subscript. `codeSeparatorIndices` is indexed by public method (index 0 = first public method); `codeSeparatorIndex` is the single-method form. **Multi-method contracts must use `codeSeparatorIndices`** — the singular field names only one separator and signing against it for a different method produces a sighash the script will not accept.

### 3.16 `rawScriptSpans`

- **Type**: `RawScriptSpan[]`
- **Required**: No (present only when the contract uses `asm(...)`)
- **Description**: Byte ranges produced by `raw_script` ANF nodes. These bytes are opaque: the stack analyzer cannot model their effect and relies on the declared arity, so a consumer must treat these ranges as unanalysable rather than as ordinary script.

### 3.17 `unsoundPrimitives`

- **Type**: `string[]`
- **Required**: No — **absent**, not empty, on any artifact that reaches no such builtin
- **Description**: Names of unsound primitives this artifact's script reaches. Read by the SDKs (`packages/runar-sdk/src/unsound-primitives.ts`) and by all six native tiers.

### 3.18 `buildTimestamp`

- **Type**: `string` (ISO 8601)
- **Required**: Yes
- **Description**: Timestamp of when the artifact was produced.
- **Example**: `"2025-06-15T10:30:00Z"`
- **Rules**: UTC timezone. Informational only -- not used for artifact identity.

---

## 4. Deployment Flow

The SDK uses the artifact to deploy a contract as follows:

### Step 1: Instantiate

```typescript
import { RunarContract } from 'runar-sdk';

const artifact = JSON.parse(fs.readFileSync('P2PKH.json', 'utf8'));
const contract = new RunarContract(artifact, [pubKeyHash]);
```

### Step 2: Build Locking Script

The SDK uses the `constructorSlots` array to splice constructor argument values into the `script` template at the recorded byte offsets:

```
Template:      "76a9140088ac"
                       ^^ OP_0 placeholder at byteOffset 3
constructorSlots: [{ paramIndex: 0, byteOffset: 3 }]
Value:         pubKeyHash = "89abcdef01234567890abcdef01234567890abcd"
Result:        "76a91489abcdef01234567890abcdef01234567890abcd88ac"
```

For each constructor slot, the SDK:

1. Serializes the value according to its type (see Type Encoding in `abi.md`).
2. Wraps it with the appropriate push data opcode.
3. Replaces the 2-hex-char `00` (OP_0) at the recorded `byteOffset` with the hex-encoded result.

### Step 3: Create Transaction Output

The final locking script bytes are placed in a transaction output.

---

## 5. Method Invocation Flow

To spend a UTXO locked by a Rúnar contract:

### Step 1: Select Method

The caller specifies which public method to invoke and provides its arguments.

### Step 2: Build Unlocking Script

The SDK constructs the unlocking script:

```
For single-method contracts:
    <param_1> <param_2> ... <param_n>

For multi-method contracts:
    <param_1> <param_2> ... <param_n> <method_index>
```

Parameters are pushed in **forward declaration order** (matching the order in the ABI `params` array). The first parameter is pushed first (ending up deepest on the stack) and the last parameter is pushed last (ending up on top).

### Step 3: Create Transaction Input

The unlocking script is placed in the transaction input's scriptSig.

---

## 6. Stateful Contract Flow

For stateful contracts, the deployment and invocation flows are extended:

### Deployment

The initial locking script includes the initial state appended after an `OP_RETURN` separator:

```
<code_part> OP_RETURN <field_0> <field_1> ... <field_n>
```

### State Transition

When a stateful method is called:

1. The unlocking script provides method parameters and the sighash preimage.
2. The locking script reads the current state from the preimage.
3. The method logic updates the state.
4. The method constructs the expected new locking script (with updated state).
5. `checkPreimage` verifies the transaction output matches.

The SDK handles serialization/deserialization of state using the `stateFields` descriptor.

---

## 7. Complete Example Artifact

```json
{
    "version": "runar-v0.1.0",
    "compilerVersion": "0.1.0",
    "contractName": "P2PKH",
    "abi": {
        "constructor": {
            "params": [
                { "name": "pubKeyHash", "type": "Addr" }
            ]
        },
        "methods": [
            {
                "name": "unlock",
                "params": [
                    { "name": "sig", "type": "Sig" },
                    { "name": "pubKey", "type": "PubKey" }
                ],
                "isPublic": true
            }
        ]
    },
    "script": "76a9140088ac",
    "asm": "OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG",
    "constructorSlots": [
        { "paramIndex": 0, "byteOffset": 3 }
    ],
    "sourceMap": {
        "mappings": [
            { "opcodeIndex": 0, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 1, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 2, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 3, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 4, "sourceFile": "P2PKH.ts", "line": 13, "column": 8 }
        ]
    },
    "buildTimestamp": "2025-06-15T10:30:00Z"
}
```

---

## 8. Versioning and Compatibility

### Forward Compatibility

The SDK SHOULD ignore unknown fields in the artifact. This allows newer compilers to add fields without breaking older SDKs.

### Backward Compatibility

The SDK SHOULD reject artifacts with a `version` major number it does not support. Minor and patch version differences are acceptable.

> **Unimplemented.** No tier reads the `version` field. This rule describes intended behaviour; it does not describe any SDK shipping today, and an artifact from an incompatible future major version will be deployed rather than refused. Stated here so that the gap is visible rather than assumed closed.

### Version History

| Version | Changes |
|---|---|
| `0.1.0` | Initial specification |
| `1.0.0-rc.1` | Current. Adds `parentClass`, top-level `anf`, `templateDigest`, `codeSepIndexSlots`, `codeSeparatorIndex` / `codeSeparatorIndices`, `rawScriptSpans`, `unsoundPrimitives` |
