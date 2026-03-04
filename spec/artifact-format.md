# Rúnar Compiled Artifact Format

**Version:** 0.1.0
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
    "sourceMap": { ... },
    "ir": { ... },
    "stateFields": [ ... ],
    "constructorSlots": [ ... ],
    "buildTimestamp": "string"
}
```

---

## 3. Field Definitions

### 3.1 `version`

- **Type**: `string`
- **Required**: Yes
- **Description**: Artifact format version. Follows semantic versioning.
- **Example**: `"0.1.0"`
- **Rules**: The SDK MUST reject artifacts with a major version it does not support.

### 3.2 `compilerVersion`

- **Type**: `string`
- **Required**: Yes
- **Description**: Version of the Rúnar compiler that produced this artifact.
- **Example**: `"0.1.0-alpha.1"`
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
- **Description**: The compiled locking script as a hex-encoded byte string. This is the **script template** -- it contains placeholders for constructor parameters.
- **Example**: `"76a914<pubKeyHash>88ac"`
- **Placeholder format**: `<paramName>` is replaced with the actual value during deployment.

#### Placeholder Encoding

Placeholders appear in the hex string as:

```
<name>
```

Where `name` is the constructor parameter name. When deploying, the SDK replaces each placeholder with the hex-encoded push data for that parameter value.

### 3.6 `asm`

- **Type**: `string`
- **Required**: Yes
- **Description**: Human-readable assembly representation of the script. Uses standard Bitcoin Script opcode mnemonics.
- **Example**: `"OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG"`
- **Rules**: Opcodes are separated by single spaces. Placeholders use the same `<name>` syntax as the `script` field. Literal data is shown as hex.

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

- **Type**: `ANFProgram` object (see `ir-format.md`)
- **Required**: No (optional, included when compiler flag `--ir` is set)
- **Description**: The canonical ANF IR for the contract. Useful for debugging and verification.

### 3.9 `stateFields`

- **Type**: `StateField[]`
- **Required**: Yes (empty array for stateless contracts)
- **Description**: Describes the mutable state fields of the contract, their types, and their order in the state serialization.

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

For stateless contracts (no mutable properties), this is an empty array `[]`.

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

### 3.11 `buildTimestamp`

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
const artifact = JSON.parse(fs.readFileSync('P2PKH.json', 'utf8'));
const P2PKH = buildContractClass(artifact);
const instance = new P2PKH(pubKeyHash);
```

### Step 2: Build Locking Script

The SDK replaces placeholders in the `script` template:

```
Template:  "76a914<pubKeyHash>88ac"
Value:     pubKeyHash = "89abcdef01234567890abcdef01234567890abcd"
Result:    "76a91489abcdef01234567890abcdef01234567890abcd88ac"
```

For each placeholder, the SDK:

1. Serializes the value according to its type (see Type Encoding in `abi.md`).
2. Wraps it with the appropriate push data opcode.
3. Replaces the placeholder with the hex-encoded result.

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
    <param_n> <param_n-1> ... <param_1>

For multi-method contracts:
    <param_n> <param_n-1> ... <param_1> <method_index>
```

Parameters are pushed in **reverse declaration order** so that the first parameter ends up on top of the stack when the locking script begins execution.

### Step 3: Create Transaction Input

The unlocking script is placed in the transaction input's scriptSig.

---

## 6. Stateful Contract Flow

For stateful contracts, the deployment and invocation flows are extended:

### Deployment

The initial locking script includes the initial state:

```
<initial_state_data> OP_DROP ... OP_DROP <code_part>
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
    "version": "0.1.0",
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
    "script": "76a914<pubKeyHash>88ac",
    "asm": "OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG",
    "sourceMap": {
        "mappings": [
            { "opcodeIndex": 0, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 1, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 2, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 3, "sourceFile": "P2PKH.ts", "line": 12, "column": 8 },
            { "opcodeIndex": 4, "sourceFile": "P2PKH.ts", "line": 13, "column": 8 }
        ]
    },
    "stateFields": [],
    "buildTimestamp": "2025-06-15T10:30:00Z"
}
```

---

## 8. Versioning and Compatibility

### Forward Compatibility

The SDK SHOULD ignore unknown fields in the artifact. This allows newer compilers to add fields without breaking older SDKs.

### Backward Compatibility

The SDK MUST reject artifacts with a `version` major number it does not support. Minor and patch version differences are acceptable.

### Version History

| Version | Changes |
|---|---|
| `0.1.0` | Initial specification |
