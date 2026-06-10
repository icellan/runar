# Bitcoin Script Static Analyzer — Cross-Tier Specification

Status: NORMATIVE. This document is the single source of truth for the
Rúnar Bitcoin Script static analyzer. Every tier (TypeScript, Go, Rust,
Python, Zig, Ruby, Java) MUST produce byte-identical `expected-analyzer-report.json`
output for the same input hex script.

The TypeScript implementation at `packages/runar-testing/src/analyzer/`
is the reference and was used to generate the canonical fixture goldens
under `conformance/analyzer/<fixture>/expected-analyzer-report.json`.
Non-TS tier implementers MUST NOT read the TS reference source while
porting — this spec is the contract. The goldens are the only oracle.

---

## 1. Purpose

The analyzer reads a compiled, hex-encoded Bitcoin Script (the *locking*
script produced by the Rúnar compiler) and reports a structured set of
findings about stack safety, spending-path correctness, signature
verification hygiene, and opcode concerns. It is independent of which
compiler tier produced the script — the input is bytes.

The analyzer is **static**: it does not execute the script. It performs
abstract interpretation using symbolic stack depths and enumerates
spending paths through the IF/ELSE control flow.

---

## 2. Public API

Each tier MUST expose a function with the following effective signature
(naming may follow tier conventions: `analyze_script` in Python/Ruby,
`AnalyzeScript` in Go, etc.):

```text
analyzeScript(hexScript: string, options?: AnalyzeOptions) -> AnalysisResult
```

- `hexScript` — the locking script encoded as lowercase hex. Whitespace
  is permitted and stripped; the canonical normalized form is
  lowercase-hex with no whitespace.
- `options.rawScriptSpans` — optional list of byte ranges produced by
  `raw_script` ANF nodes. See §6 for behavior.

The CLI / file emission MUST also be provided per tier in a manner
sufficient for the conformance runner to consume (see §11).

### 2.1 Empty input

If the normalized hex is empty (`""`), the analyzer returns an
`AnalysisResult` with:
- `script = ""`, `scriptSize = 0`
- `findings = [{ severity: "error", code: "INVALID_TERMINAL_STACK", message: "Empty script — no opcodes to execute" }]`
- `paths = []`
- `summary = { totalPaths: 0, reachablePaths: 0, pathsWithCheckSig: 0, pathsWithoutCheckSig: 0, maxStackDepth: 0, scriptSizeBytes: 0 }`

---

## 3. On-disk JSON Schema (`expected-analyzer-report.json`)

The fixture goldens at `conformance/analyzer/<fixture>/expected-analyzer-report.json`
use this schema. Every tier's emitter MUST produce byte-identical JSON.

### 3.1 Top-level object — key order

Keys MUST appear in this exact order (regardless of language map
semantics):

1. `"script"` — string. Normalized lowercase hex of the input script.
2. `"scriptSize"` — integer. Byte length of the script.
3. `"findings"` — array of Finding objects (see §3.2).
4. `"paths"` — array of ExecutionPath objects (see §3.3).
5. `"summary"` — Summary object (see §3.4).

### 3.2 Finding object — key order

Keys MUST appear in this exact order; OPTIONAL keys are OMITTED when
absent (never `null`, never `""`, never `0`):

1. `"severity"` — string, one of `"error" | "warning" | "info"`.
2. `"code"` — string, one of the stable finding codes in §5.
3. `"message"` — string, human-readable message. The exact wording is
   normative (see §5 for canonical message templates).
4. `"offset"` — OPTIONAL integer. Byte offset of the opcode in the script.
5. `"opcode"` — OPTIONAL string. Opcode name at that offset (see §4 for naming).
6. `"path"` — OPTIONAL string. Path descriptor (see §7.3).

### 3.3 ExecutionPath object — key order

1. `"id"` — integer. Sequential path identifier starting at 0.
2. `"description"` — string. Human-readable description (see §7.3).
3. `"branchChoices"` — array of booleans. Decisions for each `OP_IF`/`OP_NOTIF`
   encountered in source order. Element type is JSON boolean (`true`/`false`).
4. `"reachable"` — boolean. Always `true` in the current spec (reserved for
   future dead-branch detection).
5. `"hasCheckSig"` — boolean.
6. `"stackDepthAtEnd"` — integer (signed). May be negative — see §8.

### 3.4 Summary object — key order

1. `"totalPaths"` — integer.
2. `"reachablePaths"` — integer.
3. `"pathsWithCheckSig"` — integer.
4. `"pathsWithoutCheckSig"` — integer.
5. `"maxStackDepth"` — integer (signed; matches §8 semantics).
6. `"scriptSizeBytes"` — integer.

### 3.5 JSON formatting rules (determinism)

- **No floating-point.** All numeric fields are JSON integers (no `1.0`,
  no `1e3`).
- **Integer encoding.** All integers in this schema fit in JS
  `Number.MAX_SAFE_INTEGER` (2^53−1); they MUST be encoded as bare JSON
  numbers (e.g. `42`, `-1`), not decimal strings.
- **Indentation.** Two-space indentation. UTF-8, no BOM, LF line endings.
- **Trailing newline.** Exactly one `\n` at end of file.
- **Array element separation.** Standard JSON pretty-print: `,\n` between
  array elements, with the closing `]` on its own line aligned with the
  opening `[`. Empty arrays serialize as `[]` (no newline inside).
- **Object key separation.** Each key on its own line, `,\n` after each
  pair except the last; closing `}` aligned with the opener. Empty objects
  serialize as `{}`.
- **Key separator.** `": "` (colon + single space) between key and value.
- **String escaping.** RFC 8259. Use `\"`, `\\`, `\b`, `\f`, `\n`, `\r`,
  `\t` for the standard control characters; non-ASCII characters MAY be
  emitted verbatim as UTF-8 (no `\uXXXX` escaping required). Solidus `/`
  is NOT escaped.
- **No `null` values.** Optional fields that are absent are omitted from
  the object (`"offset"`, `"opcode"`, `"path"`).

### 3.6 Reference example (linear stateful contract)

```json
{
  "script": "76a9148f...88ac",
  "scriptSize": 25,
  "findings": [
    {
      "severity": "info",
      "code": "CODESEPARATOR_PRESENT",
      "message": "OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise",
      "offset": 17,
      "opcode": "OP_CODESEPARATOR"
    }
  ],
  "paths": [
    {
      "id": 0,
      "description": "linear (no branches)",
      "branchChoices": [],
      "reachable": true,
      "hasCheckSig": true,
      "stackDepthAtEnd": -2
    }
  ],
  "summary": {
    "totalPaths": 1,
    "reachablePaths": 1,
    "pathsWithCheckSig": 1,
    "pathsWithoutCheckSig": 0,
    "maxStackDepth": 0,
    "scriptSizeBytes": 25
  }
}
```

---

## 4. Opcode naming

The analyzer carries opcode names in `findings[].opcode` and
`paths[].description`. Names MUST follow the BSV opcode table; see
`spec/opcodes.md` for the full enumeration. The following rules govern
canonical name selection in the analyzer's output:

- For aliased opcodes (`OP_0`/`OP_FALSE` at `0x00`, `OP_1`/`OP_TRUE` at
  `0x51`), the canonical names are `OP_0` and `OP_1` respectively.
- For unknown bytes (no opcode mapping), name is
  `OP_UNKNOWN(0xNN)` where `NN` is the byte value as lowercase
  two-digit hex.
- Push operations:
  - Direct push (1..75 bytes, opcodes `0x01..0x4b`): name is
    `PUSH_<n>` where `n` is the decimal data length. (E.g. `PUSH_20`,
    `PUSH_72`.)
  - `OP_PUSHDATA1` (0x4c), `OP_PUSHDATA2` (0x4d), `OP_PUSHDATA4` (0x4e)
    keep their canonical names regardless of payload length.
  - `OP_1NEGATE`, `OP_0`, `OP_1`..`OP_16`: their canonical names.
- The synthetic raw-span step (see §6) is named `RAW_SPAN`.

### 4.1 BSV opcode table (canonical)

The full byte → canonical name mapping the analyzer uses:

```
0x00 OP_0          0x4c OP_PUSHDATA1     0x4d OP_PUSHDATA2     0x4e OP_PUSHDATA4
0x4f OP_1NEGATE    0x51 OP_1             0x52 OP_2             0x53 OP_3
0x54 OP_4          0x55 OP_5             0x56 OP_6             0x57 OP_7
0x58 OP_8          0x59 OP_9             0x5a OP_10            0x5b OP_11
0x5c OP_12         0x5d OP_13            0x5e OP_14            0x5f OP_15
0x60 OP_16
0x61 OP_NOP        0x63 OP_IF            0x64 OP_NOTIF         0x67 OP_ELSE
0x68 OP_ENDIF      0x69 OP_VERIFY        0x6a OP_RETURN
0x6b OP_TOALTSTACK 0x6c OP_FROMALTSTACK
0x6d OP_2DROP      0x6e OP_2DUP          0x6f OP_3DUP          0x70 OP_2OVER
0x71 OP_2ROT       0x72 OP_2SWAP         0x73 OP_IFDUP         0x74 OP_DEPTH
0x75 OP_DROP       0x76 OP_DUP           0x77 OP_NIP           0x78 OP_OVER
0x79 OP_PICK       0x7a OP_ROLL          0x7b OP_ROT           0x7c OP_SWAP
0x7d OP_TUCK
0x7e OP_CAT        0x7f OP_SPLIT         0x80 OP_NUM2BIN       0x81 OP_BIN2NUM
0x82 OP_SIZE
0x83 OP_INVERT     0x84 OP_AND           0x85 OP_OR            0x86 OP_XOR
0x87 OP_EQUAL      0x88 OP_EQUALVERIFY
0x8b OP_1ADD       0x8c OP_1SUB          0x8f OP_NEGATE        0x90 OP_ABS
0x91 OP_NOT        0x92 OP_0NOTEQUAL     0x93 OP_ADD           0x94 OP_SUB
0x95 OP_MUL        0x96 OP_DIV           0x97 OP_MOD           0x98 OP_LSHIFT
0x99 OP_RSHIFT     0x9a OP_BOOLAND       0x9b OP_BOOLOR        0x9c OP_NUMEQUAL
0x9d OP_NUMEQUALVERIFY 0x9e OP_NUMNOTEQUAL 0x9f OP_LESSTHAN    0xa0 OP_GREATERTHAN
0xa1 OP_LESSTHANOREQUAL 0xa2 OP_GREATERTHANOREQUAL 0xa3 OP_MIN 0xa4 OP_MAX
0xa5 OP_WITHIN
0xa6 OP_RIPEMD160  0xa7 OP_SHA1          0xa8 OP_SHA256        0xa9 OP_HASH160
0xaa OP_HASH256    0xab OP_CODESEPARATOR
0xac OP_CHECKSIG   0xad OP_CHECKSIGVERIFY 0xae OP_CHECKMULTISIG 0xaf OP_CHECKMULTISIGVERIFY
```

Any byte not listed above (including `0x62`, `0x65`, `0x66`, `0x89`,
`0x8a`, `0x8d`, `0x8e`, and `0x50` etc.) is unknown to the analyzer
and renders as `OP_UNKNOWN(0xNN)`.

---

## 5. Stable finding codes

The set of codes the analyzer emits is **fixed**. Implementations MUST
NOT introduce new codes without updating this spec.

Severity is assigned per code (never varies by context).

| Code                          | Severity | Description                                        |
|-------------------------------|----------|----------------------------------------------------|
| `STACK_UNDERFLOW`             | error    | An opcode requires more items than available.      |
| `INVALID_TERMINAL_STACK`      | error    | Empty script (no opcodes to execute).              |
| `UNBALANCED_IF_ENDIF`         | error    | OP_IF without OP_ENDIF, or stray OP_ELSE/OP_ENDIF. |
| `INCONSISTENT_BRANCH_DEPTH`   | warning  | IF/ELSE branches leave different stack depths.    |
| `UNREACHABLE_AFTER_RETURN`    | warning  | Opcode appears after OP_RETURN in linear flow.    |
| `UNCONDITIONALLY_SUCCEEDS`    | warning  | A path contains no verification opcode.            |
| `NO_SIG_CHECK`                | warning  | A reachable path has no CHECKSIG/CHECKMULTISIG.    |
| `CHECKSIG_RESULT_DROPPED`     | warning  | OP_CHECKSIG immediately followed by OP_DROP.       |
| `CODESEPARATOR_PRESENT`       | info     | OP_CODESEPARATOR present (expected for stateful). |
| `INEFFICIENT_PUSH`            | info     | A push uses a longer encoding than necessary.      |
| `LARGE_SCRIPT`                | info     | Script size exceeds the LARGE_SCRIPT threshold.    |
| `PATHS_TRUNCATED`             | warning  | Number of paths exceeded MAX_PATHS (256).          |

### 5.1 Canonical message templates

The exact `message` strings the analyzer emits. Placeholders in
`<angle brackets>` are substituted; everything else is literal,
including punctuation (em dashes `—` are U+2014).

- `STACK_UNDERFLOW`: `<opName> requires <pops> stack item(s) but only <depth> available`
- `INVALID_TERMINAL_STACK` (empty script): `Empty script — no opcodes to execute`
- `UNBALANCED_IF_ENDIF`:
  - Stray ELSE: `OP_ELSE without matching OP_IF`
  - Stray ENDIF: `OP_ENDIF without matching OP_IF`
  - Unclosed IF/NOTIF: `<opName> at offset <offset> has no matching OP_ENDIF`
- `INCONSISTENT_BRANCH_DEPTH`:
  - With ELSE: `IF/ELSE branches leave different stack depths (THEN: <t>, ELSE: <e>) — code after OP_ENDIF will see a depth that depends on which branch ran`
  - Without ELSE: `OP_IF body has net stack delta <d>; without an OP_ELSE the depth after OP_ENDIF depends on the branch condition`
- `UNREACHABLE_AFTER_RETURN`: `Unreachable opcode <opName> after OP_RETURN`
- `UNCONDITIONALLY_SUCCEEDS`: `Execution path has no verification opcode — any unlocking input will satisfy it`
- `NO_SIG_CHECK`: `Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)`
- `CHECKSIG_RESULT_DROPPED`: `<opName> result is dropped by <nextOpName> — signature check has no effect`
- `CODESEPARATOR_PRESENT`: `OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise`
- `INEFFICIENT_PUSH`:
  - `pushdata1` of ≤75-byte data: `OP_PUSHDATA1 used for <n>-byte data — direct push (opcode 0x<HH>) would be more efficient`
    where `HH` is `n` as lowercase two-digit hex, zero-padded.
  - `pushdata2` of ≤255-byte data: `OP_PUSHDATA2 used for <n>-byte data — OP_PUSHDATA1 would be more efficient`
  - `pushdata4` of ≤65535-byte data: `OP_PUSHDATA4 used for <n>-byte data — OP_PUSHDATA2 would be more efficient`
- `LARGE_SCRIPT`: `Script is <n> bytes (<k> KB) — consider if this is intentional`
  where `k` is `n / 1024` formatted with **exactly one** digit after the
  decimal point, using banker-free truncation toward zero after standard
  IEEE-754 rounding of `n/1024` to one decimal. To remove ambiguity, the
  canonical formula is: `k = round_half_to_even(n * 10 / 1024) / 10`,
  rendered as `<integer>.<digit>`. (Implementations may choose any
  algorithm equivalent to JS `(n / 1024).toFixed(1)`.)
- `PATHS_TRUNCATED`: two message forms, selected by `numBranches`:
  - For `numBranches < 53` (an exact 2^N fits in a JS safe integer):
    `Script has <numBranches> branch points (2^<numBranches> = <requested> paths); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.`
    where `<requested>` is the exact `2 ** numBranches` as a decimal
    integer.
  - For `numBranches >= 53`:
    `Script has <numBranches> branch points (more than 2^53 paths); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.`
    rendered with the literal phrase `more than 2^53 paths` (no
    `<requested>` substitution). The threshold 53 matches JavaScript's
    safe-integer bound (`Number.MAX_SAFE_INTEGER == 2^53 - 1`).

  The `<numBranches>` field is the true branch count, rendered as a
  normal decimal integer. The finding is emitted iff the true count of
  paths (`2^numBranches`) exceeds `MAX_PATHS = 256`, i.e. iff
  `numBranches >= 9`.

  *(Spec ≤ 1.1 specified a `1 << numBranches` formula using JS 32-bit
  signed-shift semantics; this was a TS-reference bug that printed
  nonsense values for large branch counts and caused the truncation
  finding to be skipped when `numBranches & 31 < 9` AND
  `numBranches >= 32`. Spec 1.2 drops the quirk; see §15.)*

When a code's message references an opcode name, the canonical name
(§4) is used.

---

## 6. Push-encoding handling

The script parser consumes bytes left-to-right. Each push operation is
classified by encoding:

- **`direct`** (`pushEncoding`): opcode byte in `[0x01, 0x4b]`. The
  byte itself is the data length; data follows immediately.
- **`pushdata1`**: opcode `0x4c`, followed by 1-byte length, then data.
- **`pushdata2`**: opcode `0x4d`, followed by 2-byte little-endian
  length, then data.
- **`pushdata4`**: opcode `0x4e`, followed by 4-byte little-endian
  length, then data.
- **`opN`**: opcodes `0x00` (OP_0), `0x4f` (OP_1NEGATE), `0x51..0x60`
  (OP_1..OP_16). No data.

### 6.1 Truncated pushes

If the declared length extends past the end of the script, the parser
emits the opcode with **whatever data is available** (silently
truncated) and stops parsing. No additional finding is emitted —
truncation is observable through:

- `STACK_UNDERFLOW` findings downstream (if subsequent analysis sees a
  smaller stack effect), or
- The script's stack effect simply being short.

This matches the reference behavior; the spec does NOT introduce a
`TRUNCATED_PUSH` code.

### 6.2 Inefficient encoding

An `INEFFICIENT_PUSH` (severity `info`) is emitted when a push uses a
longer encoding than necessary:
- `pushdata1` with `dataLength <= 75`
- `pushdata2` with `dataLength <= 255`
- `pushdata4` with `dataLength <= 65535`

(Truncated pushes have `dataLength = declared length` — if the declared
length itself is within the threshold, the inefficiency finding still
applies.)

---

## 7. Path enumeration

### 7.1 Branch matching

Walk the opcode list once, maintaining a stack of open IF/NOTIF frames.
On each opcode:
- `OP_IF` (0x63) or `OP_NOTIF` (0x64): push a new frame with
  `{ifIndex: i, elseIndex: -1, isNotIf: (op == NOTIF)}`.
- `OP_ELSE` (0x67): if frame stack is empty, emit `UNBALANCED_IF_ENDIF`
  (`OP_ELSE without matching OP_IF`); else set top frame's `elseIndex = i`.
- `OP_ENDIF` (0x68): if frame stack is empty, emit
  `UNBALANCED_IF_ENDIF` (`OP_ENDIF without matching OP_IF`); else pop
  and record the completed branch `{ifIndex, elseIndex, endifIndex: i, isNotIf}`.
- After the walk, any remaining frames emit `UNBALANCED_IF_ENDIF`
  (`<opName> at offset <offset> has no matching OP_ENDIF`).

### 7.2 Path enumeration

Let `numBranches` be the count of OP_IF + OP_NOTIF opcodes in the
script.

- If structural errors exist (`UNBALANCED_IF_ENDIF`), `paths = []` and
  enumeration stops.
- If `numBranches == 0`: a single linear path is produced
  (`id: 0, description: "linear (no branches)", branchChoices: []`).
- Else: enumerate `min(2^numBranches, 256)` paths. Implementations
  MUST treat `numBranches >= 9` as the truncation condition (every
  such script has at least 512 true paths, exceeding `MAX_PATHS = 256`)
  and unconditionally bound the `combo` loop to `MAX_PATHS = 256`
  in that case. When the loop is bounded, emit a `PATHS_TRUNCATED`
  finding using the message form specified in §5.1 (the exact-decimal
  branch is used for `numBranches < 53`, the symbolic `more than 2^53`
  branch otherwise). The `2^N` count must not be computed via 32-bit
  shift arithmetic — use a 64-bit shift (safe up to `numBranches = 63`)
  or BigInt; for `numBranches >= 53` no exact count is rendered, so
  no arithmetic past the safe-integer bound is required.

The choices array for path index `combo` (0..N-1) is built as:
```text
for b in [0 .. numBranches):
  choices[b] = ((combo >> b) & 1) == 1
```

I.e., bit `b` of `combo` (LSB = first IF/NOTIF in source order)
determines that branch's choice. Path id is the running index
(`0..N-1`), and paths are emitted in this combo order.

**Bit-extraction (spec 1.2).** Since `combo < MAX_PATHS = 256`, only
the low 8 bits of `combo` are ever non-zero. The canonical formula
all tiers MUST use is:

```text
choices[b] = (b < 31) ? (((combo >> b) & 1) == 1) : false
```

The `b < 31` clamp avoids relying on language-specific behavior for
out-of-range shifts (JS / Java mask the shift count to 5 bits;
Rust panics; C is undefined). Mathematically, bits 8..(numBranches-1)
of `combo` are zero, so the clamp does not alter any reachable choice.

*(Spec ≤ 1.1 used `choices[b] = ((combo >> (b & 31)) & 1) == 1`,
deliberately replicating the JS shift-mask quirk so that bits at
positions ≥ 32 aliased back to bits at position `b & 31`. That made
the per-path `branchChoices` vectors for fixtures with `numBranches
≥ 32` (`schnorr-zkp`, `ec-demo`) artificially dense and
non-monotonic. Spec 1.2 drops the alias; goldens were regenerated.)*

### 7.3 Path description

For a linear path: `"linear (no branches)"`.

For branched paths: `"<LABEL>[<bool>] at <offset>"` joined by `" -> "`
in source order of the IF/NOTIF opcodes. `<LABEL>` is `"IF"` for
`OP_IF`, `"NOTIF"` for `OP_NOTIF`. `<bool>` is `"true"` or `"false"`.
`<offset>` is the IF/NOTIF's byte offset, decimal, no leading zeros.

Example: `"IF[true] at 5 -> NOTIF[false] at 17"`.

### 7.4 Collecting per-path opcodes

The `choices` vector has two distinct interpretations that the spec
treats separately. Implementers MUST match both — they diverge in
practice whenever an outer IF/NOTIF body is skipped.

**Indexing model (used by the path description, §7.3).** `choices[k]`
corresponds to the *k*-th OP_IF/OP_NOTIF in source order — i.e.
indexed by position in the static opcode stream. The description
includes an entry for every one of the `numBranches` IF/NOTIFs,
regardless of whether that IF/NOTIF is actually reached at run time.
This is what §7.3 means by "in source order of the IF/NOTIF opcodes":
the IF list is the full set of IFs the script contains, paired
positionally with `choices`.

**Consumption model (used while collecting executed opcodes).** Walk
the opcode list in source order with a serial "next choice" cursor
starting at `choiceIdx = 0`. When traversal *dynamically encounters*
an OP_IF/OP_NOTIF, read `choices[choiceIdx]`, advance the cursor by 1,
then act on the boolean:
- `true` → execute the THEN body, skip the ELSE body (jumping over
  the ELSE marker to ENDIF).
- `false` → skip the THEN body (jumping to ELSE+1 if present, else to
  ENDIF+1).

A skipped body's IF/NOTIF opcodes are **never visited**, so they do
NOT advance `choiceIdx`. The dynamic IF that consumes `choices[k]` may
therefore be a different source-order IF than the one `choices[k]`
"names" under the indexing model above.

**The two interpretations diverge whenever an outer IF=false (or
outer NOTIF=true) skips a body that contains nested IF/NOTIFs.** The
description still lists those skipped IFs (with their source-order
choices), but at run time the cursor jumps over them and feeds their
choice slots to the next encountered IF in the outer ELSE branch.
This is by design — the goldens were generated by the TS reference
under this split semantics, and all tiers MUST replicate it.

**Worked example: `stateful-counter` path id 4, `choices = [F, F, T, F, F, F, F]`.**
The script has 7 IF/NOTIFs in source order; `choices[2] = true` names
an IF at source position 128. Dynamic execution proceeds:
- Encounter IF #0 → read `choices[0] = false`, cursor → 1. Skip the
  THEN body (which contains IF #1 and IF #2 at source position 128),
  jump past ELSE.
- Encounter the next IF in the outer ELSE branch → read
  `choices[1] = false`, cursor → 2. (This IF is IF #3 in source
  order — NOT IF #2.)
- Encounter the next IF → read `choices[2] = true`, cursor → 3.
  Execute its THEN body. (Source-order this is IF #4 or beyond,
  not the "IF at source position 128" the description names.)
- …and so on.

So the description's `"IF[true] at 128"` (mechanical from
source-order index 2) does not correspond to the IF that actually
ran on `choices[2]` (which is a later IF in the outer ELSE). This
inconsistency is intentional and matches the canonical goldens.

If `choices` is shorter than the IF count (cannot happen in correct
enumeration) **and** as a defensive default, missing choices are
treated as `true`.

Opcodes `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF` themselves are
**not** included in the collected per-path opcode list. Everything
else is included if executed.

Special case (linear, `numBranches == 0`): the collected list is the
full opcode list with `OP_IF`/`OP_NOTIF`/`OP_ELSE`/`OP_ENDIF` filtered
out (none should be present, but the filter is defensive).

### 7.5 Path-derived findings

Each collected per-path opcode list undergoes linear stack analysis
(§8) and unconditional-success detection.

`hasCheckSig` for the path is true iff any opcode in the collected
list is `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKMULTISIG`, or
`OP_CHECKMULTISIGVERIFY`.

`stackDepthAtEnd` is the depth from the linear analysis (initial
depth = 0).

`UNCONDITIONALLY_SUCCEEDS` is emitted when the collected list is
non-empty and contains **none** of the following verification opcodes:
- `OP_VERIFY` (0x69), `OP_RETURN` (0x6a)
- `OP_EQUALVERIFY` (0x88), `OP_NUMEQUALVERIFY` (0x9d)
- `OP_CHECKSIG` (0xac), `OP_CHECKSIGVERIFY` (0xad)
- `OP_CHECKMULTISIG` (0xae), `OP_CHECKMULTISIGVERIFY` (0xaf)

The finding's `path` field is the path description (§7.3).

### 7.6 Inconsistent branch depth

For each balanced branch:
- If `elseIndex < 0` (no ELSE): compute the flat delta of the body
  `(ifIndex+1, endifIndex)`. If non-zero, emit `INCONSISTENT_BRANCH_DEPTH`
  with `offset = endifOp.offset`, `opcode = "OP_ENDIF"`, and the
  no-ELSE message variant.
- Else: compute flat deltas of `(ifIndex+1, elseIndex)` and
  `(elseIndex+1, endifIndex)`. If different, emit
  `INCONSISTENT_BRANCH_DEPTH` with `offset = endifOp.offset`, opcode =
  `"OP_ENDIF"`, and the with-ELSE message variant.

Flat delta = sum of `(pushes - pops)` over each opcode in the range,
treating each as its static stack effect (§8.1). If the range contains
a nested `OP_IF`/`OP_NOTIF`, the delta is undefined (skip — emit
nothing for this branch). `OP_ELSE`/`OP_ENDIF` opcodes inside the range
(should not appear in well-structured input) contribute 0.

---

## 8. Stack analysis

### 8.1 Per-opcode stack effects (`(pops, pushes)`)

Conservative integer summary. The pre-shift depth requirement is `pops`;
the post-shift depth is `depth - pops + pushes`. For variable-arity
opcodes (`OP_CHECKMULTISIG`, etc.) we use the minimum.

```
OP_NOP            (0,0)   OP_IF             (1,0)   OP_NOTIF          (1,0)
OP_ELSE           (0,0)   OP_ENDIF          (0,0)   OP_VERIFY         (1,0)
OP_RETURN         (0,0)
OP_TOALTSTACK     (1,0)   OP_FROMALTSTACK   (0,1)
OP_2DROP          (2,0)   OP_2DUP           (2,4)   OP_3DUP           (3,6)
OP_2OVER          (4,6)   OP_2ROT           (6,6)   OP_2SWAP          (4,4)
OP_IFDUP          (1,1)   OP_DEPTH          (0,1)   OP_DROP           (1,0)
OP_DUP            (1,2)   OP_NIP            (2,1)   OP_OVER           (2,3)
OP_PICK           (1,1)   OP_ROLL           (1,0)   OP_ROT            (3,3)
OP_SWAP           (2,2)   OP_TUCK           (2,3)
OP_CAT            (2,1)   OP_SPLIT          (2,2)   OP_NUM2BIN        (2,1)
OP_BIN2NUM        (1,1)   OP_SIZE           (1,2)
OP_INVERT         (1,1)   OP_AND            (2,1)   OP_OR             (2,1)
OP_XOR            (2,1)   OP_EQUAL          (2,1)   OP_EQUALVERIFY    (2,0)
OP_1ADD           (1,1)   OP_1SUB           (1,1)   OP_NEGATE         (1,1)
OP_ABS            (1,1)   OP_NOT            (1,1)   OP_0NOTEQUAL      (1,1)
OP_ADD            (2,1)   OP_SUB            (2,1)   OP_MUL            (2,1)
OP_DIV            (2,1)   OP_MOD            (2,1)   OP_LSHIFT         (2,1)
OP_RSHIFT         (2,1)   OP_BOOLAND        (2,1)   OP_BOOLOR         (2,1)
OP_NUMEQUAL       (2,1)   OP_NUMEQUALVERIFY (2,0)   OP_NUMNOTEQUAL    (2,1)
OP_LESSTHAN       (2,1)   OP_GREATERTHAN    (2,1)   OP_LESSTHANOREQUAL(2,1)
OP_GREATERTHANOREQUAL(2,1) OP_MIN           (2,1)   OP_MAX            (2,1)
OP_WITHIN         (3,1)
OP_RIPEMD160      (1,1)   OP_SHA1           (1,1)   OP_SHA256         (1,1)
OP_HASH160        (1,1)   OP_HASH256        (1,1)
OP_CHECKSIG       (2,1)   OP_CHECKSIGVERIFY (2,0)
OP_CHECKMULTISIG  (3,1)   OP_CHECKMULTISIGVERIFY (3,0)
```

- Any push operation: `(0, 1)`.
- `OP_CODESEPARATOR` (0xab): `(0, 0)` — not in the table; falls
  through to default.
- Any opcode not in the table: `(0, 0)`.
- The synthetic raw-span step: `(span.inArity, span.outArity)`.

### 8.2 Linear analysis algorithm

Input: a list of parsed opcodes representing a single execution path,
plus an `initialDepth` (default 0).

Maintain `depth`, `maxDepth`, `findings`, and an `afterReturn` flag
initially false.

For each opcode in order:
1. If `afterReturn`: emit `UNREACHABLE_AFTER_RETURN` finding with
   `offset = op.offset`, `opcode = op.name`; `continue`.
2. If `op.opcode == OP_RETURN` (0x6a): set `afterReturn = true`;
   `continue`.
3. Get `(pops, pushes)` (§8.1).
4. **Underflow check.** Emit `STACK_UNDERFLOW` only when
   `initialDepth > 0 && depth < pops`. (Locking scripts analyzed in
   isolation start at depth 0; the unlocking script supplies the
   initial items, so a "negative" depth represents draws from the
   unlocking input and is NOT an underflow. This guard is critical
   for matching the goldens.)
5. `depth = depth - pops + pushes`.
6. If `depth > maxDepth`: `maxDepth = depth`.

Final state's `depth` is the path's `stackDepthAtEnd`. Findings flow
upward to the caller; the path analyzer prepends each finding's
`path` field with the path description.

### 8.3 Summary

```
totalPaths        = paths.length
reachablePaths    = paths filter (p.reachable == true)
pathsWithCheckSig = reachable paths filter (p.hasCheckSig == true)
pathsWithoutCheckSig = reachable paths filter (p.hasCheckSig == false)
maxStackDepth     = max(0, max(p.stackDepthAtEnd over all paths))
                    // defaults to 0 if paths is empty
scriptSizeBytes   = byte length of normalized hex / 2
```

`maxStackDepth` is `max` of `stackDepthAtEnd` (NOT `maxDepth`) across
all paths, **floored at 0**. The reducer is seeded with `0`, so when
every path ends with a depth below zero (a normal occurrence when the
script consumes unlocking-script items), `maxStackDepth` is clamped to
`0`. The lower bound IS `0`; `maxStackDepth` is never negative.

The canonical TS reduction is
`paths.reduce((m, p) => Math.max(m, p.stackDepthAtEnd), 0)`. Equivalent
formulations in other tiers MUST produce the same value. If `paths` is
empty, `maxStackDepth = 0` (the seed). Verified against all 8 canonical
goldens (e.g. `basic-p2pkh`: `stackDepthAtEnd: -1`, `maxStackDepth: 0`;
`stateful-counter`: all per-path `stackDepthAtEnd` negative,
`maxStackDepth: 0`; `schnorr-zkp`: positive max-over-paths,
`maxStackDepth: 1023`).

Per-path `stackDepthAtEnd` is unaffected by this clamp and may be
negative — see §14.

---

## 9. Signature hygiene

- **NO_SIG_CHECK**: For each reachable path where `hasCheckSig == false`,
  emit one finding (severity `warning`).
- **CHECKSIG_RESULT_DROPPED**: Walk the opcode list linearly. For each
  index `i` where `i+1 < opcodes.length`, if `opcodes[i]` is `OP_CHECKSIG`
  or `OP_CHECKMULTISIG` AND `opcodes[i+1]` is `OP_DROP`, emit one finding
  with `offset = opcodes[i].offset`, `opcode = opcodes[i].name`.

  Note: only `OP_CHECKSIG` and `OP_CHECKMULTISIG` are flagged (NOT the
  `*VERIFY` variants — they don't leave a result on the stack).

---

## 10. Opcode concerns

- **LARGE_SCRIPT**: Emit once if `scriptSizeBytes > 500_000`.
- **CODESEPARATOR_PRESENT**: Emit one finding per `OP_CODESEPARATOR`
  (byte `0xab`) found in the opcode stream.
- **INEFFICIENT_PUSH**: Emit one finding per inefficient push (see §6.2).

---

## 11. Orchestration (entry point algorithm)

```
analyzeScript(hexScript, options):
  normalizedHex = hexScript.replace(/\s/, "").toLowerCase()
  scriptSizeBytes = normalizedHex.length / 2

  if scriptSizeBytes == 0:
    return empty-script result (§2.1)

  opcodes = parseScript(normalizedHex)
  if options.rawScriptSpans not empty:
    opcodes = collapseRawScriptSpans(opcodes, options.rawScriptSpans)

  allFindings = []

  // Step 1: path analysis (produces paths + structural findings + per-path findings)
  { paths, findings: pathFindings } = analyzePaths(opcodes)
  allFindings.append(pathFindings)

  // Step 2: linear stack analysis fallback (only if zero paths AND
  //         no UNBALANCED_IF_ENDIF — i.e. parser anomaly or some other
  //         no-paths-but-no-structural-error case).
  if paths.length == 0 AND no finding has code UNBALANCED_IF_ENDIF:
    linearResult = analyzeStackLinear(opcodes, initialDepth=0)
    allFindings.append(linearResult.findings)

  // Step 3: sig hygiene
  allFindings.append(analyzeSigHygiene(opcodes, paths))

  // Step 4: opcode concerns
  allFindings.append(analyzeOpcodeConcerns(opcodes, scriptSizeBytes))

  // Build summary
  summary = { totalPaths, reachablePaths, pathsWithCheckSig,
              pathsWithoutCheckSig, maxStackDepth, scriptSizeBytes }

  return {
    script: normalizedHex,
    scriptSize: scriptSizeBytes,
    findings: sortFindings(allFindings),
    paths,
    summary,
  }
```

### 11.1 Sort order for `findings`

Stable sort by `(severityRank, offsetRank)` where:
- `severityRank`: `error → 0`, `warning → 1`, `info → 2`. Lower
  ranks sort earlier.
- `offsetRank`: `offset` if present, else `+Infinity` (offset-less
  findings sort to the end within their severity bucket).

Ties are broken by **original insertion order** (stable sort). This
means within the same severity and offset, findings appear in the
order they were appended in §11's orchestration: pathFindings (in
appearance order: structural, then per-path, then branch-depth) →
[linear-fallback findings] → sig hygiene → opcode concerns.

Implementers MUST use a stable sort (e.g. JS `Array.prototype.sort` is
stable per ES2019; Go `sort.SliceStable`; Python `list.sort`; Rust
`Vec::sort_by`; Java `List.sort`; Ruby `sort_by`; Zig `std.sort.block`
is not stable — Zig MUST use `std.mem.sortUnstable` only after pairing
each finding with its original index and breaking ties on that index).

---

## 12. Raw script spans (§2 option)

Each `RawScriptSpan` is `{ offset, length, inArity, outArity }`.

`collapseRawScriptSpans(opcodes, spans)`:

1. If `spans.length == 0`, return `opcodes` unchanged.
2. Sort `spans` by `offset` ascending.
3. Walk `opcodes` in order. Maintain `spanIdx = 0`.
4. For each opcode `op`:
   - Advance `spanIdx` past any span whose end (`offset+length`) is
     `<= op.offset`.
   - If `spanIdx >= spans.length`: append `op` to output; continue.
   - Let `span = spans[spanIdx]`, `spanEnd = span.offset + span.length`.
   - If `op.offset + op.size <= span.offset`: opcode is entirely before
     the span — append it; continue.
   - If `op.offset >= span.offset && op.offset + op.size <= spanEnd`:
     opcode is entirely inside the span — drop it. If the last emitted
     output is **not** the synthetic step for `span.offset`, append the
     synthetic step:
     ```
     { offset: span.offset, opcode: -1, name: "RAW_SPAN",
       size: span.length, rawSpanArity: [span.inArity, span.outArity] }
     ```
   - Otherwise (partial overlap, degenerate input): drop the opcode;
     emit the synthetic step once if not already.
5. Spans that extend past the parsed stream are silently ignored.

The synthetic step has opcode `-1` (outside the legal byte range) so
no `op.opcode == 0xNN` check ever matches it. Stack-effect tracking
reads `rawSpanArity`. Push-encoding analysis, CODESEPARATOR detection,
CHECKSIG hygiene, and IF/ELSE structure all naturally ignore it.

The 8 canonical fixtures DO NOT use `rawScriptSpans` — the spans
machinery is part of the API surface but is exercised only by
internal tier-local tests, not by the cross-tier conformance
goldens. (Each tier MUST still implement and unit-test the
collapse algorithm; the goldens just don't depend on it.)

---

## 13. Conformance integration

The conformance subsuite at `conformance/analyzer/` works as follows:

1. Each fixture name appears as `conformance/analyzer/<name>/expected-analyzer-report.json`,
   the canonical golden (generated from the TS reference).
2. The input hex is taken from `conformance/tests/<name>/expected-script.hex`
   — the existing compiler-conformance hex output. Trailing whitespace
   is stripped before passing to the analyzer.
3. Each tier exposes a thin CLI or wrapper that:
   - reads a hex script from a file (or stdin),
   - calls `analyzeScript(hex)` (no rawScriptSpans),
   - writes the JSON report to stdout (or a specified file), using
     the formatting in §3.5.
4. The driver `conformance/analyzer/run.ts` (or sibling) iterates
   over `(fixture, tier)` pairs, invokes the tier's analyzer, and
   diffs the JSON output against the golden. Any byte-level
   mismatch is a failure.

The 8 canonical fixtures are:
- `basic-p2pkh`
- `escrow`
- `stateful-counter`
- `auction`
- `covenant-vault`
- `ec-demo`
- `schnorr-zkp`
- `if-else`

(`multisig` is intentionally deferred — it ships in a follow-up commit
after BUG-009 lands and regenerates that fixture's hex.)

---

## 14. Determinism notes for porters

The following pitfalls have caused bugs in past cross-tier ports;
avoid them:

- **Map iteration order.** Never iterate over a tier-native map/dict
  when building output JSON. Always sort, or use a list.
- **JSON key ordering.** Do not rely on `json.Marshal`/`json.dumps`
  default key order. Build the output object/dictionary in §3 order
  explicitly (or use an ordered serializer with the §3 key list).
- **Integer overflow.** Stack depths, offsets, and path IDs fit in
  32-bit signed. No need for `bigint`.
- **Negative depths.** Per-path `stackDepthAtEnd` can be negative
  (when a path consumes more unlocking-script items than it pushes).
  Use signed types. Summary `maxStackDepth` is floored at `0` (§8.3)
  so it is never negative, but the intermediate `max(stackDepthAtEnd)`
  before flooring may be — keep the reduction in signed arithmetic
  before clamping.
- **Stable sort.** §11.1 mandates stable. Zig's default is unstable —
  see the note in §11.1.
- **`PATHS_TRUNCATED` cap.** Hardcoded at 256 (NOT 4096, NOT
  configurable).
- **`LARGE_SCRIPT` threshold.** Hardcoded at 500_000 bytes.
- **Em dashes.** The literal `—` (U+2014) appears in several message
  templates; do not substitute `--` or `-`.
- **`(n/1024).toFixed(1)` formatting.** Match JS `toFixed(1)` semantics
  exactly. In particular, `1024.toFixed(1) == "1.0"` and
  `1500.toFixed(1) == "1.5"`. The 8 canonical fixtures are all well
  under 500 KB, so `LARGE_SCRIPT` is not exercised by the goldens —
  but tier unit tests should cover the formatting.
- **Path ID = index.** Path IDs are exactly `0, 1, 2, ...` in the
  enumeration order (§7.2 combo order).

---

## 15. Version

Spec version: 1.2 (2026-05-28). All goldens at
`conformance/analyzer/*/expected-analyzer-report.json` were produced
under this version.

**1.2 (2026-05-28).** Drops the JS-32-bit-shift quirk in `PATHS_TRUNCATED`
arithmetic (§5.1) and path enumeration (§7.2). The `<requested>` field
is now rendered as `2^<numBranches> = <X> paths` for
`numBranches < 53` (exact decimal) and the symbolic phrase
`more than 2^53 paths` for `numBranches >= 53`. Path enumeration
correctly emits `PATHS_TRUNCATED` whenever the true count of paths
exceeds `MAX_PATHS = 256` (the previous wrap-mod-32 formula caused
`schnorr-zkp` — 514 branches → wrapped to 4 paths — to skip the
finding entirely). The per-path `choices` vector is built with
`choices[b] = (b < 31) ? ((combo >> b) & 1 == 1) : false`, removing
the prior aliasing that made bits at positions ≥ 32 mirror bits at
position `b & 31`. The goldens for `schnorr-zkp` and `ec-demo` are
regenerated under this version.

**1.1 (2026-05-27).** Documentation-only refresh that patched three
ambiguities surfaced by the 6 GAP-008 tier ports (maxStackDepth floor
at 0 in §8.3 + §3.6 + §14; split-interpretation of `choices` in §7.4;
JS 32-bit right-shift mask in §7.2). Analyzer output, finding codes,
and goldens were unchanged from 1.0.
