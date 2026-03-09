/**
 * Compile PriceBet and dump every intermediate representation:
 *   1. Parsed AST (contract structure)
 *   2. ANF IR (flattened let-bindings)
 *   3. Stack IR (stack machine ops)
 *   4. Bitcoin Script ASM (human-readable opcodes)
 *   5. Bitcoin Script Hex (raw bytes)
 *   6. Artifact JSON (deployment bundle)
 *   7. Annotated walkthrough of the locking + unlocking scripts
 *   8. Transaction structure explanation
 *
 * Run:  npx tsx end2end-example/ts/dump-compiled.ts
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PriceBet.runar.ts'), 'utf8');

// ─── Compile with baked constructor args ────────────────────────────────────
const ALICE_PK = '02' + 'aa'.repeat(32);
const BOB_PK   = '02' + 'bb'.repeat(32);
const ORACLE_PK_INT = 12345n;
const STRIKE = 50000n;

const result = compile(source, {
  fileName: 'PriceBet.runar.ts',
  constructorArgs: {
    alicePubKey:  ALICE_PK,
    bobPubKey:    BOB_PK,
    oraclePubKey: ORACLE_PK_INT,
    strikePrice:  STRIKE,
  },
});

if (!result.success) {
  console.error('Compilation failed:');
  for (const d of result.diagnostics) {
    console.error(`  [${d.severity}] ${d.message}`);
  }
  process.exit(1);
}

// ─── Helper: pretty-print with bigint support ───────────────────────────────
function toJSON(obj: unknown): string {
  return JSON.stringify(obj, (_, v) => typeof v === 'bigint' ? `${v}n` : v, 2);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. PARSED AST
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  1. PARSED AST  (Pass 1: Source → Rúnar AST)');
console.log('═'.repeat(78));
const c = result.contract!;
console.log(`Contract:    ${c.name}`);
console.log(`Base class:  ${c.parentClass}`);
console.log(`Properties:  ${c.properties.map(p => `${p.readonly ? 'readonly ' : ''}${p.name}: ${p.type.kind === 'primitive_type' ? p.type.name : '?'}`).join(', ')}`);
console.log(`Methods:`);
for (const m of c.methods) {
  const params = m.params.map(p => `${p.name}: ${p.type.kind === 'primitive_type' ? p.type.name : '?'}`).join(', ');
  console.log(`  ${m.visibility} ${m.name}(${params})`);
}
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
//  2. ANF IR
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  2. ANF IR  (Pass 4: AST → A-Normal Form)');
console.log('═'.repeat(78));
const anf = result.anf!;
console.log(`Contract: ${anf.contractName}`);
console.log(`Properties: ${anf.properties.map(p => p.name).join(', ')}`);
for (const m of anf.methods) {
  console.log(`\n  method ${m.isPublic ? 'public' : 'private'} ${m.name}(${m.params.map(p => p.name).join(', ')}):`);
  printBindings(m.body, '    ');
}
console.log();

function printBindings(bindings: any[], indent: string) {
  for (const b of bindings) {
    const v = b.value;
    switch (v.kind) {
      case 'load_param':
        console.log(`${indent}let ${b.name} = param(${v.name})`);
        break;
      case 'load_prop':
        console.log(`${indent}let ${b.name} = this.${v.name}`);
        break;
      case 'load_const':
        console.log(`${indent}let ${b.name} = ${typeof v.value === 'string' ? `"${v.value.slice(0,20)}${v.value.length > 20 ? '...' : ''}"` : v.value}`);
        break;
      case 'bin_op':
        console.log(`${indent}let ${b.name} = ${v.left} ${v.op} ${v.right}`);
        break;
      case 'call':
        console.log(`${indent}let ${b.name} = ${v.func}(${v.args.join(', ')})`);
        break;
      case 'assert':
        console.log(`${indent}assert(${v.value})`);
        break;
      case 'if': {
        console.log(`${indent}if (${v.cond}) {`);
        printBindings(v.then, indent + '  ');
        if (v.else && v.else.length > 0) {
          console.log(`${indent}} else {`);
          printBindings(v.else, indent + '  ');
        }
        console.log(`${indent}}`);
        break;
      }
      default:
        console.log(`${indent}let ${b.name} = ${v.kind}(${toJSON(v).slice(0, 80)})`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. STACK IR
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  3. STACK IR  (Pass 5: ANF → Stack Machine Ops)');
console.log('═'.repeat(78));
const artifact = result.artifact!;
// Re-compile with IR included for inspection
// (the default compile path doesn't store stack IR in the artifact)
// So we'll print the ASM which is the readable version of the stack ops.
console.log('(Stack IR is lowered directly to ASM — see section 4)');
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
//  4. BITCOIN SCRIPT ASM
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  4. BITCOIN SCRIPT ASM  (Pass 6: Stack IR → Opcodes)');
console.log('═'.repeat(78));
const asm = result.scriptAsm!;
const asmParts = asm.split(' ');
let lineNum = 1;
let indentLevel = 0;
for (const part of asmParts) {
  if (part === 'OP_ELSE' || part === 'OP_ENDIF') indentLevel = Math.max(0, indentLevel - 1);
  const indent = '  '.repeat(indentLevel);
  console.log(`  ${String(lineNum).padStart(3)}: ${indent}${part}`);
  if (part === 'OP_IF' || part === 'OP_ELSE') indentLevel++;
  lineNum++;
}
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
//  5. BITCOIN SCRIPT HEX
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  5. BITCOIN SCRIPT HEX  (raw locking script bytes)');
console.log('═'.repeat(78));
const hex = result.scriptHex!;
console.log(`Length: ${hex.length / 2} bytes`);
// Print in 32-byte rows
for (let i = 0; i < hex.length; i += 64) {
  const offset = (i / 2).toString(16).padStart(4, '0');
  console.log(`  ${offset}: ${hex.slice(i, i + 64)}`);
}
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
//  6. ARTIFACT  (deployment bundle)
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  6. ARTIFACT  (deployment JSON)');
console.log('═'.repeat(78));
console.log(`  version:       ${artifact.version}`);
console.log(`  compiler:      ${artifact.compilerVersion}`);
console.log(`  contract:      ${artifact.contractName}`);
console.log(`  script length: ${artifact.script.length / 2} bytes`);
console.log(`  ABI:`);
console.log(`    constructor(${artifact.abi.constructor.params.map(p => `${p.name}: ${p.type}`).join(', ')})`);
for (const m of artifact.abi.methods) {
  const vis = m.isPublic ? 'public' : 'private';
  console.log(`    ${vis} ${m.name}(${m.params.map(p => `${p.name}: ${p.type}`).join(', ')})`);
}
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
//  7. ANNOTATED SCRIPT WALKTHROUGH
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  7. ANNOTATED SCRIPT WALKTHROUGH');
console.log('═'.repeat(78));
console.log(`
This is a STATELESS contract (extends SmartContract), so the entire
contract logic lives in a SINGLE locking script placed in a UTXO.

The contract has 2 public methods: settle() and cancel().
The compiler emits a METHOD DISPATCH preamble that checks a numeric
selector pushed by the spending transaction:

  selector = 0  →  settle()
  selector = 1  →  cancel()

CONSTRUCTOR ARGS ARE BAKED IN:
  alicePubKey  = ${ALICE_PK.slice(0,16)}...  (33-byte compressed pubkey)
  bobPubKey    = ${BOB_PK.slice(0,16)}...  (33-byte compressed pubkey)
  oraclePubKey = ${ORACLE_PK_INT}  (Rabin public key, integer)
  strikePrice  = ${STRIKE}  (price threshold)

These values are embedded as push-data opcodes in the locking script
at compile time. They become IMMUTABLE once the UTXO is created.

HOW THE ASM READS:

Method dispatch:
  1. The top of the scriptSig stack has the method selector.
  2. OP_DUP + push(0) + OP_NUMEQUAL + OP_IF  → if selector == 0, run settle()
  3. OP_DROP removes the selector inside the matched branch.
  4. OP_ELSE → fall through to cancel() (selector 1, the default).
  5. OP_ENDIF closes the dispatch.

Inside settle(price, rabinSig, padding, aliceSig, bobSig):
  1. Computes msg = num2bin(price, 8)
  2. Calls verifyRabinSig(msg, rabinSig, padding, oraclePubKey) → OP_VERIFY
  3. Asserts price > 0
  4. OP_IF/OP_ELSE branch: if price > strikePrice
       → OP_CHECKSIGVERIFY with aliceSig + alicePubKey
     else
       → OP_CHECKSIGVERIFY with bobSig + bobPubKey

Inside cancel(aliceSig, bobSig):
  1. OP_CHECKSIGVERIFY with aliceSig + alicePubKey
  2. OP_CHECKSIGVERIFY with bobSig + bobPubKey
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  8. TRANSACTION STRUCTURE
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  8. BITCOIN TRANSACTIONS ON-CHAIN');
console.log('═'.repeat(78));
console.log(`
┌─────────────────────────────────────────────────────────────────┐
│  TX 1: FUNDING (creates the bet UTXO)                          │
├─────────────────────────────────────────────────────────────────┤
│  Inputs:                                                        │
│    [0] Alice funds (e.g. 0.5 BSV) ─ standard P2PKH spend       │
│    [1] Bob funds   (e.g. 0.5 BSV) ─ standard P2PKH spend       │
│                                                                 │
│  Outputs:                                                       │
│    [0] PriceBet UTXO                                            │
│        satoshis:       100,000,000  (1 BSV combined)            │
│        locking script: <compiled PriceBet script>               │
│                        (${hex.length / 2} bytes, hex shown above)          │
│                                                                 │
│  The locking script contains the baked-in constructor args      │
│  (both pubkeys, oracle key, strike price) as literal push data. │
│  This UTXO can ONLY be spent by satisfying one of the two       │
│  public methods: settle() or cancel().                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  TX 2a: SETTLEMENT (oracle publishes price, winner claims)      │
├─────────────────────────────────────────────────────────────────┤
│  Input [0] spends the PriceBet UTXO with:                       │
│    scriptSig (unlocking script), pushed LEFT to RIGHT:          │
│                                                                 │
│      <bobSig>       ─ Bob's DER signature (72 bytes)            │
│      <aliceSig>     ─ Alice's DER signature (72 bytes)          │
│      <padding>      ─ Rabin padding bytes                       │
│      <rabinSig>     ─ Oracle's Rabin signature (integer)        │
│      <price>        ─ The oracle-attested price (integer)        │
│      <0>            ─ Method selector: 0 = settle()             │
│                                                                 │
│  The BSV node concatenates: scriptSig | scriptPubKey            │
│  and evaluates. The locking script:                             │
│    1. Checks selector == 0 → enters settle() branch            │
│    2. Verifies the Rabin signature over the price               │
│    3. Checks price > 0                                          │
│    4. If price > 50000 → OP_CHECKSIG(aliceSig, alicePubKey)    │
│       else             → OP_CHECKSIG(bobSig, bobPubKey)         │
│    5. Script succeeds → TX is valid → winner gets the funds     │
│                                                                 │
│  Output [0]:                                                    │
│    <winner's address>  1 BSV (minus miner fee)                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  TX 2b: CANCELLATION (both parties agree to refund)             │
├─────────────────────────────────────────────────────────────────┤
│  Input [0] spends the PriceBet UTXO with:                       │
│    scriptSig (unlocking script):                                │
│                                                                 │
│      <bobSig>       ─ Bob's DER signature                       │
│      <aliceSig>     ─ Alice's DER signature                     │
│      <1>            ─ Method selector: 1 = cancel()             │
│                                                                 │
│  The locking script:                                            │
│    1. Checks selector != 0 → enters cancel() branch            │
│    2. OP_CHECKSIG(aliceSig, alicePubKey) → verifies Alice      │
│    3. OP_CHECKSIG(bobSig, bobPubKey)     → verifies Bob        │
│    4. Both pass → TX is valid → funds returned                  │
│                                                                 │
│  Outputs:                                                       │
│    [0] Alice refund  0.5 BSV                                    │
│    [1] Bob refund    0.5 BSV                                    │
└─────────────────────────────────────────────────────────────────┘

KEY INSIGHT: The locking script is PURE VERIFICATION.
It doesn't move money — it only says YES or NO.
The spending transaction chooses where the money goes (outputs).
The script just gates whether that transaction is valid.

NO TRUSTED THIRD PARTY: The oracle only signs the price.
It cannot steal funds or choose a winner. The script logic
is immutable once deployed. The oracle's Rabin signature is
verified on-chain — if it's invalid, the script fails.
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  9. OPCODE-BY-OPCODE TRACE (cancel path — simpler to follow)
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  9. OPCODE-BY-OPCODE STACK TRACE  (cancel path)');
console.log('═'.repeat(78));
console.log(`
Scenario: Alice and Bob both agree to cancel. The spending TX pushes:
  scriptSig: <bobSig> <aliceSig> <1>

The scriptSig pushes params in declaration order (left to right), so
the last param declared is deepest on the stack. After scriptSig, the
stack is (top on right):

  [ bobSig, aliceSig, 1 ]

Then the locking script runs against this stack:

 Op#  Opcode                Stack (top → right)
 ───  ─────────────────────  ─────────────────────────────────────────────
  1   OP_DUP                [ bobSig, aliceSig, 1, 1 ]
  2   OP_0                  [ bobSig, aliceSig, 1, 1, 0 ]
  3   OP_NUMEQUAL           [ bobSig, aliceSig, 1, false ]
                            (1 != 0 → false)
  4   OP_IF                 [ bobSig, aliceSig, 1 ]
                            false → skip to OP_ELSE (cancel branch)

       ── skips settle() body (ops 5-54) ──

 55   OP_ELSE               [ bobSig, aliceSig, 1 ]
 56   OP_DROP               [ bobSig, aliceSig ]
                            drops the method selector
 57   OP_SWAP               [ aliceSig, bobSig ]
                            compiler reorders so first checkSig arg is on top
 58   push <alicePK>        [ aliceSig, bobSig, alicePK ]
                            baked-in 02aaaa... (33 bytes)
 59   OP_CHECKSIGVERIFY     [ aliceSig ]
                            pops top 2 (pubkey, sig) → verifies bobSig
                            against alicePK. Passes → continues.
                            (The compiler mapped bobSig to this position
                             via OP_SWAP at step 57.)
 60   push <bobPK>          [ aliceSig, bobPK ]
                            baked-in 02bbbb... (33 bytes)
 61   OP_CHECKSIG           [ true ]
                            pops top 2 → verifies aliceSig against bobPK.
                            Leaves TRUE on stack.
 62   OP_ENDIF              [ true ]

      Final stack has TRUE on top → script SUCCEEDS → TX is valid.

Note: OP_CHECKSIG always pops top=pubkey, top-1=sig. The compiler's
stack lowering pass (Pass 5) inserts the right OP_SWAP/OP_ROLL/OP_PICK
ops to ensure each value is at the correct stack depth when consumed.
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  10. SIZE COMPARISON
// ═══════════════════════════════════════════════════════════════════════════════
console.log('═'.repeat(78));
console.log('  10. SIZE COMPARISON');
console.log('═'.repeat(78));
console.log(`
  PriceBet locking script:  ${hex.length / 2} bytes

  For reference:
    Standard P2PKH script:    25 bytes  (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG)
    2-of-3 multisig:          ~105 bytes
    PriceBet (this contract): ${hex.length / 2} bytes

  The extra size comes from:
    - Rabin signature verification inline (~40 bytes of opcodes)
    - Two baked-in 33-byte compressed pubkeys (×2 for settle + cancel = ×4)
    - Method dispatch logic (~10 bytes)
    - If/else branching for price comparison

  At current BSV fee rates (~0.05 sat/byte), this script costs
  approximately ${Math.ceil(hex.length / 2 * 0.05)} satoshis in transaction fees to deploy.
`);
