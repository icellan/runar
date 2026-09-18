/**
 * Regression tests for GitHub issues #99 (Bug 1) and #100.
 *
 * #99 Bug 1: a StatefulSmartContract that conditionally writes >=2 state
 *   fields inside an `if` must compile to STACK-BALANCED IF/ELSE branches.
 *   Previously the synthesized "preserve old values" cleanup for the
 *   update-skipped branch only compensated a 1-item depth difference, so for
 *   N>=2 fields the branches were imbalanced by (N-1) and the update branch
 *   was unspendable (`OP_NUM2BIN` "encoding impossible to satisfy").
 *
 * #100: a terminal method (no state write -> no continuation) that READS a
 *   variable-length (ByteString) state field via `substr` must read the LIVE
 *   value from the preimage scriptCode, not the deploy-time initial value.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * Net stack-depth delta of a flat opcode sequence (no nested IF). Accurate for
 * the opcodes the state-write reconciliation emits (push / ROLL / PICK / DROP /
 * NIP / DUP / OVER / SWAP / ROT / TUCK / 2DROP / 2DUP).
 */
function netDelta(tokens: string[]): number {
  let d = 0;
  for (const t of tokens) {
    if (t === 'OP_DROP' || t === 'OP_NIP' || t === 'OP_ROLL') d -= 1;
    else if (t === 'OP_2DROP') d -= 2;
    else if (t === 'OP_DUP' || t === 'OP_OVER' || t === 'OP_TUCK') d += 1;
    else if (t === 'OP_2DUP') d += 2;
    else if (t === 'OP_SWAP' || t === 'OP_ROT' || t === 'OP_PICK') d += 0; // PICK: push(+1) already counted on the preceding numeric push, PICK itself net 0
    else if (/^OP_(\d|1[0-6])$/.test(t)) d += 1; // OP_0..OP_16 numeric push
    else if (t.startsWith('<')) d += 1; // data push
    // any other opcode in this region is unexpected; ignore (test asserts balance)
  }
  return d;
}

/** Extract the first top-level OP_IF .. OP_ELSE .. OP_ENDIF region as {then, else} token lists. */
/**
 * First OP_IF region belonging to the CONTRACT BODY.
 *
 * R-010 added a compiler-injected `_codePart` authentication preamble whose
 * scriptCode varint strip contains its own nested OP_IF chain, so the literal
 * first OP_IF in the script is no longer the user's `if`. The preamble ends
 * with `<61ab> OP_SWAP OP_CAT OP_EQUALVERIFY` (the prologue-byte pin); scan
 * from there when it is present.
 */
function firstIfRegion(asm: string): { then: string[]; els: string[] } | null {
  const toks = asm.split(/\s+/).filter(Boolean);
  const preambleEnd = toks.indexOf('<61ab>');
  const searchFrom = preambleEnd < 0 ? 0 : preambleEnd;
  const start = toks.indexOf('OP_IF', searchFrom);
  if (start < 0) return null;
  let depth = 1, i = start + 1, elseAt = -1;
  for (; i < toks.length; i++) {
    if (toks[i] === 'OP_IF') depth++;
    else if (toks[i] === 'OP_ELSE' && depth === 1) elseAt = i;
    else if (toks[i] === 'OP_ENDIF') { depth--; if (depth === 0) break; }
  }
  const endAt = i;
  const then = toks.slice(start + 1, elseAt < 0 ? endAt : elseAt);
  const els = elseAt < 0 ? [] : toks.slice(elseAt + 1, endAt);
  return { then, els };
}

const CONDWRITE2 = `import { StatefulSmartContract } from 'runar-lang';
import type { Addr } from 'runar-lang';
class CondWrite2 extends StatefulSmartContract {
  best: bigint;
  who: Addr;
  constructor(best: bigint, who: Addr) { super(best, who); this.best = best; this.who = who; }
  public offer(v: bigint, addr: Addr): void { if (v < this.best) { this.best = v; this.who = addr; } }
}`;

const CONDWRITE3 = `import { StatefulSmartContract } from 'runar-lang';
import type { Addr } from 'runar-lang';
class CondWrite3 extends StatefulSmartContract {
  best: bigint;
  who: Addr;
  tag: bigint;
  constructor(best: bigint, who: Addr, tag: bigint) { super(best, who, tag); this.best = best; this.who = who; this.tag = tag; }
  public offer(v: bigint, addr: Addr, t: bigint): void { if (v < this.best) { this.best = v; this.who = addr; this.tag = t; } }
}`;

const CONDWRITE1 = `import { StatefulSmartContract } from 'runar-lang';
class CondWrite extends StatefulSmartContract {
  best: bigint;
  constructor(best: bigint) { super(best); this.best = best; }
  public offer(v: bigint): void { if (v < this.best) { this.best = v; } }
}`;

describe('#99 Bug 1 — conditional multi-field state write: IF/ELSE stack balance', () => {
  it('1-field conditional write has balanced branches (control)', () => {
    const r = compile(CONDWRITE1, { fileName: 'CondWrite.runar.ts' });
    expect(r.success).toBe(true);
    const reg = firstIfRegion(r.scriptAsm!)!;
    expect(netDelta(reg.then)).toBe(netDelta(reg.els));
  });

  it('2-field conditional write has balanced branches', () => {
    const r = compile(CONDWRITE2, { fileName: 'CondWrite2.runar.ts' });
    expect(r.success).toBe(true);
    const reg = firstIfRegion(r.scriptAsm!)!;
    expect(netDelta(reg.then)).toBe(netDelta(reg.els));
  });

  it('3-field conditional write has balanced branches', () => {
    const r = compile(CONDWRITE3, { fileName: 'CondWrite3.runar.ts' });
    expect(r.success).toBe(true);
    const reg = firstIfRegion(r.scriptAsm!)!;
    expect(netDelta(reg.then)).toBe(netDelta(reg.els));
  });
});

describe('#100 — terminal method reads live ByteString state', () => {
  const STATEREAD = `import { StatefulSmartContract, assert, substr } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class StateReadBS extends StatefulSmartContract {
  s: ByteString;
  constructor(s: ByteString) { super(s); this.s = s; }
  public liveRead(expected: ByteString): void { assert(substr(this.s, 8n, 20n) === expected); this.s = this.s; }
  public termRead(expected: ByteString): void { assert(substr(this.s, 8n, 20n) === expected); }
}`;

  it('terminal substr read performs the live preimage deserialization, not the initial-value skip', () => {
    const r = compile(STATEREAD, { fileName: 'StateReadBS.runar.ts' });
    expect(r.success).toBe(true);
    // The buggy codegen short-circuited the terminal arm to the deploy-time
    // initial via `OP_SPLIT OP_2DROP OP_0`. With _codePart now provided to
    // terminal var-length readers, the terminal arm runs the same live
    // scriptCode deserialization as the non-terminal arm.
    expect(r.scriptAsm!).not.toContain('OP_2DROP OP_0');
  });
});
