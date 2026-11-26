import { describe, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, asm, firstLine } from './harness.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXAMPLES = join(__dirname, '..', 'examples', 'ts');

function contracts(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (!statSync(p).isDirectory()) continue;
    const src = readdirSync(p).find((f) => f.endsWith('.runar.ts'));
    if (src) out.push(join(p, src));
  }
  return out;
}

const CRYPTO = /OP_CHECKSIG|OP_CHECKMULTISIG|OP_CHECKDATASIG/;
const HASHY = /OP_HASH256|OP_SHA256|OP_HASH160|OP_RIPEMD160|OP_SHA1/;
const UNSIGNED_4BYTE_READERS = /extractLocktime|currentBlockHeight|extractSequence|extractVersion|extractInputIndex/;

describe('example sweep: which contracts are exposed to which attack class', () => {
  it('classifies every examples/ts contract', () => {
    const rows: string[] = [];
    for (const path of contracts(EXAMPLES)) {
      const source = readFileSync(path, 'utf8');
      const name = path.replace(`${EXAMPLES}/`, '').replace('.runar.ts', '');
      const flags: string[] = [];

      // class: timelock via an unsigned uint32 preimage field
      const usesLocktime = UNSIGNED_4BYTE_READERS.test(source);
      const guardsSeq = /extractSequence/.test(source);
      // big literals baked into the contract or the docs (unix timestamps)
      const bigLiterals = [...source.matchAll(/(?<![\w.])(\d{10,13})(?![\w.])/g)].map((m) => m[1]!);
      const tsLike = bigLiterals.filter((v) => BigInt(v) >= 2n ** 31n);

      if (usesLocktime) flags.push(guardsSeq ? 'TIMELOCK(seq-guarded)' : 'TIMELOCK(unguarded)');
      else flags.push('no-timelock');
      if (tsLike.length) flags.push(`uint32-overflow-literals[${tsLike.join(',')}]`);

      let info = '';
      try {
        const c = build(source, path, bakeFrom(source));
        const pubs = c.artifact!.abi.methods.filter((m) => m.isPublic);
        const script = asm(c.scriptHex);
        const hasCrypto = CRYPTO.test(script);
        const hasHash = HASHY.test(script);
        const unguarded = pubs.map((m) => m.name).join('/');
        info = `${pubs.length} pub method(s) [${unguarded}], ${c.scriptHex.length / 2}B, crypto=${hasCrypto ? 'sig' : hasHash ? 'hash' : 'NONE'}`;
        if (!hasCrypto && !hasHash) flags.push('ANYONE-CAN-SPEND');
        if (!CRYPTO.test(script) && /\bcheckSig\b|\bcheckMultiSig\b/.test(source)) flags.push('sig-compiled-away?');
        if (/addOutput\(/.test(source)) flags.push('multi-output');
        if (/readonly .*: bigint/.test(source) && /extractAmount/.test(source)) flags.push('amount-bound');
        else if (/amount|sat|bid|price|value/i.test(source) && !/extractAmount/.test(source)) flags.push('money-in-state-no-amount-check');
      } catch (e: any) {
        info = 'COMPILE FAILED: ' + firstLine(String(e.message), 70);
      }
      rows.push(`${name.padEnd(42)} ${info.padEnd(70)} ${flags.join(' ')}`);
    }
    console.log(rows.join('\n'));
  });
});

/** Best-effort bake of readonly constructor args so every example compiles. */
function bakeFrom(source: string): Record<string, unknown> {
  const PK = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
  const bake: Record<string, unknown> = {};
  const re = /^\s*(?:public\s+|private\s+)?(?:readonly\s+)?(\w+)\s*:\s*([\w<>\[\]]+)\s*(?:=[^;]*)?;/gm;
  for (const m of source.matchAll(re)) {
    const [, n, t] = m as unknown as RegExpMatchArray;
    if (bake[n!] !== undefined) continue;
    const type = t!;
    if (/bigint/.test(type)) bake[n!] = 1000n;
    else if (/boolean/.test(type)) bake[n!] = true;
    else if (/PubKey|Point|P256Point|P384Point/.test(type)) bake[n!] = PK;
    else if (/Ripemd160|Addr/.test(type)) bake[n!] = '9a1c78a507689f6f54b847ad1cef1e614ee23f1e';
    else if (/Sha256/.test(type)) bake[n!] = 'aa'.repeat(32);
    else if (/Sig/.test(type)) bake[n!] = '3045' + '00'.repeat(69);
    else if (/ByteString|string/.test(type)) bake[n!] = 'aabbccdd';
    else if (/FixedArray|Array/.test(type)) bake[n!] = [1000n, 1000n];
  }
  return bake;
}
