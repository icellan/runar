import { describe, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXAMPLES = join(__dirname, '..', 'examples', 'ts');

describe('which examples can be pushed into the 129-255 byte freeze window', () => {
  it('lists ByteString state fields and who may write them', () => {
    for (const dir of readdirSync(EXAMPLES)) {
      const p = join(EXAMPLES, dir);
      if (!statSync(p).isDirectory()) continue;
      const files = readdirSync(p).filter((f) => f.endsWith('.runar.ts'));
      for (const f of files) {
        const src = readFileSync(join(p, f), 'utf8');
        // mutable (non-readonly) ByteString / PubKey / variable-length state
        const mutableBytes = [...src.matchAll(/^\s{2}(?!(?:readonly))(\w+)\s*:\s*(ByteString|PubKey|Sig)\s*(?:=[^;]*)?;/gm)].map((m) => m[1]!);
        if (!mutableBytes.length) continue;
        // which public methods take a ByteString / PubKey argument that lands in state
        const writers = [...src.matchAll(/public\s+(\w+)\s*\(([^)]*)\)\s*\{([\s\S]*?)\n  \}/g)]
          .filter(([, , params = '', body = '']) => /ByteString|PubKey|Sig/.test(params) && new RegExp(`this\\.(${mutableBytes.join('|')})\\s*=`).test(body))
          .map(([, name = '?', params = '']) => `${name}(${params.replace(/\s+/g, ' ').slice(0, 60)})`);
        if (!writers.length) continue;
        const signed = writers.filter((w) => {
          const body = [...src.matchAll(new RegExp(`public\\s+${w.split('(')[0]}\\s*\\(([^)]*)\\)\\s*\\{([\\s\\S]*?)\\n  \\}`, 'g'))][0];
          return body && /checkSig|checkMultiSig|checkPreimage/.test(body[2]!);
        });
        const open = writers.filter((w) => !signed.includes(w));
        console.log(`${dir}/${f}`);
        console.log(`   mutable byte fields : ${mutableBytes.join(', ')}`);
        console.log(`   writers             : ${writers.join(' | ')}`);
        if (open.length) console.log(`   *** UNAUTHORISED WRITERS: ${open.join(' | ')}`);
      }
    }
  });
});
