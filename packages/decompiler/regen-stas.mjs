import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { decompile } from './dist/src/index.js';
const hex = readFileSync(new URL('./__tests__/fixtures/stas-faucet.hex', import.meta.url), 'utf8').trim();
const res = decompile(hexToBytes(hex), { semantic: true });
writeFileSync('/tmp/StasFaucet.structured.runar.ts', res.source);
writeFileSync('/tmp/StasFaucet.byteexact.runar.ts', res.byteExactSource ?? '(no byte-exact companion)');
console.log('recoveryPath:', res.recoveryPath, '| ok(byte-exact companion):', res.ok, '| sourceByteIdentical:', res.sourceByteIdentical);
console.log('wrote /tmp/StasFaucet.structured.runar.ts (' + res.source.split('\n').length + ' lines) + /tmp/StasFaucet.byteexact.runar.ts');
