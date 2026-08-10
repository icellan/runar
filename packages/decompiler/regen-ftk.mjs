// Regenerate the two FTK decompiler views into stable /tmp paths for IDE-following.
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { decompile } from './dist/src/index.js';
const hex = readFileSync(new URL('./__tests__/fixtures/ftk-demo.hex', import.meta.url), 'utf8').trim();
const res = decompile(hexToBytes(hex), { semantic: true });
writeFileSync('/tmp/FtkDemo.structured.runar.ts', res.source);
writeFileSync('/tmp/FtkDemo.byteexact.runar.ts', res.byteExactSource ?? '');
console.log('wrote structured (' + res.source.split('\n').length + ' lines) + byteexact (' + (res.byteExactSource ?? '').split('\n').length + ' lines); sourceByteIdentical=' + res.sourceByteIdentical);
