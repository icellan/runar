import { compile } from './packages/tsop-compiler/dist/index.js';
import { lowerToStack } from './packages/tsop-compiler/dist/passes/05-stack-lower.js';
import { emit } from './packages/tsop-compiler/dist/passes/06-emit.js';
import { readFileSync } from 'fs';

const tests = ['basic-p2pkh', 'arithmetic', 'boolean-logic', 'bounded-loop', 'if-else', 'multi-method', 'stateful'];

for (const test of tests) {
  const source = readFileSync(`conformance/tests/${test}/${test}.tsop.ts`, 'utf-8');
  const result = compile(source);
  if (result.success && result.anf) {
    try {
      const stack = lowerToStack(result.anf);
      const emitResult = emit(stack);
      const goHex = readFileSync(`conformance/tests/${test}/expected-script.hex`, 'utf-8').trim();
      const match = emitResult.scriptHex === goHex ? 'MATCH' : 'MISMATCH';
      console.log(`${test}: ${match}`);
      if (match === 'MISMATCH') {
        console.log(`  TS: ${emitResult.scriptHex}`);
        console.log(`  Go: ${goHex}`);
      }
    } catch (e) {
      console.log(`${test}: TS backend error: ${e.message}`);
    }
  } else {
    console.log(`${test}: TS compile failed`);
  }
}
