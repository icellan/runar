/**
 * End-to-end smoke test: write a contract with asm({...}), compile via
 * standard `compile()`, decompile, re-compile, verify byte-identity.
 */

import { compile } from 'runar-compiler';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';

const src = `
import { UnsafeSmartContract, asm } from 'runar-lang';

export class CustomLock extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(): void {
    asm({ body: '76a90088ac', in_arity: 0, out_arity: 1 });
  }
}
`;

const r = compile(src, { fileName: 'CustomLock.runar.ts' });
if (!r.success || !r.scriptHex) {
  console.log('compile FAILED:', r.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; '));
  process.exit(1);
}
console.log(`compiled: ${r.scriptHex} (${r.scriptHex.length / 2} bytes)`);

const recovered = decompile(hexToBytes(r.scriptHex));
console.log(`decompile: ok=${recovered.ok} path=${recovered.recoveryPath}`);
console.log('--- recovered source ---');
console.log(recovered.source);

const reCompile = compile(recovered.source, { fileName: 'recovered.runar.ts' });
if (!reCompile.success || !reCompile.scriptHex) {
  console.log('re-compile FAILED:', reCompile.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; '));
  process.exit(1);
}
console.log(`re-compiled: ${reCompile.scriptHex} (${reCompile.scriptHex.length / 2} bytes)`);
console.log(`byte-identical: ${r.scriptHex === reCompile.scriptHex}`);
