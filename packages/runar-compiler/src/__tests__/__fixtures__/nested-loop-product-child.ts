/**
 * Child entry point for the N-202 nested-loop product test.
 *
 * A regression in the product bound does not fail: a 9000 x 9000 nest unrolls
 * to 81,000,000 iterations and wedges the compiler. That cannot be interrupted
 * from inside the test process, so the compile runs here behind a spawnSync
 * timeout (same pattern as loop-bound-child.ts).
 *
 * Usage: tsx nested-loop-product-child.ts <shape> <outer> <inner> [<innermost>]
 *   shape = nested     for i < outer { for j < inner { ... } }
 *         = if-arm     for i < outer { if (x > 0n) { for j < inner { ... } } }
 *         = triple     for i < outer { for j < inner { for k < innermost { ... } } }
 *         = sequential for i < outer { ... }  for j < inner { ... }
 * Emits a single JSON line on stdout describing the compile outcome.
 */
import { compile } from '../../index.js';

const [shape = 'nested', outer = '0', inner = '0', innermost = '0'] = process.argv.slice(2);

const step = 'acc = acc + x;';
let body: string;
switch (shape) {
  case 'nested':
    body = `for (let i = 0n; i < ${outer}n; i++) { for (let j = 0n; j < ${inner}n; j++) { ${step} } }`;
    break;
  case 'if-arm':
    body = `for (let i = 0n; i < ${outer}n; i++) { if (x > 0n) { for (let j = 0n; j < ${inner}n; j++) { ${step} } } }`;
    break;
  case 'triple':
    body =
      `for (let i = 0n; i < ${outer}n; i++) { for (let j = 0n; j < ${inner}n; j++) { ` +
      `for (let k = 0n; k < ${innermost}n; k++) { ${step} } } }`;
    break;
  case 'sequential':
    body =
      `for (let i = 0n; i < ${outer}n; i++) { ${step} } ` +
      `for (let j = 0n; j < ${inner}n; j++) { ${step} }`;
    break;
  default:
    throw new Error(`unknown shape ${shape}`);
}

const source = `import { SmartContract, assert } from 'runar-lang';

export class NestedLoops extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint): void {
    let acc: bigint = 0n;
    ${body}
    assert(acc > x);
  }
}
`;

const result = compile(source, { fileName: 'NestedLoops.runar.ts' });

process.stdout.write(
  JSON.stringify({
    success: result.success,
    diagnostics: result.diagnostics.map((d) => d.message),
  }),
);
