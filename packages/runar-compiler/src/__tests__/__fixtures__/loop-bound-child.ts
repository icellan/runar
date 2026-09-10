/**
 * Child entry point for the loop-bound narrowing regression test.
 *
 * The compile it performs is CPU-bound and synchronous, so a regression in the
 * loop-count guard does not fail — it wedges or exhausts the heap. Neither is
 * interruptible from inside the test process, which is why this runs as its own
 * process behind a spawnSync timeout (the Node analogue of the Go tier's
 * goroutine-behind-a-watchdog in bigint_narrowing_guard_test.go).
 *
 * Usage: tsx loop-bound-child.ts <decimal-bound>
 * Emits a single JSON line on stdout describing the compile outcome.
 */
import { compile } from '../../index.js';

const bound = process.argv[2] ?? '0';

const source = `import { SmartContract, assert } from 'runar-lang';

export class LoopBound extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0n; i < ${bound}n; i++) {
      acc = acc + i;
    }
    assert(acc === x);
  }
}
`;

const result = compile(source, { fileName: 'LoopBound.runar.ts' });

process.stdout.write(
  JSON.stringify({
    success: result.success,
    script: result.artifact?.script ?? null,
    diagnostics: result.diagnostics.map((d) => d.message),
  }),
);
