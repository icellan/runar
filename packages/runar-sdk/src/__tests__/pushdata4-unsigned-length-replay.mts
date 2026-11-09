/**
 * OP_PUSHDATA4 envelope replay helper (not a test file). Run in a child
 * process, one case per process, by pushdata4-unsigned-length.test.ts so a
 * walk that never terminates is killed instead of hanging vitest. Prints one
 * JSON line with the named case's outcome.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findInscriptionEnvelope, stripInscriptionEnvelope } from '../ordinals/envelope.js';
import { RunarContract } from '../contract.js';
import type { RunarArtifact } from '../types.js';

const dir = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact');
const fx = JSON.parse(readFileSync(resolve(dir, 'hostile.json'), 'utf8')) as {
  artifacts: Record<string, RunarArtifact>; cases: { name: string; prefix: string }[];
};

const ENVELOPE = '0063036f726451' + '0a746578742f706c61696e' + '00' + '0568656c6c6f' + '68';

const envelopeCases: Record<string, string> = {
  // length 0xfffffffb: the signed step was 10 + 2 * -5 = 0
  'zero step': '4efbffffff',
  // length 0xfffffff8: the signed step was -6, walking back into earlier opcodes
  'backward step': '51514ef8ffffff',
  // length 0xfffffff0 on the content-type push: the signed readPushData stepped
  // back to offset 0 and read the leading bytes as the rest of an envelope,
  // returning { startHex: 8, endHex: 8 }
  'content-type push': '0001aa68' + '0063036f726451' + '4ef0ffffff',
  // length 0xfffffff9 on the content push: the signed readPushData stepped
  // back onto the content-type byte 0x68, read it as OP_ENDIF and returned a
  // phantom envelope { startHex: 0, endHex: 18 }
  'content push': '0063036f7264' + '51' + '0168' + '00' + '4ef9ffffff',
  // control: a well-formed OP_PUSHDATA4 before an envelope is still skipped
  'valid pushdata4 then envelope': '4e01000000aa' + ENVELOPE,
};

const name = process.argv[2];
if (name !== undefined) {
  let out: unknown;
  if (name === 'fromUtxo') {
    const genuine = fx.cases.find((c) => c.name === 'stateless-genuine')!.prefix;
    const c = RunarContract.fromUtxo(fx.artifacts.stateless!, {
      txid: '00'.repeat(32), outputIndex: 0, satoshis: 1000, script: genuine + '4efbffffff',
    });
    out = { inscription: c.inscription };
  } else {
    const hex = envelopeCases[name];
    if (hex === undefined) throw new Error(`unknown case ${name}`);
    out = { found: findInscriptionEnvelope(hex), stripped: stripInscriptionEnvelope(hex) };
  }
  process.stdout.write(JSON.stringify(out) + '\n');
}
