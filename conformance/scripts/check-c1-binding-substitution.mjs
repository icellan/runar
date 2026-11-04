#!/usr/bin/env node
// Mechanical check for goldens moved by the C=1 Any-S binding (ports #170).
//
// For each path, the version at <base> is rewritten with exactly the three
// binding-blob edits (addend 01007e8100011f80517e93 -> 01007e818b, key
// 02b405d7.. -> 038ff83d.., s fan-out 31 x 76927f -> 82927f) and compared
// with the current file. The only further differences allowed are values that
// depend on script length, each smaller by exactly 6*k (1 <= k <= blobs, the
// number of default binding blobs in the file):
//   - hex: an equal-length byte run read as little-endian unsigned;
//   - JSON: a number, or a hex string checked by the hex rule.
// Anything else (a length mismatch, a changed string, a moved key) fails.
// A file whose byte size changed must also shrink by exactly 6*blobs bytes.
// A JSON file that carries no blob itself (expected-vertical.json) takes the
// blob count of the hex files beside it. script-size-baseline.json is checked
// row by row: each changed row must shrink by 6 x the blobs in that fixture's
// conformance/tests/<fixture>/expected-script.hex, and no row may appear or vanish.
//
//   - JSON prose: the text between embedded integers is unchanged, each integer obeys the 6k rule.
// Usage: node conformance/scripts/check-c1-binding-substitution.mjs --base <ref> <path>...
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const OLD_ADDEND = '01007e8100011f80517e93';
const NEW_ADDEND = '01007e818b';
const OLD_KEY = '02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0';
const NEW_KEY = '038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218';
const OLD_FAN = '76927f'.repeat(31);
const NEW_FAN = '82927f'.repeat(31);
// The sighash-agnostic prefix of the new default blob (everything up to the flag push).
const NEW_BLOB_PREFIX_END = '7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01';

const sub = (s) => s.split(OLD_ADDEND).join(NEW_ADDEND).split(OLD_KEY).join(NEW_KEY).split(OLD_FAN).join(NEW_FAN);
const countBlobs = (s) => s.split(NEW_ADDEND + '21414136d0').length - 1;

function leDelta(a, b, blobs) {
  // a, b: equal-length hex runs (<= 4 bytes); value must shrink by 6k.
  if (a.length !== b.length || a.length > 8 || a.length % 2) return false;
  const le = (h) => parseInt(h.match(/../g).reverse().join(''), 16);
  const d = le(a) - le(b);
  return d > 0 && d % 6 === 0 && d / 6 <= blobs;
}

/** Equal-length hex strings; every differing region must pass leDelta. */
function hexOk(oldSub, neu, blobs, problems, where) {
  if (oldSub === neu) return true;
  if (oldSub.length !== neu.length) {
    problems.push(`${where}: hex length ${oldSub.length / 2} vs ${neu.length / 2} after substitution`);
    return false;
  }
  for (let i = 0; i < neu.length; i += 2) {
    if (oldSub.slice(i, i + 2) === neu.slice(i, i + 2)) continue;
    let j = i;
    while (j < neu.length && oldSub.slice(j, j + 2) !== neu.slice(j, j + 2)) j += 2;
    // widen to a 4-byte window ending at j (LE low bytes change first)
    const start = Math.max(0, Math.min(i, j - 8));
    const a = oldSub.slice(i, j), b = neu.slice(i, j);
    // a carry can leave higher bytes equal: compare the minimal differing run
    // extended right to 4 bytes, read LE.
    const end = Math.min(neu.length, i + 8);
    const ok = leDelta(a, b, blobs) || leDelta(oldSub.slice(i, end), neu.slice(i, end), blobs);
    if (!ok) {
      problems.push(`${where}: byte ${i / 2}: ${oldSub.slice(start, j + 8)} -> ${neu.slice(start, j + 8)}`);
      return false;
    }
    i = j - 2;
  }
  return true;
}

function jsonOk(o, n, blobs, problems, where) {
  if (typeof o === 'string' && typeof n === 'string') {
    const os = sub(o);
    if (os === n) return true;
    if (/^[0-9a-f]+$/i.test(os) && /^[0-9a-f]+$/i.test(n)) return hexOk(os.toLowerCase(), n.toLowerCase(), blobs, problems, where);
    // Prose that embeds byte offsets ("IF[false] at 459"): the text between
    // the numbers must be identical and each number obey the 6k rule.
    const to = os.split(/(\d+)/), tn = n.split(/(\d+)/);
    const ok = to.length === tn.length && to.every((t, i) => (i % 2 === 0
      ? t === tn[i]
      : jsonOk(Number(t), Number(tn[i]), blobs, problems, `${where}#${i}`)));
    if (!ok) problems.push(`${where}: string changed`);
    return ok;
  }
  if (typeof o === 'number' && typeof n === 'number') {
    const d = o - n;
    if (d === 0 || (d > 0 && d % 6 === 0 && d / 6 <= blobs)) return true;
    problems.push(`${where}: number ${o} -> ${n}`);
    return false;
  }
  if (Array.isArray(o) && Array.isArray(n)) {
    if (o.length !== n.length) { problems.push(`${where}: array length ${o.length} -> ${n.length}`); return false; }
    return o.every((x, i) => jsonOk(x, n[i], blobs, problems, `${where}[${i}]`));
  }
  if (o && n && typeof o === 'object' && typeof n === 'object') {
    const ko = Object.keys(o), kn = Object.keys(n);
    if (ko.join() !== kn.join()) { problems.push(`${where}: keys changed`); return false; }
    return ko.every((k) => jsonOk(o[k], n[k], blobs, problems, `${where}.${k}`));
  }
  if (o === n) return true;
  problems.push(`${where}: ${JSON.stringify(o)} -> ${JSON.stringify(n)}`);
  return false;
}

const args = process.argv.slice(2);
const bi = args.indexOf('--base');
if (bi < 0) { console.error('--base <ref> required'); process.exit(2); }
const base = args[bi + 1];
const paths = args.filter((_, i) => i !== bi && i !== bi + 1);
let failed = 0;
for (const p of paths) {
  const old = execFileSync('git', ['show', `${base}:${p}`], { encoding: 'utf8', maxBuffer: 1 << 28 });
  const neu = readFileSync(p, 'utf8');
  let blobs = countBlobs(neu);
  if (blobs === 0) {
    const dir = dirname(p);
    for (const f of readdirSync(dir)) if (f.endsWith('.hex')) blobs = Math.max(blobs, countBlobs(readFileSync(join(dir, f), 'utf8')));
  }
  const problems = [];
  let ok;
  if (p.endsWith('script-size-baseline.json')) {
    const o = JSON.parse(old).fixtures, n = JSON.parse(neu).fixtures;
    ok = Object.keys(o).join() === Object.keys(n).join();
    if (!ok) problems.push('fixture rows changed');
    for (const k of Object.keys(n)) {
      const ob = typeof o[k] === 'object' ? o[k].bytes : o[k];
      const nb = typeof n[k] === 'object' ? n[k].bytes : n[k];
      if (ob === nb) continue;
      const g = `conformance/tests/${k}/expected-script.hex`;
      const b = existsSync(g) ? countBlobs(readFileSync(g, 'utf8')) : 0;
      if (ob - nb !== 6 * b || b === 0) { ok = false; problems.push(`${k}: ${ob} -> ${nb}, ${b} blobs`); }
    }
  } else if (p.endsWith('.json')) {
    ok = jsonOk(JSON.parse(old), JSON.parse(neu), blobs, problems, '$');
  } else {
    ok = hexOk(sub(old.trim()), neu.trim(), blobs, problems, '$');
    const delta = old.trim().length / 2 - neu.trim().length / 2;
    if (ok && delta !== 6 * blobs) { ok = false; problems.push(`size delta ${delta} != 6 x ${blobs}`); }
  }
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${p} (blobs ${blobs})${ok ? '' : ' ' + problems.slice(0, 3).join('; ')}`);
  if (!ok) failed++;
}
console.log(`${paths.length - failed}/${paths.length} pass`);
process.exit(failed ? 1 : 0);
