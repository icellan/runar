// ---------------------------------------------------------------------------
// runar-sdk/__tests__/f245-codegen-intent-witness-wrapper.test.ts
//
// F-245 — the generated typed wrapper (codegen/gen-typescript.ts) must not
// pass the intent-intrinsic witness params (`_prevOutScript_<i>`,
// `_serialisedOutputs`) as call args. RunarContract.prepareCall supplies
// those from setPrevOutScript / setSerialisedOutputs and excludes them from
// its arity check; a wrapper that forwards them builds an args array that
// prepareCall rejects ("expects N args, got N+k").
//
// What this proves: for the two real example contracts that use the intent
// intrinsics (extractPrevOutputScript → `_prevOutScript_0`,
// requireOutputP2PKH → `_serialisedOutputs`), the wrapper generated from
// the compiled artifact, transpiled and executed as-is, completes a deploy +
// method call on a MockProvider with broadcast validation ON. MockProvider
// runs @bsv/sdk `Spend.validate()` on every broadcast, so each call is a real
// script-execution acceptance of the unlocking script the SDK built — which
// only succeeds if the SDK appended the witness bytes set on the inner
// contract. It also pins that codegen's param classification and prepareCall's
// arity filter come from one shared predicate.
//
// What this does NOT prove: anything about the Go/Rust/Python/Zig/Ruby/Java
// native codegens (covered by their own suites), or the mustache-rendered
// non-TS wrappers beyond their args-expression (asserted on rendered text,
// not executed).
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { compile } from 'runar-compiler';
import { Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { generateTypescript, generateGo, generatePython } from '../codegen/index.js';
import { getSdkArgParams, getUserParams } from '../codegen/common.js';
import { isSdkSuppliedParam } from '../sdk-params.js';

const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

function compileExample(rel: string): RunarArtifact {
  const path = fileURLToPath(new URL(`../../../../examples/ts/${rel}`, import.meta.url));
  const result = compile(readFileSync(path, 'utf8'), { fileName: path.split('/').pop()! });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

/** Transpile + evaluate the generated wrapper, binding `runar-sdk` to this source tree. */
function loadWrapper(source: string, className: string): any {
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const sdk = { RunarContract, buildP2PKHScript };
  const mod = { exports: {} as Record<string, unknown> };
  const req = (id: string) => {
    if (id !== 'runar-sdk') throw new Error(`unexpected import '${id}' in generated wrapper`);
    return sdk;
  };
  new Function('require', 'module', 'exports', js)(req, mod, mod.exports);
  return mod.exports[className];
}

async function fundedProvider(): Promise<{ provider: MockProvider; signer: LocalSigner }> {
  const signer = new LocalSigner(PRIV_KEY);
  const provider = new MockProvider('testnet'); // validateBroadcasts defaults ON
  provider.addUtxo(await signer.getAddress(), {
    txid: 'aabbccdd'.repeat(8),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  return { provider, signer };
}

describe('F-245 — generated wrappers exclude intent-intrinsic witness params', () => {
  it('extractPrevOutputScript: wrapper.bind() deploys + calls through prepareCall on a validating MockProvider', async () => {
    const artifact = compileExample('intent-prev-output-script/IntentPrevOutputScript.runar.ts');
    const method = artifact.abi.methods.find((m) => m.name === 'bind')!;
    expect(method.params.map((p) => p.name)).toContain('_prevOutScript_0');

    const src = generateTypescript(artifact);
    // The witness is not a parameter of the generated method signature.
    expect(src).toMatch(/async bind\(options\?: IntentPrevOutputScriptStatefulCallOptions\)/);

    const Wrapper = loadWrapper(src, 'IntentPrevOutputScriptContract');
    const witness = buildP2PKHScript('00'.repeat(20).replace(/^00/, '11'));
    const expectedHash = Utils.toHex(Hash.hash256(Utils.toArray(witness, 'hex')));
    const wrapper = new Wrapper(artifact, { expectedHash, count: 0n });

    const { provider, signer } = await fundedProvider();
    wrapper.connect(provider, signer);
    await wrapper.deploy({ satoshis: 50_000 });

    wrapper.contract.setPrevOutScript(0, witness);
    await wrapper.bind();
    expect(wrapper.contract.state.count).toBe(1n);
  });

  it('requireOutputP2PKH: wrapper.payBond(outputs) deploys + calls through prepareCall on a validating MockProvider', async () => {
    const artifact = compileExample('intent-output-p2pkh/IntentOutputP2PKH.runar.ts');
    const method = artifact.abi.methods.find((m) => m.name === 'payBond')!;
    expect(method.params.map((p) => p.name)).toContain('_serialisedOutputs');

    const src = generateTypescript(artifact);
    expect(src).toMatch(/async payBond\(outputs: TerminalOutput\[\]\)/);

    const Wrapper = loadWrapper(src, 'IntentOutputP2PKHContract');
    const bondPKH = '22'.repeat(20);
    const bondAmount = 20_000;
    const wrapper = new Wrapper(artifact, { bondPKH, bondAmount: BigInt(bondAmount), count: 0n });

    const { provider, signer } = await fundedProvider();
    wrapper.connect(provider, signer);
    await wrapper.deploy({ satoshis: 50_000 });

    // The terminal tx's outputs are exactly the caller's outputs, so the
    // serialised-outputs witness is that single P2PKH output.
    const bondScript = buildP2PKHScript(bondPKH);
    const amountLE = Utils.toHex(
      Array.from({ length: 8 }, (_, i) => Number((BigInt(bondAmount) >> BigInt(8 * i)) & 0xffn)),
    );
    wrapper.contract.setSerialisedOutputs(amountLE + '19' + bondScript);
    const result = await wrapper.payBond([{ scriptHex: bondScript, satoshis: bondAmount }]);
    expect(result.txid).toMatch(/^[0-9a-f]{64}$/);
  });

  it('codegen and prepareCall share one predicate for SDK-supplied params', () => {
    const artifact = compileExample('intent-prev-output-script/IntentPrevOutputScript.runar.ts');
    const method = artifact.abi.methods.find((m) => m.name === 'bind')!;
    expect(isSdkSuppliedParam(method.params.find((p) => p.name === '_prevOutScript_0')!, true)).toBe(true);
    expect(isSdkSuppliedParam({ name: '_serialisedOutputs', type: 'ByteString' }, false)).toBe(true);
    expect(isSdkSuppliedParam({ name: 'amount', type: 'bigint' }, true)).toBe(false);
    expect(getSdkArgParams(method, true)).toEqual([]);
    expect(getUserParams(method, true)).toEqual([]);

    // A stateless method carrying a witness param: stateless args keep
    // everything EXCEPT the witness (prepareCall's stateless filter).
    const stateless = {
      name: 'm',
      isPublic: true,
      params: [
        { name: 'x', type: 'bigint' },
        { name: '_serialisedOutputs', type: 'ByteString' },
      ],
    };
    expect(getSdkArgParams(stateless, false).map((p) => p.name)).toEqual(['x']);
  });

  it('mustache-rendered wrappers (Go, Python) do not forward witness params either', () => {
    const artifact = compileExample('intent-prev-output-script/IntentPrevOutputScript.runar.ts');
    expect(generateGo(artifact)).not.toMatch(/PrevOutScript_0|_prevOutScript_0/i);
    expect(generatePython(artifact)).not.toMatch(/prev_out_script_0/);
  });
});
