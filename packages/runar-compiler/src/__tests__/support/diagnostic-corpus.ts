/**
 * Negative corpus for the diagnostic-coverage gate (R-101).
 *
 * One entry per diagnostic the validate / typecheck passes can emit. Each
 * entry names the diagnostic it is aimed at (`target`, a distinctive substring
 * of the message template) and carries the smallest source that provokes it.
 * The gate asserts BOTH directions:
 *
 *   - the entry actually produces the diagnostic it claims (an entry whose
 *     shape stops triggering is a dead entry, not a silent pass), and
 *   - every diagnostic site in the passes is hit by some entry, or is listed
 *     in the ratcheted baseline with a reason.
 *
 * These are TypeScript-surface sources compiled in-process by the reference
 * tier. They are deliberately NOT in `conformance/negatives/`: that corpus is
 * the seven-tier REJECTION-PARITY gate, where every fixture must be refused by
 * all seven compilers, and promoting a TS-only diagnostic there would fail
 * tiers that do not implement the same check. Coverage first, parity when a
 * shape is worth demanding of every tier.
 */

export interface CorpusEntry {
  /** Distinctive substring of the diagnostic template this entry targets. */
  target: string;
  /** Fixture name, used in failure output. */
  name: string;
  /** Source compiled by the reference tier. */
  source: string;
  /** File name passed to the parser (selects the frontend). */
  fileName?: string;
}

/** Stateless contract with one readonly bigint property and one public method. */
function stateless(body: string, opts: { imports?: string; extra?: string } = {}): string {
  const imports = opts.imports ?? 'SmartContract, assert';
  return `import { ${imports} } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }
${opts.extra ?? ''}
  public go(x: bigint) {
${body}
  }
}
`;
}

/** Stateful contract with one mutable bigint property and one public method. */
function stateful(body: string, opts: { imports?: string; extra?: string } = {}): string {
  const imports = opts.imports ?? 'StatefulSmartContract, assert';
  return `import { ${imports} } from 'runar-lang';

export class Neg extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }
${opts.extra ?? ''}
  public go(x: bigint) {
${body}
  }
}
`;
}

/** UnsafeSmartContract with one public method — the only home for `asm`. */
function unsafe(body: string, opts: { imports?: string } = {}): string {
  const imports = opts.imports ?? 'UnsafeSmartContract, assert, asm';
  return `import { ${imports} } from 'runar-lang';

export class Neg extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public go(x: bigint) {
${body}
  }
}
`;
}

export const CORPUS: CorpusEntry[] = [
  // ------------------------------------------------------------------
  // 02-validate: contract shape
  // ------------------------------------------------------------------
  {
    target: "is an implicit property of StatefulSmartContract",
    name: 'declares-txPreimage',
    source: `import { StatefulSmartContract, assert, ByteString } from 'runar-lang';

export class Neg extends StatefulSmartContract {
  count: bigint;
  txPreimage: ByteString;

  constructor(count: bigint, txPreimage: ByteString) {
    super(count, txPreimage);
    this.count = count;
    this.txPreimage = txPreimage;
  }

  public go(x: bigint) {
    this.count = this.count + x;
    assert(x > 0n);
  }
}
`,
  },
  {
    target: 'initializer must be an array literal of literal values',
    name: 'fixed-array-initializer-not-array',
    source: `import { SmartContract, assert, FixedArray } from 'runar-lang';

export class Neg extends SmartContract {
  readonly arr: FixedArray<bigint, 2> = 7n;

  constructor() {
    super();
  }

  public go(x: bigint) {
    assert(x > 0n);
  }
}
`,
  },
  {
    target: 'must be readonly. Use StatefulSmartContract for mutable state.',
    name: 'mutable-property-in-stateless',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`,
  },
  {
    target: 'has no mutable properties; consider using SmartContract',
    name: 'stateful-all-readonly',
    source: `import { StatefulSmartContract, assert } from 'runar-lang';

export class Neg extends StatefulSmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`,
  },
  {
    target: "Property type 'void' is not valid",
    name: 'void-property',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: void;

  constructor(a: void) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > 0n);
  }
}
`,
  },
  {
    target: "Property '*' must be assigned in the constructor",
    name: 'property-never-assigned',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`,
  },
  {
    target: 'initialises more than one property',
    name: 'ctor-param-two-properties',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
    this.b = a;
  }

  public go(x: bigint) {
    assert(x > this.a + this.b);
  }
}
`,
  },
  {
    target: 'is assigned more than one constructor parameter',
    name: 'property-two-ctor-params',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(p: bigint, q: bigint) {
    super(p, q);
    this.a = p;
    this.a = q;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`,
  },
  {
    target: 'does not initialise any property',
    name: 'ctor-param-unused',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint, unused: bigint) {
    super(a, unused);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
`,
  },
  {
    target: 'occupies deploy-time slot',
    name: 'ctor-param-order-mismatch',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(p: bigint, q: bigint) {
    super(p, q);
    this.b = p;
    this.a = q;
  }

  public go(x: bigint) {
    assert(x > this.a + this.b);
  }
}
`,
  },
  {
    target: 'has no public methods',
    name: 'no-public-methods',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  private go(x: bigint): bigint {
    return x + this.a;
  }
}
`,
  },
  {
    target: "Parameter '*' in method '*' cannot be a FixedArray",
    name: 'method-param-fixed-array',
    source: `import { SmartContract, assert, FixedArray } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(xs: FixedArray<bigint, 2>) {
    assert(this.a > 0n);
  }
}
`,
  },
  {
    target: "Public method '*' must end with an assert() call",
    name: 'public-method-no-trailing-assert',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
    const y: bigint = x + 1n;
  }
}
`,
  },
  {
    target: 'must not use `return`',
    name: 'public-method-returns',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    if (x > this.a) {
      return;
    }
    assert(x > 0n);
  }
}
`,
  },
  {
    target: 'Recursion detected',
    name: 'recursive-helper',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  private h(x: bigint): bigint {
    return this.h(x);
  }

  public go(x: bigint) {
    assert(this.h(x) > 0n);
  }
}
`,
  },

  // ------------------------------------------------------------------
  // 02-validate: statements and literals
  // ------------------------------------------------------------------
  {
    target: "Local variable '*' cannot be a FixedArray",
    name: 'local-fixed-array',
    source: stateless(
      `    const ys: FixedArray<bigint, 2> = [1n, 2n];
    assert(x > 0n);`,
      { imports: 'SmartContract, assert, FixedArray' },
    ),
  },
  {
    target: 'For loop update must advance the loop variable by one',
    name: 'loop-update-non-unit',
    source: stateless(
      `    let s: bigint = 0n;
    for (let i = 0n; i < 4n; this.step(i)) {
      s = s + i;
    }
    assert(s > 0n);`,
      {
        extra: `
  private step(i: bigint): bigint {
    return i + 1n;
  }
`,
      },
    ),
  },
  {
    target: 'has odd length',
    name: 'bytestring-odd-length',
    source: stateless(
      `    const b: ByteString = '0xabc';
    assert(len(b) > 0n);`,
      { imports: 'SmartContract, assert, ByteString, len' },
    ),
  },
  {
    target: "ByteString literal '*' contains non-hex characters",
    name: 'bytestring-non-hex',
    source: stateless(
      `    const b: ByteString = '0xzz';
    assert(len(b) > 0n);`,
      { imports: 'SmartContract, assert, ByteString, len' },
    ),
  },
  {
    target: 'auto-injects checkPreimage()',
    name: 'manual-checkpreimage',
    source: stateful(
      `    this.count = this.count + x;
    assert(checkPreimage(this.txPreimage));`,
      { imports: 'StatefulSmartContract, assert, checkPreimage' },
    ),
  },
  {
    target: 'calling getStateScript() manually',
    name: 'manual-getstatescript',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = this.getStateScript();
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len' },
    ),
  },

  // ------------------------------------------------------------------
  // 03-typecheck: expressions
  // ------------------------------------------------------------------
  {
    target: 'For loop condition must be boolean',
    name: 'loop-condition-not-boolean',
    // The condition used to be the bare literal `4n`. W4 made validate refuse
    // any for-condition that is not `<iterator> <relop> <expr>`, and validate
    // runs before typecheck, so that source now stops one pass earlier and this
    // entry no longer reached the diagnostic it names. `i + 1n` satisfies the
    // new shape rule -- left IS the iterator, right IS a compile-time constant
    // -- and is still a bigint where a boolean is required, so the typecheck
    // diagnostic stays reachable from source rather than becoming dead.
    source: stateless(
      `    let s: bigint = 0n;
    for (let i = 0n; i + 1n; i++) {
      s = s + i;
    }
    assert(s > 0n);`,
    ),
  },
  {
    target: "Property '*' does not exist on the contract",
    name: 'unknown-property',
    source: stateless(`    assert(x > this.missing);`),
  },
  {
    target: 'Ternary condition must be boolean',
    name: 'ternary-condition-not-boolean',
    source: stateless(
      `    const y: bigint = x ? 1n : 2n;
    assert(y > 0n);`,
    ),
  },
  {
    target: 'Array index must be bigint',
    name: 'array-index-not-bigint',
    source: `import { SmartContract, assert, FixedArray } from 'runar-lang';

export class Neg extends SmartContract {
  readonly arr: FixedArray<bigint, 2> = [1n, 2n];

  constructor() {
    super();
  }

  public go(x: bigint) {
    assert(this.arr[true] > 0n);
  }
}
`,
  },
  {
    target: 'Array element type mismatch',
    name: 'array-element-type-mismatch',
    source: `import { SmartContract, assert, checkMultiSig, Sig, PubKey } from 'runar-lang';

export class Neg extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public go(s: Sig, x: bigint) {
    assert(checkMultiSig([s, x], [this.pk, this.pk]));
  }
}
`,
  },
  {
    target: "Operand of '!' must be boolean",
    name: 'not-operand-not-boolean',
    source: stateless(`    assert(!x);`),
  },
  {
    target: "Operand of unary '-' must be bigint",
    name: 'negate-operand-not-bigint',
    source: stateless(
      `    const b: boolean = true;
    assert(-b > 0n);`,
    ),
  },
  {
    target: "Operand of '~' must be bigint or ByteString",
    name: 'bitnot-operand-not-bigint',
    source: stateless(
      `    const b: boolean = true;
    assert(~b > 0n);`,
    ),
  },
  {
    target: 'Cannot compare',
    name: 'compare-mixed-types',
    source: stateless(
      `    const b: boolean = true;
    assert(x === b);`,
    ),
  },
  {
    target: "Left operand of '*' must be boolean",
    name: 'logical-left-not-boolean',
    source: stateless(`    assert(x && true);`),
  },
  {
    target: "Right operand of '*' must be boolean",
    name: 'logical-right-not-boolean',
    source: stateless(`    assert(true && x);`),
  },
  {
    target: "Left operand of '*' must be bigint or ByteString",
    name: 'bitwise-left-not-bigint',
    source: stateless(
      `    const b: boolean = true;
    assert((b & x) > 0n);`,
    ),
  },
  {
    target: "Right operand of '*' must be bigint or ByteString",
    name: 'bitwise-right-not-bigint',
    source: stateless(
      `    const b: boolean = true;
    assert((x & b) > 0n);`,
    ),
  },

  // ------------------------------------------------------------------
  // 03-typecheck: intrinsics
  // ------------------------------------------------------------------
  {
    target: 'getStateScript() takes no arguments',
    name: 'getstatescript-with-args',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = this.getStateScript(1n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len' },
    ),
  },
  {
    target: 'addOutput() is only available in StatefulSmartContract',
    name: 'addoutput-in-stateless',
    source: stateless(
      `    this.addOutput(1000n, x);
    assert(x > 0n);`,
    ),
  },
  {
    target: 'addRawOutput() first argument (satoshis) must be bigint',
    name: 'addrawoutput-satoshis-not-bigint',
    source: stateful(
      `    this.count = this.count + x;
    this.addRawOutput(true, 'aabb');
    assert(x > 0n);`,
    ),
  },
  {
    target: 'addDataOutput() is only available in StatefulSmartContract',
    name: 'adddataoutput-in-stateless',
    source: stateless(
      `    this.addDataOutput(1000n, 'aabb');
    assert(x > 0n);`,
    ),
  },
  {
    target: 'addDataOutput() expects 2 arguments',
    name: 'adddataoutput-arity',
    source: stateful(
      `    this.count = this.count + x;
    this.addDataOutput(1000n);
    assert(x > 0n);`,
    ),
  },
  {
    target: 'addDataOutput() first argument (satoshis) must be bigint',
    name: 'adddataoutput-satoshis-not-bigint',
    source: stateful(
      `    this.count = this.count + x;
    this.addDataOutput(true, 'aabb');
    assert(x > 0n);`,
    ),
  },
  {
    target: 'addDataOutput() second argument (scriptBytes) must be ByteString',
    name: 'adddataoutput-script-not-bytestring',
    source: stateful(
      `    this.count = this.count + x;
    this.addDataOutput(1000n, 5n);
    assert(x > 0n);`,
    ),
  },
  {
    target: "Unknown method 'this.",
    name: 'unknown-this-method',
    source: stateless(
      `    this.nope(x);
    assert(x > 0n);`,
    ),
  },
  {
    target: 'assert() expects 1 or 2 arguments',
    name: 'assert-arity',
    source: stateless(`    assert(x > 0n, 'a', 'b');`),
  },
  {
    target: 'assert() condition must be boolean',
    name: 'assert-condition-not-boolean',
    source: stateless(`    assert(x);`),
  },
  {
    target: 'checkMultiSig() expects 2 arguments',
    name: 'checkmultisig-arity',
    source: stateless(`    assert(checkMultiSig(x));`, {
      imports: 'SmartContract, assert, checkMultiSig',
    }),
  },

  // ------------------------------------------------------------------
  // 02-validate: asm() / UnsafeSmartContract
  // ------------------------------------------------------------------
  {
    target: "'asm' is only available in contracts extending UnsafeSmartContract",
    name: 'asm-in-safe-contract',
    source: stateless(
      `    asm({ body: '51', in_arity: 0, out_arity: 1 });
    assert(x > 0n);`,
      { imports: 'SmartContract, assert, asm' },
    ),
  },
  {
    target: 'asm() body must be a non-empty hex string literal',
    name: 'asm-body-empty',
    source: unsafe(`    asm({ body: '', in_arity: 0, out_arity: 1 });`),
  },
  {
    target: 'asm() body has odd hex length',
    name: 'asm-body-odd-length',
    source: unsafe(`    asm({ body: '515', in_arity: 0, out_arity: 1 });`),
  },
  {
    target: 'asm() body contains non-hex characters',
    name: 'asm-body-non-hex',
    source: unsafe(`    asm({ body: 'zz', in_arity: 0, out_arity: 1 });`),
  },
  {
    target: 'Expression-form asm<*>() must have out_arity 1',
    name: 'asm-expression-out-arity',
    source: unsafe(
      `    const v: bigint = asm<bigint>({ body: '5152', in_arity: 0, out_arity: 2 });
    assert(v > 0n);`,
    ),
  },
  {
    target: "Public method '*' must end with an assert() call or a terminal asm({...}) with out_arity 1",
    name: 'unsafe-method-no-terminal',
    source: unsafe(
      `    asm({ body: '51', in_arity: 0, out_arity: 1 });
    const v: bigint = 1n;`,
    ),
  },

  // ------------------------------------------------------------------
  // 02-validate: deploy-time slots and covenant warnings
  // ------------------------------------------------------------------
  {
    target: 'has no initializer and is not assigned a constructor parameter',
    name: 'property-no-initializer-no-param',
    source: `import { SmartContract, assert } from 'runar-lang';

export class Neg extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
    this.b = this.a;
  }

  public go(x: bigint) {
    assert(x > this.a + this.b);
  }
}
`,
  },
  {
    target: 'reads extractLocktime but does not assert',
    name: 'locktime-without-sequence-guard',
    source: stateful(
      `    this.count = this.count + x;
    assert(extractLocktime(this.txPreimage) > 500000n);`,
      { imports: 'StatefulSmartContract, assert, extractLocktime' },
    ),
  },

  // ------------------------------------------------------------------
  // 03-typecheck: intrinsic arity, index bounds and preimage intrinsics
  // ------------------------------------------------------------------
  {
    target: '* operator requires bigint',
    name: 'increment-not-bigint',
    source: stateless(
      `    let b: boolean = true;
    b++;
    assert(x > 0n);`,
    ),
  },
  {
    target: 'affine value',
    name: 'sig-consumed-twice',
    source: `import { SmartContract, assert, checkSig, Sig, PubKey } from 'runar-lang';

export class Neg extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public go(s: Sig) {
    assert(checkSig(s, this.pk));
    assert(checkSig(s, this.pk));
  }
}
`,
  },
  {
    target: "*() expects * argument(s), got *",
    name: 'builtin-arity',
    source: stateless(
      `    assert(len() > 0n);`,
      { imports: 'SmartContract, assert, len' },
    ),
  },
  {
    target: 'Argument * of *(): expected',
    name: 'builtin-argument-type',
    source: stateless(
      `    assert(len(true) > 0n);`,
      { imports: 'SmartContract, assert, len' },
    ),
  },
  {
    target: '*() is only available in StatefulSmartContract methods',
    name: 'requireoutput-in-stateless',
    source: stateless(
      `    requireOutputP2PKH(0n, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'SmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: '*() argument 1 (index) must be an integer literal',
    name: 'requireoutput-index-not-literal',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(x, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: '*() argument 1 (index) must be >= 0',
    name: 'requireoutput-index-negative',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(-1n, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: '*() argument 1 (index) must fit in int64',
    name: 'requireoutput-index-overflow',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(99999999999999999999999999n, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    // W2: the bound used to be <= 1000; any literal index above 0 is refused
    // now, because `outputIndex * 34` is an output boundary only at 0.
    target: 'requireOutputP2PKH() argument 1 (outputIndex) must be 0 in v1',
    name: 'requireoutput-index-nonzero',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(5000n, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: 'mixes requireOutputP2PKH() with addDataOutput()',
    name: 'requireoutput-mixed-with-data-output',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(1n, 'aabb', 1000n);
    this.addDataOutput(0n, 'aabb');
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: 'calls requireOutputP2PKH(0, ...) but also mutates state',
    name: 'requireoutput-zero-with-state-mutation',
    source: stateful(
      `    this.count = this.count + x;
    requireOutputP2PKH(0n, 'aabb', 1000n);
    assert(x > 0n);`,
      { imports: 'StatefulSmartContract, assert, requireOutputP2PKH' },
    ),
  },
  {
    target: 'extractPrevOutputScript() expects 2 or 3 arguments',
    name: 'extractprevoutput-arity',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
  {
    target: "Argument 2 of extractPrevOutputScript(): expected 'ByteString'",
    name: 'extractprevoutput-arg2-type',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n, 5n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
  {
    target: 'argument 3 (prefixLen) must be an integer literal when supplied',
    name: 'extractprevoutput-prefixlen-not-literal',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n, 'aabb', x);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
  {
    target: 'argument 3 (prefixLen) must fit in int64',
    name: 'extractprevoutput-prefixlen-overflow',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n, 'aabb', 99999999999999999999999999n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
  {
    target: 'argument 3 (prefixLen) must be >= 32',
    name: 'extractprevoutput-prefixlen-too-small',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n, 'aabb', 2n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
  {
    target: 'argument 3 (prefixLen) must be <= MAX_SCRIPT_BYTES',
    name: 'extractprevoutput-prefixlen-too-large',
    source: stateful(
      `    this.count = this.count + x;
    const s: ByteString = extractPrevOutputScript(0n, 'aabb', 99999999n);
    assert(len(s) > 0n);`,
      { imports: 'StatefulSmartContract, assert, ByteString, len, extractPrevOutputScript' },
    ),
  },
];
