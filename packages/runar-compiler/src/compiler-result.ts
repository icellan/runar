/**
 * CompilerResult<T> / DiagnosticList — typed wrapper that gives every
 * compiler pass a uniform recovery contract.
 *
 * Background
 * ----------
 * The Rúnar TS pipeline historically mixed two error-reporting styles:
 *
 *   - Pass 1 (parse), 2 (validate), 3 (typecheck), 3b (expandFixedArrays)
 *     return `{ contract, errors, warnings? }` shapes.
 *   - Pass 4 (anf-lower), 5 (stack-lower), 6 (emit) throw on any error.
 *
 * The top-level `compile()` boundary wraps each pass in try/catch to bridge
 * the two styles. That works but offers no shared type for downstream code
 * that wants to compose passes (the "execute next pass only if the
 * previous succeeded" pattern repeats 7+ times in `index.ts`).
 *
 * `CompilerResult<T>` is the typed enhancement. It does NOT replace the
 * existing per-pass result interfaces — those continue to work — it gives
 * callers a uniform monadic surface (`ok` / `fail` / `map` / `flatMap` /
 * `unwrap`) for composing passes. The wrapper functions in
 * `./passes/compiler-result-passes.ts` adapt each existing pass to this
 * shape without changing the pass signatures themselves.
 */

import type { CompilerDiagnostic } from './errors.js';

/**
 * Re-exported alias: the project's canonical diagnostic type.
 *
 * `CompilerResult` is generic over the value type but the diagnostic shape
 * is fixed to the project-wide `CompilerDiagnostic` so a result produced
 * by one pass can be merged with diagnostics from any other pass.
 */
export type Diagnostic = CompilerDiagnostic;

/**
 * A pair of error and warning diagnostic lists.
 *
 * Exposed so callers (CLI / SDK / conformance runner) can return the same
 * shape without re-declaring it.
 */
export interface DiagnosticList {
  errors: Diagnostic[];
  warnings: Diagnostic[];
}

/**
 * Wrapper carrying either a successful value or a list of errors, plus
 * any warnings emitted along the way.
 *
 * Invariants:
 *   - `ok === (errors.length === 0 && value !== null)`.
 *   - A failed result MUST have `value === null`.
 *   - Warnings may be present in either a successful or failed result.
 */
export class CompilerResult<T> {
  readonly value: T | null;
  readonly errors: Diagnostic[];
  readonly warnings: Diagnostic[];

  constructor(
    value: T | null,
    errors: Diagnostic[] = [],
    warnings: Diagnostic[] = [],
  ) {
    this.value = value;
    this.errors = errors;
    this.warnings = warnings;
  }

  get ok(): boolean {
    return this.errors.length === 0 && this.value !== null;
  }

  /** Construct a successful result. */
  static ok<T>(value: T, warnings: Diagnostic[] = []): CompilerResult<T> {
    return new CompilerResult<T>(value, [], warnings);
  }

  /**
   * Construct a failed result. `errors` MUST be non-empty; callers that
   * pass an empty `errors` array will produce a result whose `ok` is
   * `false` solely because `value` is `null`, which is almost certainly a
   * bug. We don't throw here because some pass error-detection paths
   * collect errors lazily, but a caller that wants the assertion can
   * check `errors.length` themselves.
   */
  static fail<T>(
    errors: Diagnostic[],
    warnings: Diagnostic[] = [],
  ): CompilerResult<T> {
    return new CompilerResult<T>(null, errors, warnings);
  }

  /**
   * Map the value through `f`. Diagnostics are preserved unchanged. If
   * this result is failed, `f` is NOT invoked and a failed result with
   * the same diagnostics is returned.
   */
  map<U>(f: (value: T) => U): CompilerResult<U> {
    if (!this.ok) return CompilerResult.fail<U>(this.errors, this.warnings);
    return CompilerResult.ok(f(this.value as T), this.warnings);
  }

  /**
   * Chain through a function that itself returns a `CompilerResult`. The
   * diagnostics from both stages are merged: errors and warnings from
   * `this` come first, then those from the inner result. If this result
   * is failed, `f` is NOT invoked.
   */
  flatMap<U>(f: (value: T) => CompilerResult<U>): CompilerResult<U> {
    if (!this.ok) return CompilerResult.fail<U>(this.errors, this.warnings);
    const next = f(this.value as T);
    return new CompilerResult<U>(
      next.value,
      [...this.errors, ...next.errors],
      [...this.warnings, ...next.warnings],
    );
  }

  /**
   * Throw the first error if this result is failed. Useful at the top of
   * the public `compile()` boundary when a caller wants exception
   * semantics. Lower-level passes SHOULD NOT call this — they should keep
   * propagating the result so the boundary can decide how to surface it.
   */
  unwrap(): T {
    if (!this.ok) {
      const first = this.errors[0];
      throw new Error(`compile failed: ${first?.message ?? 'unknown error'}`);
    }
    return this.value as T;
  }
}
