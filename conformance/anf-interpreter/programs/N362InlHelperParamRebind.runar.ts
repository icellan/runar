import { StatefulSmartContract } from 'runar-lang';

/**
 * N-362 — an output-emitting private helper is inlined into its caller at ANF
 * level. Its parameter `a` is reassigned straight-line and in both arms of an
 * if/else before the helper commits it through `addOutput`. The compiler binds
 * a reassigned helper parameter as a local of the inlined scope, so the ANF
 * carries `a = @ref:<arg>` followed by its rebindings; the committed state is
 * `(x * 10 + (c ? 1 : 2)) + count`, never the caller's argument `x + count`.
 */
class N362InlHelperParamRebind extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private emit(a: bigint, c: boolean): void {
    a = a * 10n;
    if (c) {
      a = a + 1n;
    } else {
      a = a + 2n;
    }
    this.addOutput(1000n, a + this.count);
  }

  public m(x: bigint, c: boolean) {
    this.emit(x, c);
  }
}
