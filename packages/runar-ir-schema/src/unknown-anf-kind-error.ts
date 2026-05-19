/**
 * Typed error thrown by ANF / Stack-IR / constant-fold dispatch sites when
 * they encounter an ANFValue kind they don't recognize.
 *
 * Historically these dispatchers used silent `default:` fall-throughs that
 * returned a no-op value (empty refs list, unchanged ANFValue, `false` for
 * side-effect checks). Adding a new ANFValue variant and forgetting to wire
 * it into all 14 dispatch sites (see CLAUDE.md § Adding a New ANF Value Kind)
 * would then silently corrupt output instead of failing loudly.
 *
 * Every former silent default now throws this error so the regression is
 * caught at the first dispatch site instead of leaking into Stack IR / hex.
 */
export class UnknownANFKindError extends Error {
  readonly kind: string;
  readonly location: string;

  constructor(kind: string, location: string) {
    super(
      `Unknown ANF kind '${kind}' encountered in ${location} — ` +
      `if you added a new ANFValue variant, update all dispatch sites ` +
      `(see CLAUDE.md § Adding a New ANF Value Kind for the 14-step recipe).`,
    );
    this.name = 'UnknownANFKindError';
    this.kind = kind;
    this.location = location;
  }
}
