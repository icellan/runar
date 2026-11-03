// Vitest 5 no longer walks up to a parent directory's config, so `vitest run`
// from this package (turbo `test`, `cd packages/... && npx vitest run`) would
// otherwise drop the root src aliases and the `**/dist/**` exclude.
export { default } from '../../vitest.config.js';
