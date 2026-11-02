// Vitest 5 no longer walks up to a parent directory's config, so
// `cd conformance && npx vitest run …` would otherwise drop the root src
// aliases (see mutation/README.md) and the `**/dist/**` exclude.
export { default } from '../vitest.config.js';
