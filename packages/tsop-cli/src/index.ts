// ---------------------------------------------------------------------------
// tsop-cli — programmatic API re-exports
// ---------------------------------------------------------------------------
// Allows other packages to import CLI commands directly without going
// through the CLI entry point.

export { initCommand } from './commands/init.js';
export { compileCommand } from './commands/compile.js';
export { testCommand } from './commands/test.js';
export { deployCommand } from './commands/deploy.js';
export { verifyCommand } from './commands/verify.js';
