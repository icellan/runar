import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      'tsop-testing': resolve(__dirname, 'packages/tsop-testing/src/index.ts'),
      'tsop-compiler': resolve(__dirname, 'packages/tsop-compiler/src/index.ts'),
      'tsop-ir-schema': resolve(__dirname, 'packages/tsop-ir-schema/src/index.ts'),
      'tsop-lang': resolve(__dirname, 'packages/tsop-lang/src/index.ts'),
    },
  },
});
