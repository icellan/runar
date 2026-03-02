import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      'runar-testing': resolve(__dirname, 'packages/runar-testing/src/index.ts'),
      'runar-compiler': resolve(__dirname, 'packages/runar-compiler/src/index.ts'),
      'runar-ir-schema': resolve(__dirname, 'packages/runar-ir-schema/src/index.ts'),
      'runar-lang': resolve(__dirname, 'packages/runar-lang/src/index.ts'),
    },
  },
});
