import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'runar-compiler': path.resolve(__dirname, '../../packages/runar-compiler/src'),
      'runar-sdk': path.resolve(__dirname, '../../packages/runar-sdk/src'),
      'runar-lang': path.resolve(__dirname, '../../packages/runar-lang/src'),
      'runar-ir-schema': path.resolve(__dirname, '../../packages/runar-ir-schema/src'),
      'runar-testing': path.resolve(__dirname, '../../packages/runar-testing/src'),
    },
  },
  test: {
    testTimeout: 600_000,
    hookTimeout: 600_000,
    globalSetup: './setup.ts',
  },
});
