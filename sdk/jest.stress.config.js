/**
 * Stress suite config. Same transform/ESM setup as the base gate, but matches
 * ONLY tests/stress. Run serially via `npm run test:stress` (the suite pushes
 * up to 250k concurrent calls and must not share memory with parallel workers).
 */
/** @type {import('jest').Config} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  testMatch: ['**/tests/stress/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/'],
};
