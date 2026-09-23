// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const restrictImports = (...patterns) => ({
  '@typescript-eslint/no-restricted-imports': ['error', { patterns }],
});

// The protocol layer takes a `Dial` and a `TlsFactory` and names no runtime.
// That is what lets the handshakes, the TLS pump and the HTTP client all be
// tested against in-memory streams instead of a Worker.
const runtimeFree = {
  regex: '^(cloudflare:|node:|bun:|deno)',
  message: 'Only src/workers/ may name a runtime; everything else takes a Dial.',
};

const noModuleState = [
  'Program > VariableDeclaration[kind="let"]',
  'Program > ExportNamedDeclaration > VariableDeclaration[kind="let"]',
].map((selector) => ({
  selector,
  message: 'No module-level mutable state: one isolate serves many requests.',
}));

export default tseslint.config(
  { ignores: ['**/node_modules/', 'rust-tls/', '.wrangler/'] },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      'max-lines': ['error', { max: 300, skipBlankLines: true, skipComments: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['**/*.{js,mjs}'],
    extends: [tseslint.configs.disableTypeChecked],
  },
  {
    files: ['src/**/*.ts'],
    ignores: ['src/workers/**/*.ts'],
    rules: {
      ...restrictImports(runtimeFree),
      'no-restricted-syntax': ['error', ...noModuleState],
    },
  },
  {
    // Generated data, one browser after another; its length is the catalogue's.
    files: ['src/fingerprint/browsers.ts'],
    rules: { 'max-lines': 'off' },
  },
);
