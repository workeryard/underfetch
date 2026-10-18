/**
 * What `import wasm from './underfetch_tls_bg.wasm'` gives: Wrangler and Vite
 * hand a `.wasm` import over as a compiled `WebAssembly.Module`.
 *
 * Copied over the declaration wasm-bindgen writes beside the module on every
 * build. Its named exports — the raw memory and `__wbg_*` functions — describe
 * an instance nothing here imports, and with them TypeScript refuses the
 * default import in a project that installs the package.
 */
declare const module: WebAssembly.Module;
export default module;
