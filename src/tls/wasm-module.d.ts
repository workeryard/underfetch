/** Wrangler and Vite hand a `.wasm` import over as an instantiated module. */
declare module '*.wasm' {
  const module: WebAssembly.Module;
  export default module;
}
