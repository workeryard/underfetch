/**
 * `Symbol.dispose` and `Symbol.asyncDispose`, which a session is closed by
 * when `using` goes out of scope.
 *
 * Both runtimes have them — Node 20 and workerd — but TypeScript lists them
 * only in its `esnext.disposable` lib, which neither our configurations nor
 * a Worker project compiling this source may have. They are declared here,
 * as the lib declares them: TypeScript merges the two where both are present,
 * which was checked with `ES2022`, `ES2024`, `ESNext`, `@types/node` and
 * `@cloudflare/workers-types`.
 */

declare global {
  interface SymbolConstructor {
    readonly dispose: unique symbol;
    readonly asyncDispose: unique symbol;
  }
}

export {};
