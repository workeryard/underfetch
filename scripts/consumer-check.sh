#!/usr/bin/env bash
# Typechecks the package as a project that installs it sees it: packed into a
# tarball, installed into a throwaway Worker project, imported and compiled
# against @cloudflare/workers-types. A link or this repository's own
# typecheck cannot show what goes wrong only inside node_modules — 0.1.0
# shipped a .wasm import that failed exactly there.
#
#   make consumer-check
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
types="$root/.cache/workers-types/node_modules/@cloudflare/workers-types"
[ -d "$types" ] || { echo "run make typecheck-workers once first, to fetch the Workers types"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$(cd "$root" && npm pack --silent --pack-destination "$work")"

mkdir -p "$work/app/src" "$work/app/node_modules/@cloudflare"
cd "$work/app"
echo '{ "name": "consumer", "private": true, "type": "module" }' > package.json
pnpm add --silent "$work/$tarball" >/dev/null
ln -s "$types" node_modules/@cloudflare/workers-types

# What every caller writes, against a Worker's usual tsconfig.
cat > src/index.ts <<'TS'
import { Session, profiles, timingOf, type Impersonation } from '@workeryard/underfetch/workers';
import { fetchOver } from '@workeryard/underfetch';

const profile: Impersonation = profiles.chrome;

export default {
  async fetch(): Promise<Response> {
    const session = new Session({ impersonate: 'chrome' });
    const response = await session.get('https://example.com/');
    await session.close();
    return Response.json({
      ja4: profile.expected.ja4,
      timing: timingOf(response),
      primitive: typeof fetchOver,
    });
  },
};
TS

# `using`, which TypeScript allows only with the esnext.disposable lib.
mkdir -p disposable
cat > disposable/index.ts <<'TS'
import { Session } from '@workeryard/underfetch/workers';

export async function once(url: string): Promise<number> {
  await using session = new Session({ impersonate: 'firefox' });
  using spare = new Session();
  void spare;
  return (await session.get(url)).status;
}
TS

config() {
  cat <<JSON
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": [$1],
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true
  },
  "include": ["$2"]
}
JSON
}
config '"ES2023"' src > tsconfig.json
config '"ES2023", "ESNext.Disposable"' disposable > tsconfig.disposable.json

tsc="$root/node_modules/.bin/tsc"
"$tsc" -p tsconfig.json
"$tsc" -p tsconfig.disposable.json
echo "consumer typecheck passes for $tarball: a Worker's tsconfig, and with using"
