# The commands this repo is worked with, so none has to be typed twice.
# `make` alone lists them.
#
#   make check                 typecheck, lint and tests
#   make wasm                  rebuild rust-tls/pkg after changing rust-tls/
#   make dev                   the dev worker on $(PORT), cache cleared
#   make live AS=chrome        every live check against it
#   make fetch URL=... [AS=chrome] [PROXY=socks5://host:1080]
#   make live REMOTE=1         the same against the deployed probe worker
#   make deploy                deploy it (every endpoint needs PROBE_TOKEN)

PORT  ?= 8799
# `:=`, not `?=`: make predefines AS as the assembler, `as`, which `?=` keeps.
AS    :=
ONLY  ?= http,tls,session,sites,websocket
URL   ?= https://httpbin.org/ip
PROXY ?=
RESOURCE ?=

# REMOTE=1 points the live targets at the deployed probe worker instead of
# `make dev`, with the token from .probe-token, which git ignores.
PROBE_URL   ?= https://probe.underfetch.workers.dev
TOKEN_FILE  ?= .probe-token
ifdef REMOTE
export PROBE_URL
export PROBE_TOKEN := $(shell cat $(TOKEN_FILE) 2>/dev/null)
endif

# Rust lives in ~/.cargo/bin, which is not on every shell's PATH.
export PATH := $(HOME)/.cargo/bin:$(PATH)

LIVE    = pnpm -s tsx scripts/live.ts
AS_FLAG = $(if $(AS),--as $(AS))
LOG     = .wrangler/dev.log
WASM    = rust-tls/pkg/underfetch_tls_bg.wasm

.DEFAULT_GOAL := help
.PHONY: help install check test typecheck typecheck-workers lint format verify wasm wasm-size notices \
        import-browsers dev dev-stop dev-restart dev-log fingerprints cases \
        resume state live fetch deploy probe-token clean

help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

install: ## install the node dependencies
	pnpm install

check: ## typecheck, lint and test, as before any commit
	pnpm check

test: ## the tests alone
	pnpm test

typecheck: ## tsc alone
	pnpm typecheck

lint: ## eslint alone
	pnpm lint

format: ## prettier over everything
	pnpm format

# A Worker compiles src/ against @cloudflare/workers-types, whose DOM-like
# types differ (a TextDecoder's ignoreBOM is required; clearTimeout takes no
# undefined). The types are fetched once into .cache/ rather than depended on.
WORKERS_TYPES = .cache/workers-types/node_modules/@cloudflare/workers-types
typecheck-workers: ## typecheck src/ the way a Worker project compiles it
	@if [ ! -d $(WORKERS_TYPES) ]; then \
	  mkdir -p .cache/workers-types && cd .cache/workers-types && \
	  npm pack @cloudflare/workers-types --silent >/dev/null && \
	  mkdir -p node_modules/@cloudflare && tar -xzf cloudflare-workers-types-*.tgz && \
	  mv package node_modules/@cloudflare/workers-types && rm -f cloudflare-workers-types-*.tgz; \
	fi
	npx tsc -p tsconfig.workers.json
	@echo "src/ typechecks under @cloudflare/workers-types $$(node -p "require('./$(WORKERS_TYPES)/package.json').version")"

verify: ## every profile's JA4 and Akamai string, offline
	pnpm verify

wasm: ## rebuild the TLS module after changing rust-tls/
	pnpm build:wasm
	@# wasm-pack writes a `*` .gitignore here on every build; the output is committed.
	@rm -f rust-tls/pkg/.gitignore
	@$(MAKE) -s wasm-size
	@$(MAKE) -s notices

# The wasm is shipped, and with it the crates compiled into it; their
# licences have to go with them. Rewritten on every wasm build.
notices: ## THIRD-PARTY-NOTICES.md from the crates compiled into the wasm
	@python3 scripts/notices.py

wasm-size: ## how big the committed wasm is
	@printf 'wasm: %s bytes, %s gzipped\n' "$$(stat -c %s $(WASM))" "$$(gzip -c $(WASM) | wc -c)"

import-browsers: ## regenerate the browsers from curl-impersonate's captures
	pnpm import:browsers
	pnpm -s prettier --write src/fingerprint/browsers/

# The dev server caches the wasm, so a stale .wrangler measures the previous
# build; it is cleared on every start.
dev: dev-stop ## start the dev worker in the background, cache cleared
	@rm -rf .wrangler/tmp .wrangler/state/v3/cache
	@mkdir -p .wrangler
	@nohup pnpm -s verify:live > $(LOG) 2>&1 &
	@for i in $$(seq 1 60); do \
	  curl -s -o /dev/null localhost:$(PORT)/fetch && { echo "dev worker on :$(PORT), log in $(LOG)"; exit 0; }; \
	  sleep 1; \
	done; echo "it did not start; see $(LOG)"; exit 1

# Killing workerd alone is not enough: its parent, node running wrangler,
# respawns it at once. So the parent goes first, then the child.
# A server that has stopped listening can still be running, so what is left
# is then found by its command line; the [w] keeps pgrep from matching the
# shell running this recipe, whose own command line holds the pattern.
dev-stop: ## stop the dev worker
	@pid=$$(ss -ltnp 2>/dev/null | grep ':$(PORT) ' | grep -oP 'pid=\K[0-9]+' | head -1); \
	if [ -n "$$pid" ]; then \
	  parent=$$(ps -o ppid= -p $$pid | tr -d ' '); \
	  kill $$parent $$pid 2>/dev/null; sleep 1; \
	fi; \
	left=$$(pgrep -f '[w]rangler.*dev --port $(PORT)'; pgrep -f '[w]orkerd serve.*entry=localhost:$(PORT)'); \
	if [ -n "$$left" ]; then kill $$left 2>/dev/null; sleep 1; fi; \
	if [ -n "$$pid$$left" ]; then echo "stopped the dev worker"; fi

dev-restart: dev-stop dev ## a fresh isolate: nothing left in wasm memory

dev-log: ## follow the dev worker's log
	tail -f $(LOG)

fingerprints: ## JA4 and Akamai as tls.peet.ws sees them [AS=name]
	$(LIVE) fingerprints $(AS_FLAG)

cases: ## the live case matrix [AS=name] [ONLY=http,tls,...]
	$(LIVE) cases $(AS_FLAG) --only $(ONLY)

resume: ## three requests in one session; the 2nd and 3rd should resume [AS=chrome]
	$(LIVE) resume --as $(or $(AS),chrome)

state: ## save a session, restart into a new isolate, load it back [AS=chrome]
	$(LIVE) state-save --as $(or $(AS),chrome)
	@$(MAKE) -s dev-restart
	$(LIVE) state-load

live: ## fingerprints, cases and resumption, one after another [AS=name]
	$(LIVE) fingerprints $(AS_FLAG)
	$(LIVE) cases $(AS_FLAG) --only $(ONLY)
	$(LIVE) resume --as $(or $(AS),chrome)

fetch: ## one request through the dev worker [URL=] [AS=] [PROXY=] [RESOURCE=fetch]
	$(LIVE) fetch --url $(URL) $(AS_FLAG) $(if $(PROXY),--proxy $(PROXY)) $(if $(RESOURCE),--resource $(RESOURCE))

deploy: ## deploy the probe worker; its endpoints demand the PROBE_TOKEN secret
	npx wrangler deploy

probe-token: ## make a new token, keep it in .probe-token, and set it as the worker's secret
	@(umask 077; openssl rand -hex 32 > $(TOKEN_FILE))
	npx wrangler secret put PROBE_TOKEN < $(TOKEN_FILE)
	@echo "new token in $(TOKEN_FILE); it takes a few seconds to reach every location"

clean: dev-stop ## remove the dev server's state and the Rust build
	rm -rf .wrangler rust-tls/target
