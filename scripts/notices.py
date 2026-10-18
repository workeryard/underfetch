#!/usr/bin/env python3
"""Writes THIRD-PARTY-NOTICES.md: the licence texts of every crate compiled
into rust-tls/pkg/underfetch_tls_bg.wasm, which the package distributes.

Only what ends up in the WebAssembly counts: the crates reachable from
rust-tls by normal dependencies, for the wasm32 target. Build-time crates —
proc macros such as syn and quote — are left out, as they are not shipped.
Each crate's own LICENSE, COPYING and NOTICE files are copied as they are.

    make notices
"""

import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust-tls"
OUT = ROOT / "THIRD-PARTY-NOTICES.md"
TARGET = "wasm32-unknown-unknown"

meta = json.loads(
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--filter-platform", TARGET],
        cwd=CRATE,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)
packages = {p["id"]: p for p in meta["packages"]}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
root = meta["resolve"]["root"]


def shipped(pkg: dict) -> bool:
    """A proc macro runs in the compiler and is never in the binary."""
    return not any("proc-macro" in t["kind"] for t in pkg["targets"])


seen: set[str] = set()
todo = [root]
while todo:
    node = nodes[todo.pop()]
    for dep in node["deps"]:
        if not any(k["kind"] is None for k in dep["dep_kinds"]):
            continue  # dev and build dependencies
        if dep["pkg"] in seen or not shipped(packages[dep["pkg"]]):
            continue
        seen.add(dep["pkg"])
        todo.append(dep["pkg"])

NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")


def normal(text: str) -> str:
    """The text with its whitespace evened out, to tell copies apart."""
    return " ".join(text.split())


# Identical texts — the Apache licence above all — are written once, with
# every crate that ships them; a text that differs, even by a copyright line,
# stands on its own.
texts: dict[str, dict] = {}
crates = []
missing = []
for pkg in sorted((packages[i] for i in seen), key=lambda p: (p["name"], p["version"])):
    folder = pathlib.Path(pkg["manifest_path"]).parent
    files = sorted(f for f in folder.iterdir() if f.is_file() and f.name.upper().startswith(NAMES))
    # A crate in a workspace may keep its licence at the workspace root.
    if not files and (folder.parent / "LICENSE").exists():
        files = sorted(f for f in folder.parent.iterdir() if f.name.upper().startswith(NAMES))
    if not files:
        missing.append(pkg["name"])
    label = f"{pkg['name']} {pkg['version']}"
    crates.append(
        f"| {label} | {pkg.get('license') or 'see its texts'} | {pkg.get('repository') or 'crates.io'} |"
    )
    for f in files:
        text = f.read_text(errors="replace").strip()
        entry = texts.setdefault(normal(text), {"text": text, "names": set(), "crates": []})
        entry["names"].add(f.name)
        entry["crates"].append(label)

sections = []
for n, entry in enumerate(sorted(texts.values(), key=lambda e: (-len(e["crates"]), e["crates"][0])), 1):
    sections.append(
        f"### Text {n}: {', '.join(sorted(entry['names']))}\n\n"
        f"Shipped by: {', '.join(entry['crates'])}\n\n```\n{entry['text']}\n```"
    )

OUT.write_text(
    "# Third-party notices\n\n"
    "`rust-tls/pkg/underfetch_tls_bg.wasm` is compiled from the crates below,\n"
    "rustls among them in a fork kept under `rust-tls/vendor/`. Their licence\n"
    "texts follow as each crate ships them, each identical text once. Generated\n"
    "by `scripts/notices.py`; do not edit.\n\n"
    "| crate | licence | source |\n| --- | --- | --- |\n"
    + "\n".join(crates)
    + "\n\n## Licence texts\n\n"
    + "\n\n".join(sections)
    + "\n"
)
print(f"{len(crates)} crates, {len(sections)} distinct texts, in {OUT.name}")
if missing:
    raise SystemExit(f"no licence file found for: {', '.join(missing)}")
