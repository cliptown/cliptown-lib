#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
INTERFACES_SHA = "ec4f820bcc9181c2423a6963d3890ddc8ef18b97"
ZED_CLI_SHA = "751358fe130e64b646844bc7d857c4cff215ca2d"
errors: list[str] = []

cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
zed = tomllib.loads((ROOT / ".zpkg.toml").read_text())

if cargo["package"]["name"] != "cliptown-lib":
    errors.append("Cargo package name must be cliptown-lib")
if cargo["package"]["version"] != zed["package"]["version"]:
    errors.append("Cargo and Zed package versions must match")
if cargo["package"]["rust-version"] != "1.88":
    errors.append("Cargo rust-version must remain 1.88")
if zed["package"]["org"] != "cliptown" or zed["package"]["name"] != "cliptown-lib":
    errors.append("Zed package coordinate must be cliptown/cliptown-lib")
if zed.get("dependencies", {}).get("cliptown/cliptown-interfaces") != "^0.1.0":
    errors.append("Zed package must depend on cliptown/cliptown-interfaces ^0.1.0")

cargo_dependency = cargo.get("dependencies", {}).get("cliptown-interfaces-rust", {})
if cargo_dependency.get("rev") != INTERFACES_SHA:
    errors.append("Rust interface dependency must be pinned to the reviewed merge SHA")
if cargo_dependency.get("version") != "0.1.0":
    errors.append("Rust interface dependency must retain the matching package version")
if cargo_dependency.get("package") != "cliptown-interfaces-rust":
    errors.append("Rust interface dependency must name the canonical package")

required = [
    "README.md",
    "SECURITY.md",
    "PROVENANCE.md",
    "LICENSE",
    "docs/architecture.md",
    "src/lib.rs",
    "src/error.rs",
    "src/model.rs",
    "src/policy.rs",
    "src/ports.rs",
    "src/api.rs",
    "src/contract.rs",
    "src/convergence.rs",
    "src/crypto.rs",
    "src/search.rs",
    "src/delegation.rs",
    "src/transfer.rs",
    ".github/workflows/ci.yml",
]
for path in required:
    if not (ROOT / path).is_file():
        errors.append(f"missing required package file: {path}")

zed_lock_path = ROOT / ".zpkg.lock"
if not zed_lock_path.is_file():
    errors.append("resolver-owned .zpkg.lock is required")
else:
    zed_lock = tomllib.loads(zed_lock_path.read_text())
    if zed_lock.get("version") != 1:
        errors.append(".zpkg.lock must use the supported resolver lock format")

lib_text = (ROOT / "src/lib.rs").read_text()
for required_text in [
    "pub use cliptown_interfaces_rust as interfaces;",
    "pub mod contract;",
    "pub mod convergence;",
    "pub mod crypto;",
    "pub mod search;",
    "pub use delegation::",
    "pub use transfer::",
]:
    if required_text not in lib_text:
        errors.append(f"library root missing semantic integration: {required_text}")

workflow_text = (ROOT / ".github/workflows/ci.yml").read_text()
if "actions/checkout@v" in workflow_text:
    errors.append("workflow actions must be pinned to immutable SHAs")
if ZED_CLI_SHA not in workflow_text:
    errors.append("workflow must pin the reviewed Zed CLI source")

credential_patterns = [
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"lin_api_[A-Za-z0-9]+"),
    re.compile(r"cfat_[A-Za-z0-9]+"),
]
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts or "target" in path.parts:
        continue
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        continue
    for pattern in credential_patterns:
        if pattern.search(text):
            errors.append(f"credential-shaped value found in {path.relative_to(ROOT)}")

if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)
print("validated cliptown-lib Cargo/Zed/interface package contract")
