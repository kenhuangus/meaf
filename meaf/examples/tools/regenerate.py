#!/usr/bin/env python3
"""Regenerate the shipped example packages' digests, signatures and keyring.

The example evidence has to be signed by something, and a real signing key
cannot be committed. This script derives a demo Ed25519 key from a fixed,
published seed so that anyone can reproduce the shipped bytes exactly:

    python meaf/examples/tools/regenerate.py --check

reports whether the committed examples still match what this script produces.
The test suite runs the same check, so a hand edit to an example that forgets to
re-sign is caught rather than shipped.

THE DEMO KEY IS NOT SECRET. Its seed is three lines below. It exists so the
pilot's signature path is exercised end to end. Never accept evidence signed by
it as assurance for anything, and never place it in a production keyring.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

EXAMPLES = Path(__file__).resolve().parent.parent
DEMO_KEY_SEED_PHRASE = b"meaf-example-demo-key-do-not-use-in-production"

#: Which components each evidence item was collected against. Written out rather
#: than inferred so that the binding in the example is a stated relationship, not
#: an artifact of whatever the script happened to compute.
EVIDENCE_SUBJECTS: dict[str, dict[str, list[str]]] = {
    "covert-influence.json": {
        "ev-counterfactual-run-2026-07": ["cmp-foundation-model", "cmp-rag-corpus"],
        "ev-model-attestation": ["cmp-foundation-model"],
        "ev-corpus-manifest": ["cmp-rag-corpus"],
        "ev-evaluator-prompt-attestation": ["cmp-evaluator-prompt"],
        "ev-containment-drill-2026-07": [
            "cmp-foundation-model",
            "cmp-rag-corpus",
            "cmp-evaluator-prompt",
        ],
    },
    "memory-poisoning.json": {
        "ev-memory-quarantine-drill-2026-06": ["cmp-agent-memory", "cmp-planner-graph"],
        "ev-memory-store-attestation": ["cmp-agent-memory"],
        "ev-planner-graph-attestation": ["cmp-planner-graph"],
        "ev-poison-write-probe-2026-05": ["cmp-agent-memory"],
    },
}

#: Evidence whose model-metadata binds an evaluator prompt to a component.
PROMPT_BINDINGS: dict[str, dict[str, str]] = {
    "covert-influence.json": {"ev-counterfactual-run-2026-07": "cmp-evaluator-prompt"},
    "memory-poisoning.json": {},
}


def demo_private_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(DEMO_KEY_SEED_PHRASE).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_payload(evidence: dict) -> bytes:
    unsigned = {key: value for key, value in evidence.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def rebuild(package: dict, package_name: str, private_key: Ed25519PrivateKey) -> dict:
    """Recompute every digest and signature in ``package`` from the artifacts."""
    digests: dict[str, str] = {}
    for component in package["components"]:
        artifact_path = component.get("artifact-path")
        if not artifact_path:
            continue
        digest = file_digest(EXAMPLES / artifact_path)
        component["digest"] = digest
        digests[component["id"]] = digest

    subjects = EVIDENCE_SUBJECTS.get(package_name, {})
    prompts = PROMPT_BINDINGS.get(package_name, {})

    for evidence in package["evidence"]:
        evidence_id = evidence["id"]
        component_ids = subjects.get(evidence_id)
        if component_ids is not None:
            evidence["subject-digests"] = [
                digests[component_id]
                for component_id in component_ids
                if component_id in digests
            ]
        prompt_component = prompts.get(evidence_id)
        if prompt_component and isinstance(evidence.get("model-metadata"), dict):
            evidence["model-metadata"]["evaluator-prompt-digest"] = digests[prompt_component]
        evidence.pop("signature", None)
        evidence["signature"] = {
            "algorithm": "ed25519",
            "key-id": evidence["collector"],
            "value": base64.b64encode(
                private_key.sign(canonical_payload(evidence))
            ).decode("ascii"),
        }
    return package


def build_keyring(packages: list[dict], private_key: Ed25519PrivateKey) -> dict[str, str]:
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base64.b64encode(public_bytes).decode("ascii")
    collectors = {
        evidence["collector"]
        for package in packages
        for evidence in package["evidence"]
    }
    return {collector: encoded for collector in sorted(collectors)}


def serialize(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def regenerate(check_only: bool = False) -> int:
    private_key = demo_private_key()
    rebuilt: dict[Path, str] = {}
    packages: list[dict] = []

    for package_name in sorted(EVIDENCE_SUBJECTS):
        path = EXAMPLES / package_name
        if not path.is_file():
            continue
        package = json.loads(path.read_text(encoding="utf-8"))
        package = rebuild(package, package_name, private_key)
        packages.append(package)
        rebuilt[path] = serialize(package)

    rebuilt[EXAMPLES / "keyring.json"] = serialize(build_keyring(packages, private_key))

    drift = 0
    for path, content in sorted(rebuilt.items()):
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == content:
            continue
        drift += 1
        if check_only:
            print(f"out of date: {path.relative_to(EXAMPLES.parent.parent)}")
        else:
            path.write_text(content, encoding="utf-8")
            print(f"rewrote: {path.relative_to(EXAMPLES.parent.parent)}")

    if check_only and drift == 0:
        print("examples are up to date")
    return 1 if (check_only and drift) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without rewriting anything (exit 1 when out of date)",
    )
    args = parser.parse_args(argv)
    return regenerate(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
