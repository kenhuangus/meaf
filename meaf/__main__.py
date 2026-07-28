"""CLI entry point: python -m meaf <command> ..."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from meaf.lifecycle import attempt_transition, current_state, format_status, legal_next_states
from meaf.oscal import export_oscal
from meaf.signing import load_keyring
from meaf.testpack import format_run_results, load_signing_key, merge_evidence, run_tests
from meaf.validator import format_findings, has_errors, load_package, validate_package


def _resolve_keyring(path: Path | None) -> dict[str, bytes] | None:
    if path is None:
        return None
    return load_keyring(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="meaf", description="MEAF package tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate a MEAF package")
    validate_parser.add_argument("package", type=Path, help="Path to package JSON")
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON findings",
    )
    validate_parser.add_argument(
        "--keyring",
        type=Path,
        help="Path to Ed25519 public keyring JSON for L4 signature verification",
    )

    run_tests_parser = subparsers.add_parser(
        "run-tests",
        help="Execute test-pack runners and emit evidence",
    )
    run_tests_parser.add_argument("package", type=Path, help="Path to package JSON")
    run_tests_parser.add_argument("--test", help="Run only the test with this id")
    run_tests_parser.add_argument(
        "--sign-with",
        type=Path,
        help="Path to Ed25519 private key PEM for signing emitted evidence",
    )
    run_tests_parser.add_argument(
        "--output",
        type=Path,
        help="Write updated package with new evidence to this path",
    )

    lifecycle_parser = subparsers.add_parser(
        "lifecycle",
        help="Inspect or advance package lifecycle state",
    )
    lifecycle_parser.add_argument("package", type=Path, help="Path to package JSON")
    lifecycle_parser.add_argument("--to", help="Target lifecycle state")
    lifecycle_parser.add_argument("--actor", default="unknown", help="Actor for history")
    lifecycle_parser.add_argument("--reason", default="", help="Reason for transition")
    lifecycle_parser.add_argument(
        "--output",
        type=Path,
        help="Write updated package on successful transition",
    )
    lifecycle_parser.add_argument(
        "--keyring",
        type=Path,
        help="Path to Ed25519 public keyring JSON",
    )

    export_parser = subparsers.add_parser(
        "export-oscal",
        help="Export package to OSCAL 1.1.2 JSON artifacts",
    )
    export_parser.add_argument("package", type=Path, help="Path to package JSON")
    export_parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Output directory for OSCAL files",
    )

    args = parser.parse_args(argv)

    if args.command == "validate":
        package = load_package(args.package)
        keyring = _resolve_keyring(args.keyring)
        findings = validate_package(package, keyring=keyring)
        if args.json:
            payload = [f.to_dict() for f in findings]
            print(json.dumps(payload, indent=2))
        else:
            print(format_findings(findings))
        return 1 if has_errors(findings) else 0

    if args.command == "run-tests":
        package = load_package(args.package)
        sign_with = load_signing_key(args.sign_with) if args.sign_with else None
        results = run_tests(
            package,
            test_id=args.test,
            sign_with=sign_with,
            cwd=Path.cwd(),
        )
        print(format_run_results(results))
        if args.output:
            updated = merge_evidence(package, [r.evidence for r in results])
            with args.output.open("w", encoding="utf-8") as handle:
                json.dump(updated, handle, indent=2)
                handle.write("\n")
        else:
            for result in results:
                print(json.dumps(result.evidence, indent=2))
        return 0

    if args.command == "lifecycle":
        package = load_package(args.package)
        now = datetime.now(timezone.utc)
        keyring = _resolve_keyring(args.keyring)
        if args.to is None:
            print(format_status(package, now=now))
            next_states = legal_next_states(package, now=now, keyring=keyring)
            if next_states:
                print(f"Guarded transitions: {', '.join(next_states)}")
            return 0
        transition, updated = attempt_transition(
            package,
            args.to,
            actor=args.actor,
            reason=args.reason,
            now=now,
            keyring=keyring,
        )
        status = "granted" if transition.granted else "refused"
        print(
            f"Transition {status}: {transition.from_state} -> {transition.to_state} "
            f"({transition.reason})"
        )
        if transition.granted and args.output:
            with args.output.open("w", encoding="utf-8") as handle:
                json.dump(updated, handle, indent=2)
                handle.write("\n")
        return 0 if transition.granted else 1

    if args.command == "export-oscal":
        package = load_package(args.package)
        written = export_oscal(package, args.out_dir)
        for path in written:
            print(path)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
