"""CLI entry point: ``python -m meaf <command> ...`` (or the ``meaf`` script).

This module parses arguments, calls library functions, and formats output. It
holds no assurance logic: anything that decides whether a claim holds lives in a
library module so that it can be tested without a subprocess and reused without
a shell.

Exit codes are part of the interface, because the point of the tool is to gate
pipelines:

    validate     0 clean, 1 conformance errors
    gate         0 allow, 1 block, 2 review-required
    run-tests    0 every executed contract passed and nothing was left unrun
    lifecycle    0 transition granted, 1 refused
    attest       0 every artifact matches, 1 drift, missing or out of root
    migrate      0 migration complete, 1 decisions still required
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meaf.adoption import assess_adoption, format_adoption
from meaf.attest import (
    attestation_exit_code,
    check_attestation,
    default_root_for_package,
    format_attestation_records,
    update_attestation,
)
from meaf.contract import GATE_ALLOW, GATE_BLOCK, evaluate_gate, format_gate
from meaf.impact import analyse_change, format_impact
from meaf.lifecycle import attempt_transition, format_status
from meaf.migrate import format_report, migrate_package
from meaf.model import parse_datetime
from meaf.oscal import export_oscal
from meaf.packs import format_registry
from meaf.policy import PolicyError, resolve_policy
from meaf.report import build_report
from meaf.signing import load_keyring
from meaf.summary import conformance_summary, format_summary
from meaf.testpack import (
    findings_for_failures,
    format_run_results,
    link_evidence_to_contracts,
    load_signing_key,
    merge_evidence,
    merge_findings,
    run_exit_code,
    run_tests,
    unrunnable_tests,
)
from meaf.validator import format_findings, has_errors, load_package, validate_package

GATE_EXIT_CODES = {GATE_ALLOW: 0, GATE_BLOCK: 1}
GATE_REVIEW_EXIT_CODE = 2


def _resolve_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    return parse_datetime(value)


def _write_json(path: Path, document: Any) -> None:
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _add_common(parser: argparse.ArgumentParser, *, policy: bool = True, now: bool = True) -> None:
    parser.add_argument("package", type=Path, help="path to the package JSON")
    if policy:
        parser.add_argument(
            "--policy",
            type=Path,
            help="policy bundle JSON (default: the bundle shipped with meaf)",
        )
    if now:
        parser.add_argument(
            "--now",
            help="evaluation instant as RFC 3339, for reproducible results "
            "(default: current time)",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meaf",
        description="MAESTRO Executable Assurance Framework tools",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate", help="run the six conformance levels over a package"
    )
    _add_common(validate)
    validate.add_argument("--json", action="store_true", help="emit findings as JSON")
    validate.add_argument(
        "--keyring", type=Path, help="Ed25519 public keyring for level 4 signature checks"
    )
    validate.add_argument(
        "--root",
        type=Path,
        help="attestation root for artifact-path resolution "
        "(default: the package file's directory)",
    )

    gate = subparsers.add_parser(
        "gate", help="evaluate assurance-contract states and the gate decision"
    )
    _add_common(gate)
    gate.add_argument("--json", action="store_true", help="emit the gate result as JSON")
    gate.add_argument(
        "--keyring", type=Path, help="Ed25519 public keyring for level 4 signature checks"
    )
    gate.add_argument("--root", type=Path, help="attestation root")

    summary = subparsers.add_parser(
        "summary", help="report the eight conformance-summary dimensions"
    )
    _add_common(summary)
    summary.add_argument("--json", action="store_true", help="emit the summary as JSON")

    report = subparsers.add_parser(
        "report", help="generate the Markdown assurance report with diagrams"
    )
    _add_common(report)
    report.add_argument(
        "--output", type=Path, help="write the report here instead of standard output"
    )

    run = subparsers.add_parser("run-tests", help="execute test runners and emit evidence")
    _add_common(run)
    run.add_argument("--test", help="run only the test with this id")
    run.add_argument(
        "--sign-with", type=Path, help="Ed25519 private key PEM for signing emitted evidence"
    )
    run.add_argument("--output", type=Path, help="write the updated package here")
    run.add_argument(
        "--link-evidence",
        action="store_true",
        help="point each exercised contract's required-evidence at the run just performed",
    )
    run.add_argument(
        "--create-findings",
        action="store_true",
        help="create findings for contracts that failed, as the assess activity requires",
    )

    lifecycle = subparsers.add_parser(
        "lifecycle", help="inspect or advance the package lifecycle state"
    )
    _add_common(lifecycle)
    lifecycle.add_argument("--to", help="target state (omit to inspect every guard)")
    lifecycle.add_argument("--actor", default="unknown", help="responsible role making the change")
    lifecycle.add_argument("--reason", default="", help="reason recorded in history")
    lifecycle.add_argument("--output", type=Path, help="write the updated package here")
    lifecycle.add_argument("--keyring", type=Path, help="Ed25519 public keyring")
    lifecycle.add_argument("--root", type=Path, help="attestation root")

    export = subparsers.add_parser("export-oscal", help="export OSCAL 1.1.2 documents")
    _add_common(export)
    export.add_argument("--out-dir", type=Path, required=True, help="output directory")

    attest = subparsers.add_parser("attest", help="check or update artifact attestations")
    _add_common(attest, policy=False, now=False)
    attest.add_argument("--root", type=Path, help="attestation root")
    attest.add_argument(
        "--update",
        action="store_true",
        help="rebind component digests to what is on disk (evidence bindings are never rewritten)",
    )
    attest.add_argument(
        "--output",
        type=Path,
        help="write the updated package here; without it --update refuses to overwrite",
    )
    attest.add_argument(
        "--in-place",
        action="store_true",
        help="allow --update to overwrite the package file itself",
    )
    attest.add_argument("--json", action="store_true", help="emit records as JSON")

    impact = subparsers.add_parser(
        "impact", help="report what a component change would invalidate"
    )
    _add_common(impact)
    impact.add_argument(
        "--changed",
        action="append",
        default=[],
        metavar="COMPONENT_ID",
        help="component that is changing; repeat for several",
    )
    impact.add_argument("--json", action="store_true", help="emit the analysis as JSON")

    migrate = subparsers.add_parser("migrate", help="migrate a 1.0.0 package to 2.0.0")
    _add_common(migrate, policy=False, now=False)
    migrate.add_argument("--output", type=Path, help="write the migrated package here")

    adoption = subparsers.add_parser(
        "adoption", help="assess the non-normative A.9 adoption level"
    )
    _add_common(adoption)
    adoption.add_argument("--keyring", type=Path, help="Ed25519 public keyring")
    adoption.add_argument("--root", type=Path, help="attestation root")
    adoption.add_argument("--json", action="store_true", help="emit the assessment as JSON")

    subparsers.add_parser("testpacks", help="list the nine standard test packs")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "testpacks":
        print(format_registry())
        return 0

    package = load_package(args.package)

    # A 1.0.0 package fails level 1 on every renamed field, which buries the one
    # thing the operator needs to know.
    if (
        args.command != "migrate"
        and isinstance(package, dict)
        and package.get("meaf-version") == "1.0.0"
    ):
        print(
            "note: this is a MEAF 1.0.0 package. Run "
            f"`meaf migrate {args.package} --output <new>` first; see "
            "docs/MIGRATION-1.0-TO-2.0.md",
            file=sys.stderr,
        )

    try:
        policy = resolve_policy(getattr(args, "policy", None))
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    now = _resolve_now(getattr(args, "now", None))
    root = getattr(args, "root", None) or default_root_for_package(args.package)
    keyring = load_keyring(args.keyring) if getattr(args, "keyring", None) else None

    if args.command == "validate":
        findings = validate_package(
            package, now=now, keyring=keyring, root=root, policy=policy
        )
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            print(format_findings(findings))
        return 1 if has_errors(findings) else 0

    if args.command == "gate":
        # A gate result computed over a package that does not conform is not a
        # gate result. Contract states are only meaningful once references
        # resolve and evidence is attributable, so conformance errors block
        # before any contract is evaluated.
        conformance = [
            finding
            for finding in validate_package(
                package, now=now, keyring=keyring, root=root, policy=policy
            )
            if finding.severity == "error"
        ]
        result = evaluate_gate(package, now=now, policy=policy)
        if conformance:
            result = replace(
                result,
                decision=GATE_BLOCK,
                reasons=(
                    f"package has {len(conformance)} conformance error(s); the first is "
                    f"L{conformance[0].level} {conformance[0].object_id or '(package)'}: "
                    f"{conformance[0].message}",
                    *result.reasons,
                ),
            )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(format_gate(result))
        return GATE_EXIT_CODES.get(result.decision, GATE_REVIEW_EXIT_CODE)

    if args.command == "summary":
        document = conformance_summary(package, now=now, policy=policy)
        print(json.dumps(document, indent=2) if args.json else format_summary(document))
        return 0

    if args.command == "report":
        document = build_report(package, now=now, policy=policy)
        if args.output:
            args.output.write_text(document, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(document, end="")
        return 0

    if args.command == "run-tests":
        sign_with = load_signing_key(args.sign_with) if args.sign_with else None
        results = run_tests(
            package,
            test_id=args.test,
            sign_with=sign_with,
            now=now,
            cwd=args.package.resolve().parent,
        )
        skipped = unrunnable_tests(package, args.test)
        print(format_run_results(results, skipped))

        if args.output:
            updated = merge_evidence(package, [result.evidence for result in results])
            if args.link_evidence:
                updated = link_evidence_to_contracts(updated, results)
            if args.create_findings:
                new_findings = findings_for_failures(updated, results, now=now)
                updated = merge_findings(updated, new_findings)
                for finding in new_findings:
                    print(f"created finding {finding['id']} for {finding['failed-claim']}")
            _write_json(args.output, updated)
            print(f"wrote {args.output}")
        else:
            for result in results:
                print(json.dumps(result.evidence, indent=2))
        return run_exit_code(results, skipped)

    if args.command == "lifecycle":
        if args.to is None:
            print(
                format_status(package, now=now, keyring=keyring, root=root, policy=policy)
            )
            return 0
        transition, updated = attempt_transition(
            package,
            args.to,
            actor=args.actor,
            reason=args.reason,
            now=now,
            keyring=keyring,
            root=root,
            policy=policy,
        )
        verdict = "granted" if transition.granted else "refused"
        print(
            f"Transition {verdict}: {transition.from_state} -> {transition.to_state} "
            f"({transition.reason})"
        )
        if transition.granted and args.output:
            _write_json(args.output, updated)
            print(f"wrote {args.output}")
        return 0 if transition.granted else 1

    if args.command == "export-oscal":
        for path in export_oscal(package, args.out_dir, now=now, policy=policy):
            print(path)
        return 0

    if args.command == "attest":
        if args.update:
            destination = args.output or (args.package if args.in_place else None)
            if destination is None:
                print(
                    "error: --update needs --output PATH, or --in-place to overwrite "
                    "the package file",
                    file=sys.stderr,
                )
                return 2
            updated, changes = update_attestation(package, root)
            _write_json(destination, updated)
            for change in changes:
                print(change)
            if not changes:
                print("no digest changes required")
            print(f"wrote {destination}")
            return 0

        records = check_attestation(package, root)
        print(
            json.dumps(records, indent=2) if args.json else format_attestation_records(records)
        )
        return attestation_exit_code(records)

    if args.command == "impact":
        if not args.changed:
            print("error: --changed COMPONENT_ID is required", file=sys.stderr)
            return 2
        analysis = analyse_change(package, args.changed, now=now, policy=policy)
        print(
            json.dumps(analysis.to_dict(), indent=2) if args.json else format_impact(analysis)
        )
        return 0

    if args.command == "migrate":
        try:
            migrated, report = migrate_package(package)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.output:
            _write_json(args.output, migrated)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(migrated, indent=2))
        print(format_report(report), file=sys.stderr)
        return 0 if report.complete else 1

    if args.command == "adoption":
        reached, criteria = assess_adoption(
            package, now=now, keyring=keyring, root=root, policy=policy
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "level-reached": reached,
                        "criteria": [criterion.to_dict() for criterion in criteria],
                    },
                    indent=2,
                )
            )
        else:
            print(format_adoption(reached, criteria))
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
