"""Command line entry point.

Exit codes follow the usual monitoring convention: 0 means no finding at or
above the selected threshold, 1 means there was one, and 2 is an auditor error
or a usage error. The default threshold is `warning`; `--fail-on` changes it to
`critical` (only serious findings) or `info` (any finding). A degraded audit
always exits 1, whatever the threshold. With `--since`, the threshold applies to
new or worsened findings, and the default is any regression.
"""

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from .auditor import audit, audit_with_coverage, check_prefixes, list_checks  # noqa: F401 - audit is a public seam

# Lower is worse; a rise means the finding got more severe. The same ranking
# drives --since comparisons and the --fail-on threshold so they cannot disagree.
_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

# Bump when the report shape changes in a way a consumer must know about.
# v2 adds generated_at and coverage; --since keeps reading v1 findings only.
REPORT_VERSION = 2


def _generated_at() -> str:
    """UTC ISO-8601 with an explicit Z, so a report carries its run time."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _coverage_from_findings(findings) -> dict:
    """Coverage for the injected-findings seam, where no readers actually ran.

    A degraded finding still carries its reader map; mirror it so a test that
    injects one sees the same coverage a real audit would produce.
    """
    degraded = []
    for finding in findings:
        if finding.get("check") != "auditor.degraded":
            continue
        readers = (finding.get("evidence") or {}).get("readers") or {}
        if isinstance(readers, dict):
            degraded = sorted(str(name) for name in readers)
    return {"readers": 0, "degraded": degraded}


def _payload(findings, coverage, generated_at=None) -> dict:
    return {
        "version": REPORT_VERSION,
        "generated_at": generated_at if generated_at is not None else _generated_at(),
        "host": platform.node(),
        "coverage": coverage,
        "findings": findings,
        "counts": _counts(findings),
    }


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="volt-watch",
        description="Audit a Tailscale-managed Linux host for health and safety problems.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the findings as JSON instead of plain text (alias for --format json)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "ndjson"),
        help=(
            "output format: text (default), a single JSON document, or NDJSON "
            "with a meta line followed by one line per finding"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the plain-text report; the exit code still reports problems",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="also write the JSON report to FILE, so the next run can compare against it",
    )
    parser.add_argument(
        "--since",
        metavar="FILE",
        help="compare against a previous --output report and exit non-zero only for new or worsened findings",
    )
    parser.add_argument(
        "--check",
        metavar="PREFIX",
        help="run only the checks whose name starts with PREFIX, e.g. --check power",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="print registered check groups, prefixes, and finding names, then exit",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "warning", "info"),
        help=(
            "minimum severity that makes the exit code 1 (default: warning; "
            "with --since, any new or worsened finding)"
        ),
    )
    args = parser.parse_args(argv)
    if args.list_checks and (args.since is not None or args.output is not None):
        parser.error("--list-checks cannot be used with --since or --output")
    return args


def _finding_key(finding):
    """The identity of a finding: what it is and the values that justify it.

    The message is excluded on purpose — it can carry volatile values, and a
    reworded finding is the same finding.
    """
    return (finding["check"], json.dumps(finding.get("evidence"), sort_keys=True))


def _valid_finding(finding) -> bool:
    """Whether a baseline entry has everything the comparison reads.

    The report is machine-written but hand-editable, so one broken entry must
    not take the whole run down. Anything the comparison would choke on is
    rejected here and dropped from the baseline.
    """
    if not isinstance(finding, dict):
        return False
    if not isinstance(finding.get("check"), str):
        return False
    if finding.get("severity") not in _SEVERITY_RANK:
        return False
    try:
        json.dumps(finding.get("evidence"), sort_keys=True)
    except (TypeError, ValueError):
        return False
    return True


def _regressions(current, previous):
    """Return the findings that are new or worse than the previous report."""
    before = {_finding_key(f): f["severity"] for f in previous}
    worse = []
    for finding in current:
        key = _finding_key(finding)
        if key not in before:
            worse.append(finding)
        elif _SEVERITY_RANK[finding["severity"]] < _SEVERITY_RANK[before[key]]:
            worse.append(finding)
    return worse


def _read_baseline(path):
    """Read a previous report, or None when it is missing or unreadable.

    Only well-formed findings come back; the number dropped is returned so the
    caller can say the comparison was partial. A file that is not a report at
    all is treated as no baseline, as before.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, 0
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        return None, 0
    good = [f for f in findings if _valid_finding(f)]
    return good, len(findings) - len(good)


def _counts(findings):
    counts = {"total": len(findings), "critical": 0, "warning": 0, "info": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def _report(findings):
    for finding in findings:
        print(f"{finding['severity']:<9} {finding['check']}: {finding['message']}")
        if finding["remedy"]:
            print(f"          remedy: {finding['remedy']}")
    print(f"{len(findings)} finding(s)")


def _print_ndjson(payload: dict) -> None:
    """One JSON object per line: a meta record, then each finding in order.

    The meta record carries everything except the findings themselves, so a
    consumer can start with `head -1` for version/coverage/counts and stream
    the rest without loading the whole report.
    """
    meta = {key: value for key, value in payload.items() if key != "findings"}
    meta["record"] = "meta"
    print(json.dumps(meta, separators=(",", ":")))
    for finding in payload["findings"]:
        print(json.dumps(finding, separators=(",", ":")))


def _at_or_above(findings, threshold: str) -> bool:
    """Whether any finding is at least as severe as ``threshold``."""
    limit = _SEVERITY_RANK[threshold]
    return any(_SEVERITY_RANK[f["severity"]] <= limit for f in findings)


def _exit_code(findings, threshold: str, baseline) -> int:
    """Decide the exit code from the findings the run actually selected.

    An incomplete audit is never green, whatever the threshold. With a
    baseline only new or worsened findings count; without one every finding
    counts. ``auditor.baseline_invalid`` describes the tool, not the host.
    """
    if any(f["check"] == "auditor.degraded" for f in findings):
        return 1
    if baseline is not None:
        host = [f for f in findings if f["check"] != "auditor.baseline_invalid"]
        return 1 if _at_or_above(_regressions(host, baseline), threshold) else 0
    return 1 if _at_or_above(findings, threshold) else 0


def main(argv=None, findings=None) -> int:
    """Run the audit and print the report.

    ``findings`` is a test seam: when supplied, the audit is skipped and those
    findings are reported instead.
    """
    try:
        args = _parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        # Usage errors become a normal exit code; --help keeps argparse's
        # usual SystemExit(0) so callers that capture it still work.
        if exc.code == 0:
            raise
        return 2

    fmt = args.format or "text"
    machine_readable = bool(args.json) or fmt in ("json", "ndjson")

    if args.list_checks:
        groups = list_checks()
        if fmt == "ndjson":
            print(json.dumps({"version": REPORT_VERSION, "checks": groups}, separators=(",", ":")))
        elif machine_readable:
            print(json.dumps({"version": REPORT_VERSION, "checks": groups}, indent=2))
        elif not args.quiet:
            for entry in groups:
                prefixes = ", ".join(entry["prefixes"])
                print(f"{entry['group']} (prefixes: {prefixes})")
                for name in entry["findings"]:
                    print(f"  - {name}")
        return 0

    if args.check and not any(p.startswith(args.check) for p in check_prefixes()):
        available = ", ".join(check_prefixes())
        message = f"unknown check prefix {args.check!r}; available: {available}"
        if machine_readable:
            payload = _payload([], {"readers": 0, "degraded": []})
            print(json.dumps({**payload, "error": message}, indent=2))
        elif not args.quiet:
            print(f"volt-watch: error: {message}", file=sys.stderr)
        return 2

    if findings is None:
        audited, coverage = audit_with_coverage(only=args.check)
        findings = [f.as_dict() for f in audited]
    else:
        coverage = _coverage_from_findings(findings)

    baseline, dropped = _read_baseline(args.since) if args.since else (None, 0)
    if args.since and baseline is None:
        findings = findings + [
            {
                "check": "auditor.no_baseline",
                "severity": "info",
                "message": f"No readable baseline at {args.since}; nothing to compare against",
                "remedy": "Run once with --output to create the baseline.",
                "evidence": {"since": args.since},
            }
        ]

    if dropped:
        findings = findings + [
            {
                "check": "auditor.baseline_invalid",
                "severity": "warning",
                "message": (
                    f"{dropped} baseline finding(s) could not be read; "
                    "this comparison is incomplete"
                ),
                "remedy": f"Inspect {args.since} or delete it, then run once with --output.",
                "evidence": {"since": args.since, "dropped": dropped},
            }
        ]

    payload = _payload(findings, coverage)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            message = f"could not write {args.output!r}: {exc}"
            if machine_readable:
                print(json.dumps({**payload, "error": message}, indent=2))
            else:
                print(f"volt-watch: error: {message}", file=sys.stderr)
            return 2

    if fmt == "ndjson":
        _print_ndjson(payload)
    elif machine_readable:
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        _report(findings)

    # No explicit threshold means today's behaviour: warning and above, or
    # any regression when comparing against a baseline.
    threshold = args.fail_on or ("info" if baseline is not None else "warning")
    return _exit_code(findings, threshold, baseline)


if __name__ == "__main__":
    sys.exit(main())
