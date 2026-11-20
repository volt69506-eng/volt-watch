"""Command line entry point.

Exit codes follow the usual monitoring convention: 0 means no problem worth
acting on, 1 means at least one warning or critical finding, 2 is reserved for
the auditor itself failing. ``info`` findings never change the exit code.
"""

import argparse
import json
import platform
import sys
from pathlib import Path

from .auditor import audit, check_prefixes

# The exit code a finding severity contributes to.
_EXIT_BY_SEVERITY = {"critical": 1, "warning": 1, "info": 0}

# Lower is worse; a rise means the finding got more severe.
_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

# Bump when the report shape changes in a way a consumer must know about.
REPORT_VERSION = 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="volt-watch",
        description="Audit a Tailscale-managed Linux host for health and safety problems.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the findings as JSON instead of plain text",
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
    return parser.parse_args(argv)


def _finding_key(finding):
    """The identity of a finding: what it is and the values that justify it.

    The message is excluded on purpose — it can carry volatile values, and a
    reworded finding is the same finding.
    """
    return (finding["check"], json.dumps(finding.get("evidence"), sort_keys=True))


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
    """Read a previous report, or None when it is missing or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    findings = data.get("findings") if isinstance(data, dict) else None
    return findings if isinstance(findings, list) else None


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


def main(argv=None, findings=None) -> int:
    """Run the audit and print the report.

    ``findings`` is a test seam: when supplied, the audit is skipped and those
    findings are reported instead.
    """
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if args.check and not any(p.startswith(args.check) for p in check_prefixes()):
        available = ", ".join(check_prefixes())
        message = f"unknown check prefix {args.check!r}; available: {available}"
        if args.json:
            print(json.dumps({"findings": [], "counts": {"total": 0, "critical": 0, "warning": 0, "info": 0}, "error": message}, indent=2))
        elif not args.quiet:
            print(f"volt-watch: error: {message}", file=sys.stderr)
        return 2

    if findings is None:
        findings = [f.as_dict() for f in audit(only=args.check)]

    baseline = _read_baseline(args.since) if args.since else None
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

    payload = {
        "version": REPORT_VERSION,
        "host": platform.node(),
        "findings": findings,
        "counts": _counts(findings),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        _report(findings)

    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if baseline is not None:
        # Compared against the last report, only a new or worsened finding is a
        # regression; one that cleared up is the good outcome.
        return 1 if _regressions(findings, baseline) else 0

    worst = max((_EXIT_BY_SEVERITY[f["severity"]] for f in findings), default=0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
