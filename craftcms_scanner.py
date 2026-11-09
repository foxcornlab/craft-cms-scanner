#!/usr/bin/env python3
"""Detection-only local triage for the Craft CMS November 2026 batch.

Headline flaw is CVE-2026-123488 (CVSS 3.1 9.8): unauthenticated SQL
injection in the Craft CMS element search endpoint. The `attribute`
parameter is concatenated into the query unsanitized, and because Craft
runs PDO with emulated prepared statements, stacked statements execute.
An unauthenticated remote attacker gets read and write access to the
application database, enough to set the admin flag on user ID 1 or
overwrite any account's password hash, which is administrator takeover.
The same 4.18.9 / 5.11.2 releases fix three more flaws: CVE-2026-123489
(authenticated blind SQL injection via getNext/getPrev, 7.1),
CVE-2026-123490 (authenticated privilege escalation via getOwners(),
8.8, 5.x only), and CVE-2026-123491 (unauthenticated SQL injection via
GraphQL eager-loading, 8.2).

The fix shipped on 17 September 2026, the vendor advisory followed on
22 October, and the CVE records did not appear until 6 November, seven
weeks after the patch, with a public proof of concept published the same
day. A patch trigger that watches only CVE feeds had nothing to act on
for seven weeks. There is no confirmed in-the-wild exploitation and the
flaw is not in CISA KEV, but the PoC is public and the bug is trivially
reachable, so a version check the day the CVE lands is worth doing.

This tool sends no traffic, probes no server, and sends no crafted
request. It only compares Craft CMS version strings you supply, or a
version it reads from a local composer.lock, against the fixed releases.
A VULNERABLE grade means the version is below the fix; it does not mean
the site was compromised, and a PATCHED grade does not prove it was never
attacked. If compromise is suspected, preserve evidence and rotate
credentials before upgrading, because an upgrade alone does not undo a
stolen password hash or a planted admin account.

Usage:
    python3 craftcms_scanner.py --version 5.11.1
    python3 craftcms_scanner.py --version 4.18.9
    python3 craftcms_scanner.py --local /var/www/craft
    python3 craftcms_scanner.py --version-file version.txt
    python3 craftcms_scanner.py --inventory-json sites.json
    python3 craftcms_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input). UNKNOWN does not change the
exit code, but it is not clean: an unparseable, bare, or out-of-table
version has not been cleared, it has simply not been graded.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CVE_ID = "CVE-2026-123488"
# Fixed releases for the whole batch, per the CVE records (published
# 6 November 2026) and the vendor advisories. Both branches fix the
# batch in the same release: 4.18.9 for Craft 4, 5.11.2 for Craft 5.
FIXED = {
    4: (4, 18, 9),
    5: (5, 11, 2),
}
# Earliest affected version on each branch. Craft 3 and older are outside
# the advisory table entirely, so they grade UNKNOWN, never clean.
AFFECTED_MIN = {
    4: (4, 0, 0),
    5: (5, 0, 0),
}
# Per-CVE detail. Scores are CVSS 3.1 as scored by VulnCheck (the CNA);
# where the CVSS 4.0 score differs it is noted in the README. The
# "min" entry overrides AFFECTED_MIN for that CVE: CVE-2026-123490 only
# affects Craft 5 from 5.8.17, so a 5.0.0 install is NOT-AFFECTED for
# that CVE while still VULNERABLE to the other three.
CVES = {
    "CVE-2026-123488": {
        "score": "9.8",
        "auth": "unauthenticated",
        "title": "SQL injection, element search endpoint",
        "min": {4: (4, 0, 0), 5: (5, 0, 0)},
    },
    "CVE-2026-123489": {
        "score": "7.1",
        "auth": "authenticated control panel user",
        "title": "blind SQL injection, getNext/getPrev criteria",
        "min": {4: (4, 0, 0), 5: (5, 0, 0)},
    },
    "CVE-2026-123490": {
        "score": "8.8",
        "auth": "authenticated control panel user",
        "title": "privilege escalation, getOwners() sandbox bypass",
        "min": {5: (5, 8, 17)},
    },
    "CVE-2026-123491": {
        "score": "8.2",
        "auth": "unauthenticated",
        "title": "SQL injection, GraphQL eager-load select",
        "min": {4: (4, 0, 0), 5: (5, 0, 0)},
    },
}

_VERSION_RE = re.compile(
    r"^\s*v?(\d+)\.(\d+)\.(\d+)(?:\.\d+)?\s*$"
)


def parse_version(text):
    """Return (major, minor, patch) or None for an unparseable string.

    Accepts an optional leading `v` and an optional fourth numeric
    segment, which is ignored. A bare `4.18` or `5.11` has no patch
    number and is rejected: it cannot be graded.
    """
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def format_version(version):
    return ".".join(str(part) for part in version)


def grade_cve(cve_id, version):
    """Grade one CVE for a parsed version tuple.

    Returns one of PATCHED, VULNERABLE, NOT-AFFECTED, UNKNOWN.
    """
    detail = CVES[cve_id]
    branch = version[0]
    if branch not in FIXED:
        return "UNKNOWN"
    minimum = detail["min"].get(branch)
    if minimum is None:
        # This CVE never affected this branch: CVE-2026-123490 is 5.x only.
        return "NOT-AFFECTED"
    if version < minimum:
        return "NOT-AFFECTED"
    if version >= FIXED[branch]:
        return "PATCHED"
    return "VULNERABLE"


def grade(version_text):
    """Grade one version string against the whole batch.

    Returns a dict with grade, per_cve, fixed, and note keys. Grades:
    PATCHED, VULNERABLE, UNKNOWN. NOT-AFFECTED only appears inside the
    per-CVE table, never as the overall grade.
    """
    version = parse_version(version_text)
    if version is None:
        return {
            "grade": "UNKNOWN",
            "per_cve": {},
            "fixed": None,
            "note": f"version {version_text!r} does not parse as a Craft "
            "CMS release like 5.11.1; a bare 5.11 with no patch number "
            "cannot be graded, and is not clean",
        }
    branch = version[0]
    if branch not in FIXED:
        return {
            "grade": "UNKNOWN",
            "per_cve": {},
            "fixed": None,
            "note": f"Craft {branch}.x is outside the advisory table, "
            "which covers 4.x and 5.x only. Craft 3 reached end of life "
            "before this batch and has no published mapping for it, so it "
            "has not been cleared, only left ungraded; migrate to a "
            "supported line, do not treat it as safe",
        }
    per_cve = {cve_id: grade_cve(cve_id, version) for cve_id in CVES}
    fixed = FIXED[branch]
    if "VULNERABLE" in per_cve.values():
        vulnerable = [c for c, g in per_cve.items() if g == "VULNERABLE"]
        note = (
            f"vulnerable to {', '.join(vulnerable)}; upgrade to "
            f"{format_version(fixed)} or later"
        )
        if branch == 4:
            note += (
                "; 4.18.9 is the final 4.x release, Craft 4 reached end "
                "of security support on 30 April 2026, so plan the move "
                "to Craft 5 after patching"
            )
        return {
            "grade": "VULNERABLE",
            "per_cve": per_cve,
            "fixed": format_version(fixed),
            "note": note,
        }
    note = (
        f"at or above the fixed {format_version(fixed)} for the whole "
        "batch"
    )
    if branch == 4:
        note += (
            "; 4.18.9 is the final 4.x release, Craft 4 reached end of "
            "security support on 30 April 2026, so this install is "
            "patched for this batch but the line gets no further "
            "security fixes, plan the move to Craft 5"
        )
    return {
        "grade": "PATCHED",
        "per_cve": per_cve,
        "fixed": format_version(fixed),
        "note": note,
    }


def detect_local(path):
    """Read the installed Craft CMS version from a project's composer.lock.

    Returns the version string (leading `v` stripped). Raises ValueError
    when the lock file is missing, unreadable, or has no craftcms/cms
    package: a project without a lock file has not been graded.
    """
    root = Path(path)
    lock_path = root / "composer.lock"
    if not root.is_dir():
        raise ValueError(f"local path {path} is not a directory")
    if not lock_path.is_file():
        raise ValueError(
            f"no composer.lock in {path}; this tool grades the installed "
            "version from the lock file, not from a version constraint in "
            "composer.json"
        )
    try:
        data = json.loads(lock_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {lock_path}: {exc}") from exc
    for section in ("packages", "packages-dev"):
        for package in data.get(section, []):
            if isinstance(package, dict) and package.get("name") == "craftcms/cms":
                version = str(package.get("version", "")).strip()
                if not version:
                    raise ValueError(
                        f"craftcms/cms in {lock_path} has no version"
                    )
                return version.lstrip("v")
    raise ValueError(f"no craftcms/cms package in {lock_path}")


def read_version_file(path):
    try:
        text = Path(path).read_text().strip()
    except OSError as exc:
        raise ValueError(f"cannot read version file {path}: {exc}") from exc
    if not text:
        raise ValueError(f"version file {path} is empty")
    return text.splitlines()[0].strip()


def render(result, version_text, label=None, source=None):
    lines = []
    if label:
        lines.append(f"[{label}]")
    if source:
        lines.append(f"source:     {source}")
    lines.append(f"version:    {version_text}")
    lines.append(f"grade:      {result['grade']}")
    if result["fixed"]:
        lines.append(f"fixed in:   {result['fixed']}")
    for cve_id, cve_grade in result["per_cve"].items():
        detail = CVES[cve_id]
        lines.append(
            f"  {cve_id} ({detail['score']}, {detail['auth']}): {cve_grade}"
        )
    lines.append(f"note:       {result['note']}")
    return "\n".join(lines)


def load_inventory(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("inventory JSON must be a list of entries")
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each inventory entry must be an object")
        if "version" not in entry and "local" not in entry:
            raise ValueError(
                "each inventory entry needs a 'version' or 'local' key"
            )
    return data


def grade_entry(entry):
    """Grade one inventory entry, resolving `local` paths to versions."""
    if "version" in entry:
        return entry["version"], None
    version = detect_local(entry["local"])
    return version, f"composer.lock in {entry['local']}"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for the Craft CMS November 2026 batch (CVE-2026-123488 et al.)."
    )
    parser.add_argument("--version", help="Craft CMS version, e.g. 5.11.1")
    parser.add_argument("--local", help="project directory holding a composer.lock")
    parser.add_argument("--version-file", help="file holding the version, e.g. version.txt")
    parser.add_argument("--inventory-json", help="JSON list of version/local entries")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--list", action="store_true", help="print the advisory table")
    args = parser.parse_args(argv)

    if args.list:
        for branch in (4, 5):
            print(
                f"Craft {branch}.x: {format_version(AFFECTED_MIN[branch])} "
                f"through {format_version((FIXED[branch][0], FIXED[branch][1], FIXED[branch][2] - 1))} "
                f"affected, fixed in {format_version(FIXED[branch])} and later"
            )
        print("CVE-2026-123490 affects Craft 5 only, from 5.8.17")
        return 0
    if args.inventory_json:
        try:
            entries = load_inventory(args.inventory_json)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        results = []
        vulnerable = False
        for entry in entries:
            try:
                version, source = grade_entry(entry)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = grade(version)
            if result["grade"] == "VULNERABLE":
                vulnerable = True
            results.append({
                "label": entry.get("label"),
                "version": version,
                "source": source,
                **result,
            })
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for result in results:
                print(render(result, result["version"],
                             label=result["label"], source=result["source"]))
                print()
        return 2 if vulnerable else 0
    version = None
    source = None
    if args.version:
        version = args.version
    elif args.local:
        try:
            version = detect_local(args.local)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        source = f"composer.lock in {args.local}"
    elif args.version_file:
        try:
            version = read_version_file(args.version_file)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        source = args.version_file
    else:
        parser.error("--version, --local, or --version-file is required (or --inventory-json / --list)")
    result = grade(version)
    if args.json:
        print(json.dumps({
            "version": version,
            "source": source,
            **result,
        }, indent=2))
    else:
        print(render(result, version, source=source))
    return 2 if result["grade"] == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
