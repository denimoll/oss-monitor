"""
Version comparison and fix-version resolution.

Answers the question a vulnerability report should always answer but rarely
does: *which version do I upgrade to in order to clear this?*

Comparison is deliberately ecosystem-agnostic and loose. A correct comparator
would need one implementation per ecosystem (PEP 440, SemVer, Maven, RPM's
`rpmvercmp`, Debian's epoch rules …); this one handles the shapes that actually
appear in OSV and NVD data — dotted numbers plus the usual pre-release markers —
and is only ever used to order versions *within a single package*, where the
maintainer's own scheme is self-consistent.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Markers that sort *before* the plain release they qualify: 2.0-rc1 < 2.0.
_PRERELEASE = {
    "alpha", "a", "beta", "b", "rc", "cr", "pre", "preview",
    "dev", "snapshot", "milestone", "m", "nightly",
}

# Markers that sort *after* the release they qualify: 1.2.3.post1 > 1.2.3.
_POSTRELEASE = {"post", "rev", "sp"}

# Ordering ranks for one version segment, lowest first: a pre-release marker
# sorts below everything, then an unrecognised word, then a number, then a
# post-release marker.
_RANK_PRERELEASE = 0
_RANK_WORD = 1
_RANK_NUMBER = 2
_RANK_POSTRELEASE = 3

# The implicit value of a missing trailing segment is numeric zero, so
# "2.0" == "2.0.0" while still being greater than "2.0-rc1" and less than
# "2.0.1".
_PAD = (_RANK_NUMBER, 0, "")

_SEGMENT_RE = re.compile(r"\d+|[a-zA-Z]+")


def _segments(version: str) -> list[tuple[int, int, str]]:
    """Split a version string into comparable segments."""
    out = []
    for part in _SEGMENT_RE.findall(version.lower()):
        if part.isdigit():
            out.append((_RANK_NUMBER, int(part), ""))
        elif part in _PRERELEASE:
            out.append((_RANK_PRERELEASE, 0, part))
        elif part in _POSTRELEASE:
            out.append((_RANK_POSTRELEASE, 0, part))
        else:
            out.append((_RANK_WORD, 0, part))
    return out


def compare_versions(left: str, right: str) -> int:
    """
    Return -1 / 0 / 1 for left < / == / > right.

    Unparseable input falls back to a plain string comparison rather than
    raising — a weird version must not break a whole refresh.
    """
    if left == right:
        return 0
    try:
        a, b = _segments(left), _segments(right)
    except Exception:  # pragma: no cover — defensive
        a = b = None
    if not a or not b:
        return (left > right) - (left < right)

    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else _PAD
        y = b[i] if i < len(b) else _PAD
        if x != y:
            return -1 if x < y else 1
    return 0


def version_lt(left: str, right: str) -> bool:
    return compare_versions(left, right) < 0


def version_gte(left: str, right: str) -> bool:
    return compare_versions(left, right) >= 0


def max_version(versions) -> str | None:
    """The highest version in an iterable, or None if it is empty."""
    highest = None
    for v in versions:
        if v and (highest is None or compare_versions(v, highest) > 0):
            highest = v
    return highest


# ── OSV range resolution ──────────────────────────────────────────────────────

def _intervals(events: list[dict]):
    """
    Yield `(introduced, fixed_or_None)` pairs from an OSV `range.events` list.

    A single range can carry several introduced/fixed pairs — a vulnerability
    reintroduced after a fix, or one patched on several release branches. The
    events are ordered, so pairing is a linear walk. `last_affected` closes an
    interval with no known fix.
    """
    introduced = None
    for event in events:
        if "introduced" in event:
            if introduced is not None:
                yield introduced, None
            introduced = event["introduced"]
        elif "fixed" in event:
            if introduced is not None:
                yield introduced, event["fixed"]
                introduced = None
        elif "last_affected" in event:
            if introduced is not None:
                yield introduced, None  # this branch was never fixed
                introduced = None
    if introduced is not None:
        yield introduced, None


def _package_matches(affected: dict, package_name: str) -> bool:
    """
    Whether an OSV `affected` entry describes the package we asked about.

    An advisory routinely lists sibling packages — the Log4Shell entry covers
    `org.ops4j.pax.logging:pax-logging-log4j2` alongside log4j-core — and their
    fix versions are meaningless for us.
    """
    name = (affected.get("package") or {}).get("name") or ""
    return name.lower() == (package_name or "").lower()


def find_fixed_version(vuln: dict, package_name: str, current_version: str) -> str | None:
    """
    The version that fixes `vuln` for `package_name` at `current_version`.

    Picks the fix belonging to the range our version actually falls into, which
    is not the same as the lowest fix in the advisory: Log4Shell's follow-up
    lists both `[2.13.0, 2.16.0)` and `[0, 2.12.2)` for log4j-core, and a 2.14.1
    install must be told 2.16.0 — 2.12.2 is a backport of a branch it is not on.

    Returns None when no range applies, when the affected branch was never
    fixed, or when the data cannot be interpreted.
    """
    candidates = []

    for affected in vuln.get("affected") or []:
        if not _package_matches(affected, package_name):
            continue

        for rng in affected.get("ranges") or []:
            # GIT ranges carry commit hashes, not versions we can compare.
            if rng.get("type") == "GIT":
                continue
            for introduced, fixed in _intervals(rng.get("events") or []):
                if introduced not in (None, "0") and version_lt(current_version, introduced):
                    continue  # our version predates this range
                if fixed is not None and version_gte(current_version, fixed):
                    continue  # our version is at or past this fix
                if fixed is not None:
                    candidates.append(fixed)

    # Several branches can legitimately match (overlapping ranges); the lowest
    # fix that still covers us is the smallest upgrade that clears the finding.
    if not candidates:
        return None
    lowest = candidates[0]
    for candidate in candidates[1:]:
        if compare_versions(candidate, lowest) < 0:
            lowest = candidate
    return lowest


# ── Component-level remediation ───────────────────────────────────────────────

def build_remediation(current_version: str, vulns: list) -> dict | None:
    """
    Turn per-CVE fix versions into one upgrade recommendation.

    Returns None when nothing is fixable. Otherwise reports the lowest version
    that clears everything fixable, plus the intermediate steps, so "upgrade to
    2.17.1 and 6 of 7 findings go away" is answerable at a glance.
    """
    fixable = [v for v in vulns if getattr(v, "fixed_version", None)]
    if not fixable:
        return None

    target = max_version(v.fixed_version for v in fixable)
    if target is None or version_gte(current_version, target):
        return None

    # Every distinct fix version is a possible stopping point; report how much
    # each one buys, so a team blocked on a major bump can still see the win
    # from a smaller one.
    steps = []
    for version in sorted({v.fixed_version for v in fixable}, key=_segments):
        cleared = sum(1 for v in fixable if version_gte(version, v.fixed_version))
        steps.append({"version": version, "clears": cleared})

    return {
        "recommended_version": target,
        "clears": len(fixable),
        "total": len(vulns),
        "unfixable": len(vulns) - len(fixable),
        "steps": steps,
    }
