"""
Tests for version comparison, OSV fix-version resolution and the component
level upgrade recommendation.
"""

import pytest

from services.versions import (
    build_remediation,
    compare_versions,
    find_fixed_version,
    max_version,
    version_gte,
    version_lt,
)


# ── Comparison ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("left,right,expected", [
    ("1.0.0", "1.0.0", 0),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.1", -1),
    # Numeric, not lexicographic — the classic bug.
    ("1.10.0", "1.9.0", 1),
    ("1.10.8", "1.10.10", -1),
    ("2.25.4", "2.14.1", 1),
    # Missing trailing segments are release-zero.
    ("2.0", "2.0.0", 0),
    ("2.0", "2.0.1", -1),
    # Pre-release markers sort below the release they qualify.
    ("2.0-alpha1", "2.0", -1),
    ("3.0.0-beta3", "3.0.0", -1),
    ("1.0.0-rc1", "1.0.0", -1),
    ("1.0.0-rc1", "1.0.0-rc2", -1),
    ("1.0.0-alpha", "1.0.0-beta", -1),
    ("2.0.0-SNAPSHOT", "2.0.0", -1),
    # Ecosystem-flavoured shapes that still have to order sanely.
    ("1.2.3.post1", "1.2.3", 1),
    ("r27", "r22", 1),
])
def test_compare_versions(left, right, expected):
    assert compare_versions(left, right) == expected


def test_comparison_is_antisymmetric():
    pairs = [("1.0", "2.0"), ("2.0-rc1", "2.0"), ("1.10", "1.9"), ("3.0.0", "3.0.0")]
    for a, b in pairs:
        assert compare_versions(a, b) == -compare_versions(b, a)


def test_helpers():
    assert version_lt("1.0", "2.0")
    assert not version_lt("2.0", "1.0")
    assert version_gte("2.0", "2.0")
    assert version_gte("2.1", "2.0")
    assert max_version(["1.0", "2.16.0", "2.9.0"]) == "2.16.0"
    assert max_version([]) is None
    assert max_version([None, None]) is None


def test_unparseable_versions_do_not_raise():
    # Garbage must degrade to a stable ordering, never blow up a refresh.
    assert compare_versions("", "") == 0
    assert compare_versions("!!!", "???") in (-1, 0, 1)


# ── OSV range resolution ──────────────────────────────────────────────────────

PKG = "org.apache.logging.log4j:log4j-core"


def osv_vuln(*ranges, package=PKG):
    return {"affected": [{"package": {"name": package}, "ranges": list(ranges)}]}


def ecosystem_range(*events):
    return {"type": "ECOSYSTEM", "events": list(events)}


def test_simple_fixed_range():
    vuln = osv_vuln(ecosystem_range({"introduced": "2.0"}, {"fixed": "2.15.0"}))
    assert find_fixed_version(vuln, PKG, "2.14.1") == "2.15.0"


def test_version_already_past_the_fix():
    vuln = osv_vuln(ecosystem_range({"introduced": "2.0"}, {"fixed": "2.15.0"}))
    assert find_fixed_version(vuln, PKG, "2.16.0") is None


def test_version_predates_the_range():
    vuln = osv_vuln(ecosystem_range({"introduced": "2.13.0"}, {"fixed": "2.16.0"}))
    assert find_fixed_version(vuln, PKG, "2.12.0") is None


def test_picks_the_branch_our_version_is_on():
    """
    The real Log4Shell follow-up: log4j-core is listed with both a 2.13.x branch
    fixed in 2.16.0 and an older branch backported in 2.12.2. A 2.14.1 install
    must be told 2.16.0 — 2.12.2 is a branch it is not on, and recommending it
    would be a downgrade that fixes nothing.
    """
    vuln = osv_vuln(
        ecosystem_range({"introduced": "2.13.0"}, {"fixed": "2.16.0"}),
        ecosystem_range({"introduced": "0"}, {"fixed": "2.12.2"}),
    )
    assert find_fixed_version(vuln, PKG, "2.14.1") == "2.16.0"
    # …and a 2.11 install is on the other branch, so it gets the backport.
    assert find_fixed_version(vuln, PKG, "2.11.0") == "2.12.2"


def test_sibling_packages_are_ignored():
    """
    Advisories routinely cover several packages; another package's fix version
    is meaningless for ours.
    """
    vuln = {
        "affected": [
            {"package": {"name": "org.ops4j.pax.logging:pax-logging-log4j2"},
             "ranges": [ecosystem_range({"introduced": "1.8.0"}, {"fixed": "1.9.2"})]},
            {"package": {"name": PKG},
             "ranges": [ecosystem_range({"introduced": "2.0"}, {"fixed": "2.16.0"})]},
        ]
    }
    assert find_fixed_version(vuln, PKG, "2.14.1") == "2.16.0"


def test_last_affected_means_no_fix():
    vuln = osv_vuln(ecosystem_range({"introduced": "3.0.0-alpha1"},
                                    {"last_affected": "3.0.0-beta3"}))
    assert find_fixed_version(vuln, PKG, "3.0.0-beta1") is None


def test_git_ranges_are_skipped():
    vuln = osv_vuln({"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123def"}]})
    assert find_fixed_version(vuln, PKG, "2.14.1") is None


def test_reintroduced_vulnerability():
    """A single range can carry several introduced/fixed pairs."""
    vuln = osv_vuln(ecosystem_range(
        {"introduced": "1.0"}, {"fixed": "1.5"},
        {"introduced": "2.0"}, {"fixed": "2.5"},
    ))
    assert find_fixed_version(vuln, PKG, "1.2") == "1.5"
    assert find_fixed_version(vuln, PKG, "2.2") == "2.5"
    # Between the two windows the package is not affected at all.
    assert find_fixed_version(vuln, PKG, "1.8") is None


def test_no_affected_data():
    assert find_fixed_version({}, PKG, "1.0") is None
    assert find_fixed_version({"affected": []}, PKG, "1.0") is None


def test_case_insensitive_package_match():
    vuln = osv_vuln(ecosystem_range({"introduced": "0"}, {"fixed": "2.0"}), package="LoDaSh")
    assert find_fixed_version(vuln, "lodash", "1.0") == "2.0"


# ── Component remediation ─────────────────────────────────────────────────────

class _Vuln:
    def __init__(self, fixed_version=None, is_false_positive=False):
        self.fixed_version = fixed_version
        self.is_false_positive = is_false_positive


def test_remediation_recommends_the_version_clearing_everything():
    vulns = [_Vuln("2.15.0"), _Vuln("2.16.0"), _Vuln("2.17.1")]
    rem = build_remediation("2.14.1", vulns)

    assert rem["recommended_version"] == "2.17.1"
    assert rem["clears"] == 3
    assert rem["total"] == 3
    assert rem["unfixable"] == 0


def test_remediation_counts_unfixable_separately():
    vulns = [_Vuln("2.16.0"), _Vuln(None), _Vuln(None)]
    rem = build_remediation("2.14.1", vulns)

    assert rem["clears"] == 1
    assert rem["total"] == 3
    assert rem["unfixable"] == 2


def test_remediation_steps_are_cumulative():
    """Each stopping point reports everything cleared at or below it."""
    vulns = [_Vuln("2.15.0"), _Vuln("2.16.0"), _Vuln("2.17.1"), _Vuln("2.17.1")]
    steps = build_remediation("2.14.1", vulns)["steps"]

    assert steps == [
        {"version": "2.15.0", "clears": 1},
        {"version": "2.16.0", "clears": 2},
        {"version": "2.17.1", "clears": 4},
    ]


def test_no_remediation_when_nothing_is_fixable():
    assert build_remediation("1.0", [_Vuln(None), _Vuln(None)]) is None
    assert build_remediation("1.0", []) is None


def test_no_remediation_when_already_past_every_fix():
    # Stale rows whose fix we have already applied must not suggest a downgrade.
    assert build_remediation("3.0.0", [_Vuln("2.16.0")]) is None
