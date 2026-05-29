import logging
from datetime import datetime

import requests
import streamlit as st

API_URL = "http://backend:8000"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s")

st.set_page_config(page_title="OSS Monitor", layout="wide")

for key in ["identifier", "analysis_payload"]:
    if key not in st.session_state:
        st.session_state[key] = None

# ── Constants ─────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "unknown": "⚪"}
SEVERITY_HEX   = {"critical": "red", "high": "orange", "medium": "#cccc00", "low": "green", "unknown": "gray"}

EVIDENCE_ICONS = {
    "analyst_report": "📄",
    "incident_link":  "🔗",
    "virustotal":     "🛡️",
    "cve_discussion": "💬",
    "audit_report":   "🔍",
    "other":          "📎",
}
EVIDENCE_LABELS = {
    "analyst_report": "Analyst Report",
    "incident_link":  "Incident Link",
    "virustotal":     "VirusTotal",
    "cve_discussion": "CVE Discussion",
    "audit_report":   "Audit Report",
    "other":          "Other",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def api_get(path: str, **kwargs):
    return requests.get(f"{API_URL}{path}", **kwargs)

def api_post(path: str, **kwargs):
    return requests.post(f"{API_URL}{path}", **kwargs)

def api_patch(path: str, **kwargs):
    return requests.patch(f"{API_URL}{path}", **kwargs)

def api_put(path: str, **kwargs):
    return requests.put(f"{API_URL}{path}", **kwargs)

def api_delete(path: str, **kwargs):
    return requests.delete(f"{API_URL}{path}", **kwargs)


def vuln_url(vuln_id: str) -> str:
    if vuln_id.startswith("CVE"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA"):
        return f"https://github.com/advisories/{vuln_id}"
    return f"https://deps.dev/advisory/osv/{vuln_id}"


def fetch_components(tag: str | None = None) -> list:
    try:
        r = api_get("/components", params={"tag": tag} if tag else {})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Failed to load components: {e}")
        return []


def scorecard_badge(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 7:
        color = "green"
    elif score >= 5:
        color = "orange"
    else:
        color = "red"
    return f'<span style="background:{color};color:white;padding:2px 7px;border-radius:4px;font-size:0.85em;font-weight:bold;">SC {score}/10</span>'


def fmt_dt(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(str(iso)).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(iso)


# ── Navigation ────────────────────────────────────────────────────────────────

page = st.sidebar.radio(
    "Navigation",
    ["📊 Dashboard", "➕ Add Component", "📋 Components", "⚙️ Settings"],
)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("📊 Dashboard")

    try:
        data = api_get("/dashboard").json()
    except Exception as e:
        st.error(f"Failed to load dashboard: {e}")
        st.stop()

    sc = data["severity_counts"]

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Total Components",    data["total_components"])
    col2.metric("With Vulnerabilities", data["components_with_vulns"])
    col3.metric("🔴 Critical",         sc.get("critical", 0))
    col4.metric("🟠 High",             sc.get("high", 0))
    col5.metric("🟡 Medium",           sc.get("medium", 0))
    col6.metric("⚠️ Scorecard Warn",   data.get("scorecard_warnings", 0))

    st.divider()

    total_vulns = sum(sc.values())
    if total_vulns > 0:
        st.subheader("Vulnerability breakdown")
        cols = st.columns(5)
        for col, label in zip(cols, ["critical", "high", "medium", "low", "unknown"]):
            count = sc.get(label, 0)
            pct   = round(count / total_vulns * 100) if total_vulns else 0
            col.metric(f"{SEVERITY_COLOR[label]} {label.capitalize()}", f"{count} ({pct}%)")
    else:
        st.success("No active vulnerabilities found across all components.")

    st.divider()

    if data["top_vulnerable"]:
        st.subheader("Top 5 most vulnerable components")
        for item in data["top_vulnerable"]:
            tags_str = " · " + " ".join(
                f"`{t.strip()}`" for t in item["tags"].split(",") if t.strip()
            ) if item.get("tags") else ""
            sc_badge = scorecard_badge(item.get("scorecard_score"))
            st.markdown(
                f"**{item['name']}** {item['version']}{tags_str} {sc_badge} — "
                f"🔴 {item['critical']} critical · 🟠 {item['high']} high · "
                f"**{item['vuln_count']} total**",
                unsafe_allow_html=True,
            )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ADD COMPONENT
# ══════════════════════════════════════════════════════════════════════════════
elif page == "➕ Add Component":
    st.title("➕ Add Component")

    component_type = st.radio("Component Type", ["library", "product"])
    name    = st.text_input("Name",    key="name")
    version = st.text_input("Version", key="version")
    tags_input = st.text_input("Tags (comma-separated)", placeholder="prod,db-server,k8s", key="tags_input")

    ecosystem = None
    if component_type == "library":
        ecosystem = st.selectbox("Ecosystem", ["maven", "npm", "pypi", "go", "nuget", "crates.io"])

    with st.expander("Additional metadata (optional)"):
        repo_url    = st.text_input("GitHub / GitLab repo URL", placeholder="https://github.com/owner/repo", key="repo_url_add")
        distrib_url = st.text_input("Distribution URL",         placeholder="https://example.com/release.tar.gz", key="distrib_url_add")

    # ── Generate identifier ───────────────────────────────────────────────────
    with st.columns(3)[0]:
        if st.button("Generate Identifier", use_container_width=True):
            payload = {"type": component_type, "name": name, "version": version}
            if ecosystem:
                payload["ecosystem"] = ecosystem
            try:
                r = api_post("/generate_identifier", json=payload)
                r.raise_for_status()
                st.session_state.identifier = r.json()["identifier"]
            except Exception as e:
                st.error(f"Identifier generation failed: {e}")
                st.stop()

    # ── Analyze ───────────────────────────────────────────────────────────────
    if st.session_state.identifier:
        identifier = st.text_input("Edit Identifier", value=st.session_state.identifier)

        if st.button("Analyze"):
            try:
                payload = {"type": component_type, "name": name, "version": version, "identifier_override": identifier}
                if ecosystem:
                    payload["ecosystem"] = ecosystem
                r = api_post("/analyze", json=payload)
                r.raise_for_status()
                st.session_state.analysis_payload = payload
                analysis = r.json()
                st.subheader("Vulnerabilities found")
                if analysis["vulnerabilities"]:
                    for v in analysis["vulnerabilities"]:
                        st.markdown(f"- **{v}**")
                else:
                    st.success("No vulnerabilities found.")
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    # ── Add to DB ─────────────────────────────────────────────────────────────
    if st.session_state.analysis_payload:
        notes = st.text_area("Notes (optional)")
        c1, _, c3 = st.columns(3)

        with c1:
            if st.button("➕ Add", use_container_width=True):
                try:
                    payload = dict(st.session_state.analysis_payload)
                    payload["notes"]       = notes or None
                    payload["tags"]        = tags_input.strip() or None
                    payload["repo_url"]    = repo_url.strip() or None
                    payload["distrib_url"] = distrib_url.strip() or None
                    r = api_post("/components", json=payload)
                    r.raise_for_status()
                    added = r.json()
                    sc_score = added.get("scorecard_score")
                    msg = "Component added."
                    if sc_score is not None:
                        msg += f" Scorecard: **{sc_score}/10**"
                    st.success(msg)
                    for key in ["identifier", "analysis_payload"]:
                        st.session_state[key] = None
                    st.rerun()
                except requests.HTTPError as e:
                    st.error(f"Add failed: {e.response.status_code} — {e.response.text}")

        with c3:
            if st.button("🧹 Clear", use_container_width=True):
                for key in ["identifier", "analysis_payload"]:
                    st.session_state[key] = None
                st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📋 Components":
    st.title("📋 Components")

    all_components = fetch_components()
    all_tags = sorted({
        t.strip()
        for c in all_components
        if c.get("tags")
        for t in c["tags"].split(",")
        if t.strip()
    })

    selected_tag = None
    if all_tags:
        sel = st.selectbox("Filter by tag", ["All"] + all_tags)
        selected_tag = None if sel == "All" else sel

    components = fetch_components(tag=selected_tag) if selected_tag else all_components

    if not components:
        st.info("No components found. Add one via '➕ Add Component'.")
        st.stop()

    st.caption(f"Showing {len(components)} component(s)")

    for component in components:
        cid = component["id"]
        non_fp_vulns = [v for v in component["vulnerabilities"] if not v.get("is_false_positive")]

        # ── Expander title ────────────────────────────────────────────────────
        if any(v["severity"] == "critical" for v in non_fp_vulns):
            sev_icon = "🔴 "
        elif any(v["severity"] == "high" for v in non_fp_vulns):
            sev_icon = "🟠 "
        elif non_fp_vulns:
            sev_icon = "⚠️ "
        else:
            sev_icon = ""

        tags_display = ""
        if component.get("tags"):
            tags_display = " · " + " ".join(
                f"`{t.strip()}`" for t in component["tags"].split(",") if t.strip()
            )

        sc_score = component.get("scorecard_score")
        sc_suffix = f" · SC {sc_score}/10" if sc_score is not None else ""

        display_name = f"{sev_icon}**{component['name']}** — {component['version']}{tags_display}{sc_suffix}"

        with st.expander(display_name):

            # ── Metadata ──────────────────────────────────────────────────────
            meta_col, sc_col = st.columns([2, 1])
            with meta_col:
                st.text(f"Type: {component['type']}")
                st.text(f"Identifier: {component['identifier']}")
                st.text(f"Last Updated: {fmt_dt(component['last_updated'])}")
                if component.get("ecosystem"):
                    st.text(f"Ecosystem: {component['ecosystem']}")
                if component.get("repo_url"):
                    st.markdown(f"**Repo:** [{component['repo_url']}]({component['repo_url']})")
                if component.get("distrib_url"):
                    st.markdown(f"**Distrib:** [{component['distrib_url']}]({component['distrib_url']})")
                if component.get("notes"):
                    st.markdown(f"**Notes:** {component['notes']}")

            # ── Scorecard panel ───────────────────────────────────────────────
            with sc_col:
                st.markdown("**OpenSSF Scorecard**")
                if sc_score is not None:
                    color = "green" if sc_score >= 7 else ("orange" if sc_score >= 5 else "red")
                    st.markdown(
                        f'<p style="font-size:2em;font-weight:bold;color:{color};margin:0">{sc_score}/10</p>',
                        unsafe_allow_html=True,
                    )
                    if component.get("scorecard_updated"):
                        st.caption(f"Updated: {fmt_dt(component['scorecard_updated'])}")
                else:
                    st.caption("No data — set repo URL and click Scorecard")

                if component.get("repo_url"):
                    if st.button("🔎 Scorecard", key=f"sc_{cid}", use_container_width=True):
                        try:
                            r = api_post(f"/components/{cid}/scorecard")
                            r.raise_for_status()
                            d = r.json()
                            st.success(f"Score: {d['score']}/10")
                            st.rerun()
                        except requests.HTTPError as e:
                            st.error(f"Scorecard failed: {e.response.text}")

            st.divider()

            # ── Edit form ─────────────────────────────────────────────────────
            edit_key = f"editing_{cid}"
            if st.session_state.get(edit_key):
                st.subheader("✏️ Edit")
                new_notes       = st.text_area("Notes",           value=component.get("notes") or "",       key=f"edit_notes_{cid}")
                new_tags        = st.text_input("Tags",           value=component.get("tags") or "",         key=f"edit_tags_{cid}")
                new_repo_url    = st.text_input("Repo URL",       value=component.get("repo_url") or "",     key=f"edit_repo_{cid}")
                new_distrib_url = st.text_input("Distrib URL",    value=component.get("distrib_url") or "",  key=f"edit_distrib_{cid}")
                save_col, cancel_col = st.columns(2)
                with save_col:
                    if st.button("💾 Save", key=f"save_{cid}", use_container_width=True):
                        try:
                            api_patch(f"/components/{cid}", json={
                                "notes":       new_notes or None,
                                "tags":        new_tags.strip() or None,
                                "repo_url":    new_repo_url.strip() or None,
                                "distrib_url": new_distrib_url.strip() or None,
                            }).raise_for_status()
                            st.success("Saved.")
                            st.session_state[edit_key] = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"Save failed: {e}")
                with cancel_col:
                    if st.button("Cancel", key=f"cancel_{cid}", use_container_width=True):
                        st.session_state[edit_key] = False
                        st.rerun()
                st.divider()

            # ── Vulnerabilities ───────────────────────────────────────────────
            st.markdown("**Vulnerabilities**")
            if non_fp_vulns or [v for v in component["vulnerabilities"] if v.get("is_false_positive")]:
                for vuln in component["vulnerabilities"]:
                    vuln_id  = vuln.get("cve_id", "Unknown")
                    is_fp    = vuln.get("is_false_positive", False)
                    reason   = vuln.get("false_positive_reason") or ""
                    severity = vuln.get("severity", "unknown").lower()
                    color    = SEVERITY_HEX.get(severity, "gray")
                    icon     = SEVERITY_COLOR.get(severity, "⚪")
                    url      = vuln_url(vuln_id)

                    label_html = f'<span style="color:{color};font-weight:bold;">{icon} {vuln_id} ({severity.upper()})</span>'
                    vuln_display = f"<s>{label_html}</s>" if is_fp else f'<a href="{url}" target="_blank">{label_html}</a>'

                    cols = st.columns([0.35, 0.1, 0.55], vertical_alignment="center")
                    with cols[0]:
                        st.markdown(vuln_display, unsafe_allow_html=True)
                    with cols[1]:
                        new_fp = st.checkbox("FP", value=is_fp, key=f"fp_{cid}_{vuln_id}")
                    with cols[2]:
                        new_reason = st.text_input(
                            "Reason", value=reason, key=f"reason_{cid}_{vuln_id}",
                            placeholder="why is FP", label_visibility="collapsed",
                        )
                    if new_fp != is_fp:
                        try:
                            api_patch(f"/vulnerabilities/{vuln['id']}/false_positive",
                                      json={"is_false_positive": new_fp, "reason": new_reason})
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to mark as FP: {e}")
            else:
                st.success("No vulnerabilities.")

            st.divider()

            # ── Evidence ──────────────────────────────────────────────────────
            st.markdown("**Evidence & Links**")
            evidence_list = component.get("evidence", [])

            if evidence_list:
                for ev in evidence_list:
                    ev_type  = ev.get("type", "other")
                    ev_icon  = EVIDENCE_ICONS.get(ev_type, "📎")
                    ev_label = EVIDENCE_LABELS.get(ev_type, ev_type)
                    ev_date  = fmt_dt(ev.get("created_at"))

                    ev_cols = st.columns([0.05, 0.6, 0.25, 0.1], vertical_alignment="center")
                    with ev_cols[0]:
                        st.markdown(ev_icon)
                    with ev_cols[1]:
                        title = ev["title"]
                        if ev.get("url"):
                            st.markdown(f"[{title}]({ev['url']})  \n<small style='color:gray'>{ev_label} · {ev_date}</small>", unsafe_allow_html=True)
                        else:
                            st.markdown(f"**{title}**  \n<small style='color:gray'>{ev_label} · {ev_date}</small>", unsafe_allow_html=True)
                        if ev.get("notes"):
                            st.caption(ev["notes"])
                    with ev_cols[3]:
                        if st.button("🗑", key=f"del_ev_{ev['id']}", help="Delete"):
                            try:
                                api_delete(f"/evidence/{ev['id']}").raise_for_status()
                                st.rerun()
                            except Exception as e:
                                st.error(f"Delete failed: {e}")

            # ── Add evidence form ─────────────────────────────────────────────
            add_ev_key = f"add_evidence_{cid}"
            if st.session_state.get(add_ev_key):
                with st.form(key=f"ev_form_{cid}", clear_on_submit=True):
                    ev_type_sel  = st.selectbox("Type", list(EVIDENCE_LABELS.keys()),
                                                format_func=lambda x: f"{EVIDENCE_ICONS[x]} {EVIDENCE_LABELS[x]}")
                    ev_title_in  = st.text_input("Title *")
                    ev_url_in    = st.text_input("URL (optional)")
                    ev_notes_in  = st.text_area("Notes (optional)", height=70)
                    submitted    = st.form_submit_button("💾 Save evidence")
                    if submitted:
                        if not ev_title_in.strip():
                            st.warning("Title is required.")
                        else:
                            try:
                                api_post(f"/components/{cid}/evidence", json={
                                    "type":  ev_type_sel,
                                    "title": ev_title_in.strip(),
                                    "url":   ev_url_in.strip() or None,
                                    "notes": ev_notes_in.strip() or None,
                                }).raise_for_status()
                                st.session_state[add_ev_key] = False
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to add evidence: {e}")

            ev_btn_label = "✖ Cancel" if st.session_state.get(add_ev_key) else "➕ Add evidence"
            if st.button(ev_btn_label, key=f"toggle_ev_{cid}"):
                st.session_state[add_ev_key] = not st.session_state.get(add_ev_key, False)
                st.rerun()

            st.divider()

            # ── Action buttons ────────────────────────────────────────────────
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🔄 Refresh", key=f"refresh_{cid}", use_container_width=True):
                    try:
                        api_post(f"/components/{cid}/refresh").raise_for_status()
                        st.success("Refreshed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Refresh failed: {e}")
            with c2:
                if st.button("✏️ Edit", key=f"edit_btn_{cid}", use_container_width=True):
                    st.session_state[edit_key] = not st.session_state.get(edit_key, False)
                    st.rerun()
            with c3:
                if st.button("❌ Delete", key=f"delete_{cid}", use_container_width=True):
                    try:
                        api_delete(f"/components/{cid}").raise_for_status()
                        st.success("Deleted.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.title("⚙️ Settings")

    try:
        current = api_get("/settings").json()
    except Exception as e:
        st.error(f"Failed to load settings: {e}")
        st.stop()

    st.subheader("🔔 Webhook Notifications")
    st.caption("Slack incoming webhooks, Telegram via bot, or any HTTP endpoint that accepts JSON POST.")

    webhook_url = st.text_input(
        "Webhook URL",
        value=current.get("webhook_url") or "",
        placeholder="https://hooks.slack.com/services/...",
    )

    col1, col2 = st.columns(2)
    with col1:
        notify_critical = st.toggle("Alert on new Critical CVE",  value=current.get("notify_on_critical", True))
        notify_high     = st.toggle("Alert on new High CVE",       value=current.get("notify_on_high", False))
    with col2:
        notify_scorecard = st.toggle("Daily digest: Scorecard failures", value=current.get("notify_on_scorecard_fail", True))
        notify_stale     = st.toggle("Daily digest: Stale components",   value=current.get("notify_on_stale", True))

    st.divider()
    st.subheader("🚦 Quality Gate Thresholds")

    col3, col4 = st.columns(2)
    with col3:
        sc_min = st.number_input(
            "Minimum Scorecard score (0–10)",
            min_value=0.0, max_value=10.0, step=0.5,
            value=float(current.get("scorecard_min_score", 5.0)),
            help="Components with a score below this value will be flagged in the daily digest.",
        )
    with col4:
        stale_days = st.number_input(
            "Stale threshold (days without commits)",
            min_value=30, max_value=3650, step=30,
            value=int(current.get("stale_days_threshold", 730)),
            help="Components whose repo has not been updated for this many days will be flagged.",
        )

    st.divider()

    save_col, test_col, _ = st.columns([1, 1, 2])
    with save_col:
        if st.button("💾 Save settings", use_container_width=True, type="primary"):
            try:
                api_put("/settings", json={
                    "webhook_url":            webhook_url.strip() or None,
                    "notify_on_critical":     notify_critical,
                    "notify_on_high":         notify_high,
                    "scorecard_min_score":    sc_min,
                    "stale_days_threshold":   stale_days,
                    "notify_on_scorecard_fail": notify_scorecard,
                    "notify_on_stale":        notify_stale,
                }).raise_for_status()
                st.success("Settings saved.")
            except Exception as e:
                st.error(f"Save failed: {e}")

    with test_col:
        if st.button("📨 Test webhook", use_container_width=True):
            if not webhook_url.strip():
                st.warning("Enter a webhook URL first.")
            else:
                try:
                    r = requests.post(webhook_url.strip(), json={
                        "text": "✅ OSS Monitor — test notification",
                        "event": "test",
                    }, timeout=5)
                    if r.ok:
                        st.success(f"Delivered ({r.status_code}).")
                    else:
                        st.warning(f"Endpoint returned {r.status_code}.")
                except Exception as e:
                    st.error(f"Test failed: {e}")
