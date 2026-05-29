import csv
import io
import json
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

EVIDENCE_ICONS  = {"analyst_report": "📄", "incident_link": "🔗", "virustotal": "🛡️",
                   "cve_discussion": "💬", "audit_report": "🔍", "other": "📎"}
EVIDENCE_LABELS = {"analyst_report": "Analyst Report", "incident_link": "Incident Link",
                   "virustotal": "VirusTotal", "cve_discussion": "CVE Discussion",
                   "audit_report": "Audit Report", "other": "Other"}

PAGE_SIZE = 20

# ── Helpers ───────────────────────────────────────────────────────────────────

def api(method: str, path: str, **kw):
    return getattr(requests, method)(f"{API_URL}{path}", **kw)

def vuln_url(vuln_id: str) -> str:
    if vuln_id.startswith("CVE"):   return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA"):  return f"https://github.com/advisories/{vuln_id}"
    return f"https://deps.dev/advisory/osv/{vuln_id}"

def fmt_dt(iso) -> str:
    if not iso: return "—"
    try:    return datetime.fromisoformat(str(iso)).strftime("%d.%m.%Y %H:%M")
    except: return str(iso)

def scorecard_badge(score) -> str:
    if score is None: return ""
    color = "green" if score >= 7 else ("orange" if score >= 5 else "red")
    return f'<span style="background:{color};color:white;padding:2px 7px;border-radius:4px;font-size:0.85em;font-weight:bold;">SC {score}/10</span>'

def fetch_components(tag: str | None = None) -> list:
    try:
        r = api("get", "/components", params={"tag": tag} if tag else {})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Failed to load components: {e}")
        return []

def build_csv(components: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "version", "type", "ecosystem", "identifier", "tags",
                "scorecard_score", "cve_count", "critical", "high", "medium", "low",
                "last_updated", "repo_url", "notes"])
    for c in components:
        av = [v for v in c["vulnerabilities"] if not v.get("is_false_positive")]
        w.writerow([
            c["name"], c["version"], c["type"], c.get("ecosystem") or "",
            c.get("identifier") or "", c.get("tags") or "",
            c.get("scorecard_score") or "",
            len(av),
            sum(1 for v in av if v["severity"] == "critical"),
            sum(1 for v in av if v["severity"] == "high"),
            sum(1 for v in av if v["severity"] == "medium"),
            sum(1 for v in av if v["severity"] == "low"),
            fmt_dt(c.get("last_updated")),
            c.get("repo_url") or "",
            (c.get("notes") or "").replace("\n", " "),
        ])
    return buf.getvalue()

# ── Navigation ────────────────────────────────────────────────────────────────

page = st.sidebar.radio("Navigation", [
    "📊 Dashboard", "➕ Add Component", "📋 Components", "📥 Import", "⚙️ Settings",
])


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("📊 Dashboard")
    try:
        data = api("get", "/dashboard").json()
    except Exception as e:
        st.error(f"Failed to load dashboard: {e}"); st.stop()

    sc = data["severity_counts"]
    col1,col2,col3,col4,col5,col6 = st.columns(6)
    col1.metric("Total Components",     data["total_components"])
    col2.metric("With Vulnerabilities", data["components_with_vulns"])
    col3.metric("🔴 Critical",          sc.get("critical", 0))
    col4.metric("🟠 High",              sc.get("high", 0))
    col5.metric("🟡 Medium",            sc.get("medium", 0))
    col6.metric("⚠️ Scorecard Warn",    data.get("scorecard_warnings", 0))

    st.divider()
    total_vulns = sum(sc.values())
    if total_vulns > 0:
        st.subheader("Vulnerability breakdown")
        cols = st.columns(5)
        for col, label in zip(cols, ["critical", "high", "medium", "low", "unknown"]):
            count = sc.get(label, 0)
            pct   = round(count / total_vulns * 100)
            col.metric(f"{SEVERITY_COLOR[label]} {label.capitalize()}", f"{count} ({pct}%)")
    else:
        st.success("No active vulnerabilities found.")

    st.divider()
    if data["top_vulnerable"]:
        st.subheader("Top 5 most vulnerable components")
        for item in data["top_vulnerable"]:
            tags_str = " · " + " ".join(f"`{t.strip()}`" for t in item["tags"].split(",") if t.strip()) if item.get("tags") else ""
            st.markdown(
                f"**{item['name']}** {item['version']}{tags_str} {scorecard_badge(item.get('scorecard_score'))} — "
                f"🔴 {item['critical']} · 🟠 {item['high']} · **{item['vuln_count']} total**",
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

    with st.columns(3)[0]:
        if st.button("Generate Identifier", use_container_width=True):
            payload = {"type": component_type, "name": name, "version": version}
            if ecosystem: payload["ecosystem"] = ecosystem
            try:
                r = api("post", "/generate_identifier", json=payload); r.raise_for_status()
                st.session_state.identifier = r.json()["identifier"]
            except Exception as e:
                st.error(f"Identifier generation failed: {e}"); st.stop()

    if st.session_state.identifier:
        identifier = st.text_input("Edit Identifier", value=st.session_state.identifier)
        if st.button("Analyze"):
            try:
                payload = {"type": component_type, "name": name, "version": version, "identifier_override": identifier}
                if ecosystem: payload["ecosystem"] = ecosystem
                r = api("post", "/analyze", json=payload); r.raise_for_status()
                st.session_state.analysis_payload = payload
                analysis = r.json()
                st.subheader("Vulnerabilities found")
                if analysis["vulnerabilities"]:
                    for v in analysis["vulnerabilities"]: st.markdown(f"- **{v}**")
                else:
                    st.success("No vulnerabilities found.")
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    if st.session_state.analysis_payload:
        notes = st.text_area("Notes (optional)")
        c1, _, c3 = st.columns(3)
        with c1:
            if st.button("➕ Add", use_container_width=True):
                try:
                    payload = dict(st.session_state.analysis_payload)
                    payload.update(notes=notes or None, tags=tags_input.strip() or None,
                                   repo_url=repo_url.strip() or None, distrib_url=distrib_url.strip() or None)
                    r = api("post", "/components", json=payload); r.raise_for_status()
                    added = r.json()
                    msg = "Component added."
                    if added.get("scorecard_score") is not None:
                        msg += f" Scorecard: **{added['scorecard_score']}/10**"
                    st.success(msg)
                    for k in ["identifier", "analysis_payload"]: st.session_state[k] = None
                    st.rerun()
                except requests.HTTPError as e:
                    st.error(f"Add failed: {e.response.status_code} — {e.response.text}")
        with c3:
            if st.button("🧹 Clear", use_container_width=True):
                for k in ["identifier", "analysis_payload"]: st.session_state[k] = None
                st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📋 Components":
    st.title("📋 Components")

    all_components = fetch_components()

    # ── Search + filter ───────────────────────────────────────────────────────
    filter_col, tag_col, export_col = st.columns([2, 1, 1])
    with filter_col:
        search = st.text_input("🔍 Search by name", placeholder="nginx, spring…", label_visibility="collapsed")
    with tag_col:
        all_tags = sorted({t.strip() for c in all_components if c.get("tags")
                           for t in c["tags"].split(",") if t.strip()})
        selected_tag = None
        if all_tags:
            sel = st.selectbox("Tag", ["All"] + all_tags, label_visibility="collapsed")
            selected_tag = None if sel == "All" else sel
    with export_col:
        csv_data = build_csv(all_components)
        st.download_button("⬇️ Export CSV", csv_data, "components.csv", "text/csv", use_container_width=True)

    # ── Apply filters ─────────────────────────────────────────────────────────
    components = all_components
    if search:
        components = [c for c in components if search.lower() in c["name"].lower()]
    if selected_tag:
        components = [c for c in components if c.get("tags") and
                      selected_tag in [t.strip() for t in c["tags"].split(",")]]

    if not components:
        st.info("No components match your filters."); st.stop()

    # ── Pagination ────────────────────────────────────────────────────────────
    total = len(components)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page_key = "comp_page"
    if page_key not in st.session_state:
        st.session_state[page_key] = 0
    # Reset page when filters change
    filter_sig = f"{search}|{selected_tag}"
    if st.session_state.get("filter_sig") != filter_sig:
        st.session_state[page_key] = 0
        st.session_state["filter_sig"] = filter_sig

    current_page = st.session_state[page_key]
    start = current_page * PAGE_SIZE
    page_components = components[start : start + PAGE_SIZE]

    pag_col1, pag_col2, pag_col3 = st.columns([1, 3, 1])
    with pag_col1:
        if st.button("← Prev", disabled=current_page == 0, use_container_width=True):
            st.session_state[page_key] -= 1; st.rerun()
    with pag_col2:
        st.caption(f"Showing {start+1}–{min(start+PAGE_SIZE, total)} of {total} component(s)")
    with pag_col3:
        if st.button("Next →", disabled=current_page >= total_pages - 1, use_container_width=True):
            st.session_state[page_key] += 1; st.rerun()

    # ── Component cards ───────────────────────────────────────────────────────
    for component in page_components:
        cid = component["id"]
        non_fp = [v for v in component["vulnerabilities"] if not v.get("is_false_positive")]

        if any(v["severity"] == "critical" for v in non_fp):   sev_icon = "🔴 "
        elif any(v["severity"] == "high" for v in non_fp):     sev_icon = "🟠 "
        elif non_fp:                                            sev_icon = "⚠️ "
        else:                                                   sev_icon = ""

        tags_disp = " · " + " ".join(f"`{t.strip()}`" for t in component["tags"].split(",") if t.strip()) \
                    if component.get("tags") else ""
        sc_score  = component.get("scorecard_score")
        sc_suffix = f" · SC {sc_score}/10" if sc_score is not None else ""

        with st.expander(f"{sev_icon}**{component['name']}** — {component['version']}{tags_disp}{sc_suffix}"):

            # ── Metadata + Scorecard ──────────────────────────────────────────
            meta_col, sc_col = st.columns([2, 1])
            with meta_col:
                st.text(f"Type: {component['type']}")
                st.text(f"Identifier: {component['identifier']}")
                st.text(f"Last Updated: {fmt_dt(component['last_updated'])}")
                if component.get("ecosystem"):   st.text(f"Ecosystem: {component['ecosystem']}")
                if component.get("repo_url"):    st.markdown(f"**Repo:** [{component['repo_url']}]({component['repo_url']})")
                if component.get("distrib_url"): st.markdown(f"**Distrib:** [{component['distrib_url']}]({component['distrib_url']})")
                if component.get("notes"):       st.markdown(f"**Notes:** {component['notes']}")

            with sc_col:
                st.markdown("**OpenSSF Scorecard**")
                if sc_score is not None:
                    color = "green" if sc_score >= 7 else ("orange" if sc_score >= 5 else "red")
                    st.markdown(f'<p style="font-size:2em;font-weight:bold;color:{color};margin:0">{sc_score}/10</p>',
                                unsafe_allow_html=True)
                    if component.get("scorecard_updated"):
                        st.caption(f"Updated: {fmt_dt(component['scorecard_updated'])}")

                    # Scorecard checks table
                    sc_data = component.get("scorecard_data")
                    if sc_data and sc_data.get("checks"):
                        with st.expander("View checks", expanded=False):
                            for ch in sc_data["checks"]:
                                ch_score = ch.get("score", -1)
                                if ch_score == 10:    icon = "✅"
                                elif ch_score >= 5:   icon = "🟡"
                                elif ch_score >= 0:   icon = "🔴"
                                else:                 icon = "⚪"
                                st.markdown(f"{icon} **{ch['name']}** — {ch_score if ch_score >= 0 else 'N/A'}/10")
                else:
                    st.caption("No data — set repo URL and refresh")

                if component.get("repo_url"):
                    if st.button("🔎 Refresh Scorecard", key=f"sc_{cid}", use_container_width=True):
                        try:
                            r = api("post", f"/components/{cid}/scorecard"); r.raise_for_status()
                            st.success(f"Score: {r.json()['score']}/10"); st.rerun()
                        except requests.HTTPError as e:
                            st.error(f"Scorecard failed: {e.response.text}")

            st.divider()

            # ── Edit form ─────────────────────────────────────────────────────
            edit_key = f"editing_{cid}"
            if st.session_state.get(edit_key):
                st.subheader("✏️ Edit")
                new_notes  = st.text_area("Notes",      value=component.get("notes") or "",       key=f"en_{cid}")
                new_tags   = st.text_input("Tags",       value=component.get("tags") or "",         key=f"et_{cid}")
                new_repo   = st.text_input("Repo URL",   value=component.get("repo_url") or "",     key=f"er_{cid}")
                new_distrib= st.text_input("Distrib URL",value=component.get("distrib_url") or "",  key=f"ed_{cid}")
                s_col, c_col = st.columns(2)
                with s_col:
                    if st.button("💾 Save", key=f"save_{cid}", use_container_width=True):
                        try:
                            api("patch", f"/components/{cid}", json={
                                "notes": new_notes or None, "tags": new_tags.strip() or None,
                                "repo_url": new_repo.strip() or None, "distrib_url": new_distrib.strip() or None,
                            }).raise_for_status()
                            st.success("Saved."); st.session_state[edit_key] = False; st.rerun()
                        except Exception as e:
                            st.error(f"Save failed: {e}")
                with c_col:
                    if st.button("Cancel", key=f"cancel_{cid}", use_container_width=True):
                        st.session_state[edit_key] = False; st.rerun()
                st.divider()

            # ── Vulnerabilities ───────────────────────────────────────────────
            st.markdown("**Vulnerabilities**")
            if component["vulnerabilities"]:
                for vuln in component["vulnerabilities"]:
                    vuln_id  = vuln.get("cve_id", "Unknown")
                    is_fp    = vuln.get("is_false_positive", False)
                    reason   = vuln.get("false_positive_reason") or ""
                    severity = vuln.get("severity", "unknown").lower()
                    color    = SEVERITY_HEX.get(severity, "gray")
                    icon     = SEVERITY_COLOR.get(severity, "⚪")
                    cvss     = vuln.get("cvss_score")
                    first_s  = fmt_dt(vuln.get("first_seen"))
                    url      = vuln_url(vuln_id)

                    cvss_str  = f" <small style='color:gray'>CVSS {cvss}</small>" if cvss else ""
                    date_str  = f" <small style='color:gray'>since {first_s}</small>" if first_s != "—" else ""
                    label_html= f'<span style="color:{color};font-weight:bold;">{icon} {vuln_id} ({severity.upper()})</span>{cvss_str}{date_str}'
                    vuln_disp = f"<s>{label_html}</s>" if is_fp else f'<a href="{url}" target="_blank">{label_html}</a>'

                    v_cols = st.columns([0.4, 0.1, 0.5], vertical_alignment="center")
                    with v_cols[0]: st.markdown(vuln_disp, unsafe_allow_html=True)
                    with v_cols[1]: new_fp = st.checkbox("FP", value=is_fp, key=f"fp_{cid}_{vuln_id}")
                    with v_cols[2]:
                        new_reason = st.text_input("Reason", value=reason, key=f"reason_{cid}_{vuln_id}",
                                                   placeholder="why is FP", label_visibility="collapsed")
                    if new_fp != is_fp:
                        try:
                            api("patch", f"/vulnerabilities/{vuln['id']}/false_positive",
                                json={"is_false_positive": new_fp, "reason": new_reason})
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to mark as FP: {e}")
            else:
                st.success("No vulnerabilities.")

            st.divider()

            # ── Evidence ──────────────────────────────────────────────────────
            st.markdown("**Evidence & Links**")
            for ev in component.get("evidence", []):
                ev_type = ev.get("type", "other")
                ev_cols = st.columns([0.05, 0.65, 0.2, 0.1], vertical_alignment="center")
                with ev_cols[0]: st.markdown(EVIDENCE_ICONS.get(ev_type, "📎"))
                with ev_cols[1]:
                    title = ev["title"]
                    label = f"{EVIDENCE_LABELS.get(ev_type, ev_type)} · {fmt_dt(ev.get('created_at'))}"
                    if ev.get("url"):
                        st.markdown(f"[{title}]({ev['url']})  \n<small style='color:gray'>{label}</small>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"**{title}**  \n<small style='color:gray'>{label}</small>", unsafe_allow_html=True)
                    if ev.get("notes"): st.caption(ev["notes"])
                with ev_cols[3]:
                    if st.button("🗑", key=f"del_ev_{ev['id']}", help="Delete"):
                        try:
                            api("delete", f"/evidence/{ev['id']}").raise_for_status(); st.rerun()
                        except Exception as e:
                            st.error(f"Delete failed: {e}")

            add_ev_key = f"add_evidence_{cid}"
            if st.session_state.get(add_ev_key):
                with st.form(key=f"ev_form_{cid}", clear_on_submit=True):
                    ev_type_sel = st.selectbox("Type", list(EVIDENCE_LABELS.keys()),
                                               format_func=lambda x: f"{EVIDENCE_ICONS[x]} {EVIDENCE_LABELS[x]}")
                    ev_title = st.text_input("Title *")
                    ev_url   = st.text_input("URL (optional)")
                    ev_notes = st.text_area("Notes (optional)", height=70)
                    if st.form_submit_button("💾 Save evidence"):
                        if not ev_title.strip():
                            st.warning("Title is required.")
                        else:
                            try:
                                api("post", f"/components/{cid}/evidence", json={
                                    "type": ev_type_sel, "title": ev_title.strip(),
                                    "url": ev_url.strip() or None, "notes": ev_notes.strip() or None,
                                }).raise_for_status()
                                st.session_state[add_ev_key] = False; st.rerun()
                            except Exception as e:
                                st.error(f"Failed to add evidence: {e}")

            ev_label = "✖ Cancel" if st.session_state.get(add_ev_key) else "➕ Add evidence"
            if st.button(ev_label, key=f"toggle_ev_{cid}"):
                st.session_state[add_ev_key] = not st.session_state.get(add_ev_key, False); st.rerun()

            st.divider()

            # ── Action buttons ────────────────────────────────────────────────
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🔄 Refresh", key=f"refresh_{cid}", use_container_width=True):
                    try:
                        api("post", f"/components/{cid}/refresh").raise_for_status()
                        st.success("Refreshed."); st.rerun()
                    except Exception as e:
                        st.error(f"Refresh failed: {e}")
            with c2:
                if st.button("✏️ Edit", key=f"edit_btn_{cid}", use_container_width=True):
                    st.session_state[edit_key] = not st.session_state.get(edit_key, False); st.rerun()
            with c3:
                if st.button("❌ Delete", key=f"delete_{cid}", use_container_width=True):
                    try:
                        api("delete", f"/components/{cid}").raise_for_status()
                        st.success("Deleted."); st.rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: IMPORT
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📥 Import":
    st.title("📥 Bulk Import")

    st.markdown("""
Upload a JSON file with a list of components to analyze and add in one go.
Each component will be checked against NVD/OSV automatically.
Already-existing components (same name + version + type + ecosystem) are skipped.

**[Download example file](https://raw.githubusercontent.com/denimoll/oss-monitor/develop/examples/import.json)**
""")

    with st.expander("JSON format reference"):
        st.code(json.dumps([
            {"type": "product", "name": "nginx", "version": "1.24.0",
             "tags": "prod,web", "repo_url": "https://github.com/nginx/nginx", "notes": "optional"},
            {"type": "library", "name": "lodash", "version": "4.17.21",
             "ecosystem": "npm", "tags": "frontend"},
        ], indent=2), language="json")
        st.caption("Fields: `type` (product/library), `name`, `version` — required. "
                   "`ecosystem` required for libraries. "
                   "Optional: `tags`, `notes`, `repo_url`, `distrib_url`, `identifier_override`.")

    uploaded = st.file_uploader("Upload import.json", type=["json"])

    if uploaded:
        try:
            raw = json.loads(uploaded.read())
            if not isinstance(raw, list):
                st.error("File must contain a JSON array.")
                st.stop()
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}"); st.stop()

        st.info(f"File loaded — **{len(raw)} component(s)** found.")

        if st.button("🚀 Start import", type="primary"):
            with st.spinner(f"Analyzing {len(raw)} components…"):
                try:
                    r = api("post", "/components/import", json=raw)
                    r.raise_for_status()
                    result = r.json()
                except requests.HTTPError as e:
                    st.error(f"Import failed: {e.response.status_code} — {e.response.text}"); st.stop()
                except Exception as e:
                    st.error(f"Import error: {e}"); st.stop()

            imp = result["imported"]
            skp = result["skipped"]
            err = result["errors"]

            col1, col2, col3 = st.columns(3)
            col1.metric("✅ Imported", len(imp))
            col2.metric("⏭️ Skipped (duplicate)", len(skp))
            col3.metric("❌ Errors", len(err))

            if imp:
                with st.expander(f"✅ Imported ({len(imp)})", expanded=True):
                    for item in imp:
                        st.markdown(f"- **{item['name']}** {item['version']} (id: {item['id']})")

            if skp:
                with st.expander(f"⏭️ Skipped ({len(skp)})"):
                    for key in skp: st.markdown(f"- {key}")

            if err:
                with st.expander(f"❌ Errors ({len(err)})"):
                    for e in err:
                        st.markdown(f"- **{e['name']} {e['version']}**: {e['error']}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.title("⚙️ Settings")
    try:
        current = api("get", "/settings").json()
    except Exception as e:
        st.error(f"Failed to load settings: {e}"); st.stop()

    st.subheader("🔔 Webhook Notifications")
    st.caption("Compatible with Slack incoming webhooks, Telegram bots, or any HTTP endpoint accepting JSON POST.")

    webhook_url = st.text_input("Webhook URL", value=current.get("webhook_url") or "",
                                placeholder="https://hooks.slack.com/services/...")
    col1, col2 = st.columns(2)
    with col1:
        notify_critical  = st.toggle("Alert on new Critical CVE",       value=current.get("notify_on_critical", True))
        notify_high      = st.toggle("Alert on new High CVE",           value=current.get("notify_on_high", False))
    with col2:
        notify_scorecard = st.toggle("Daily digest: Scorecard failures", value=current.get("notify_on_scorecard_fail", True))
        notify_stale     = st.toggle("Daily digest: Stale components",   value=current.get("notify_on_stale", True))

    st.divider()
    st.subheader("🚦 Quality Gate Thresholds")
    col3, col4 = st.columns(2)
    with col3:
        sc_min = st.number_input("Minimum Scorecard score (0–10)", min_value=0.0, max_value=10.0, step=0.5,
                                 value=float(current.get("scorecard_min_score", 5.0)))
    with col4:
        stale_days = st.number_input("Stale threshold (days without commits)", min_value=30, max_value=3650, step=30,
                                     value=int(current.get("stale_days_threshold", 730)))

    st.divider()
    st.subheader("🔐 API Authentication")
    st.info("Set the `OSS_MONITOR_API_KEY` environment variable to enable API key authentication. "
            "Pass the key via the `X-API-Key` header. If the variable is not set, auth is disabled.")

    st.divider()
    save_col, test_col, _ = st.columns([1, 1, 2])
    with save_col:
        if st.button("💾 Save settings", use_container_width=True, type="primary"):
            try:
                api("put", "/settings", json={
                    "webhook_url": webhook_url.strip() or None,
                    "notify_on_critical": notify_critical, "notify_on_high": notify_high,
                    "scorecard_min_score": sc_min, "stale_days_threshold": stale_days,
                    "notify_on_scorecard_fail": notify_scorecard, "notify_on_stale": notify_stale,
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
                    r = requests.post(webhook_url.strip(),
                                      json={"text": "✅ OSS Monitor — test notification", "event": "test"}, timeout=5)
                    st.success(f"Delivered ({r.status_code}).") if r.ok else st.warning(f"Endpoint returned {r.status_code}.")
                except Exception as e:
                    st.error(f"Test failed: {e}")
