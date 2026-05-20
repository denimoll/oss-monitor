import logging
from datetime import datetime

import requests
import streamlit as st

# Backend API URL
API_URL = "http://backend:8000"

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s"
)

st.set_page_config(page_title="OSS Monitor", layout="wide")

# Initialize session state
for key in ["components", "identifier", "analysis_payload"]:
    if key not in st.session_state:
        st.session_state[key] = [] if key == "components" else None

# ─── Sidebar navigation ───────────────────────────────────────────────────────
page = st.sidebar.radio("Navigation", ["📊 Dashboard", "➕ Add Component", "📋 Components"])

# ─── Helper: severity color ───────────────────────────────────────────────────
SEVERITY_COLOR = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "unknown": "⚪",
}


def vuln_url(vuln_id: str) -> str:
    if vuln_id.startswith("CVE"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    elif vuln_id.startswith("GHSA"):
        return f"https://github.com/advisories/{vuln_id}"
    return f"https://deps.dev/advisory/osv/{vuln_id}"


def fetch_components(tag: str | None = None) -> list:
    try:
        params = {"tag": tag} if tag else {}
        r = requests.get(f"{API_URL}/components", params=params)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Failed to load components: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("📊 Dashboard")

    try:
        r = requests.get(f"{API_URL}/dashboard")
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        st.error(f"Failed to load dashboard: {e}")
        st.stop()

    sc = data["severity_counts"]

    # ── Top metrics ──────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Components", data["total_components"])
    col2.metric("With Vulnerabilities", data["components_with_vulns"])
    col3.metric("🔴 Critical", sc.get("critical", 0))
    col4.metric("🟠 High", sc.get("high", 0))
    col5.metric("🟡 Medium", sc.get("medium", 0))

    st.divider()

    # ── Severity breakdown bar ────────────────────────────────────────────────
    total_vulns = sum(sc.values())
    if total_vulns > 0:
        st.subheader("Vulnerability breakdown")
        cols = st.columns(5)
        labels = ["critical", "high", "medium", "low", "unknown"]
        for col, label in zip(cols, labels):
            count = sc.get(label, 0)
            pct = round(count / total_vulns * 100) if total_vulns else 0
            col.metric(f"{SEVERITY_COLOR[label]} {label.capitalize()}", f"{count} ({pct}%)")
    else:
        st.success("No active vulnerabilities found across all components.")

    st.divider()

    # ── Top 5 most vulnerable ────────────────────────────────────────────────
    if data["top_vulnerable"]:
        st.subheader("Top 5 most vulnerable components")
        for item in data["top_vulnerable"]:
            tags_str = f" `{'` `'.join(item['tags'].split(','))} `" if item.get("tags") else ""
            st.markdown(
                f"**{item['name']}** {item['version']}{tags_str} — "
                f"🔴 {item['critical']} critical · 🟠 {item['high']} high · "
                f"**{item['vuln_count']} total**"
            )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ADD COMPONENT
# ══════════════════════════════════════════════════════════════════════════════
elif page == "➕ Add Component":
    st.title("➕ Add Component")

    component_type = st.radio("Component Type", ["library", "product"])
    name = st.text_input("Name", key="name")
    version = st.text_input("Version", key="version")
    tags_input = st.text_input("Tags (comma-separated)", placeholder="prod,db-server,k8s", key="tags_input")

    ecosystem = None
    if component_type == "library":
        ecosystem = st.selectbox("Ecosystem", ["maven", "npm", "pypi", "go", "nuget", "crates.io"])

    # ── Generate identifier ───────────────────────────────────────────────────
    with st.columns(3)[0]:
        if st.button("Generate Identifier", use_container_width=True):
            payload = {"type": component_type, "name": name, "version": version}
            if ecosystem:
                payload["ecosystem"] = ecosystem
            try:
                r = requests.post(f"{API_URL}/generate_identifier", json=payload)
                r.raise_for_status()
                st.session_state.identifier = r.json()["identifier"]
                logger.info(f"Identifier generated: {st.session_state.identifier}")
            except Exception as e:
                st.error(f"Identifier generation failed: {e}")
                st.stop()

    # ── Analyze ───────────────────────────────────────────────────────────────
    if st.session_state.identifier:
        identifier = st.text_input("Edit Identifier", value=st.session_state.identifier)

        if st.button("Analyze"):
            try:
                payload = {
                    "type": component_type,
                    "name": name,
                    "version": version,
                    "identifier_override": identifier,
                }
                if ecosystem:
                    payload["ecosystem"] = ecosystem

                r = requests.post(f"{API_URL}/analyze", json=payload)
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
                    payload["notes"] = notes
                    payload["tags"] = tags_input if tags_input.strip() else None
                    r = requests.post(f"{API_URL}/components", json=payload)
                    r.raise_for_status()
                    st.success("Component added.")
                    logger.info(f"Component added: {name} {version}")
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
# PAGE: COMPONENTS LIST
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📋 Components":
    st.title("📋 Components")

    # ── Tag filter ────────────────────────────────────────────────────────────
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
        tag_options = ["All"] + all_tags
        selected = st.selectbox("Filter by tag", tag_options)
        selected_tag = None if selected == "All" else selected

    components = fetch_components(tag=selected_tag) if selected_tag else all_components

    if not components:
        st.info("No components found. Add one via '➕ Add Component'.")
        st.stop()

    st.caption(f"Showing {len(components)} component(s)")

    # ── Component cards ───────────────────────────────────────────────────────
    for component in components:
        non_fp_vulns = [v for v in component["vulnerabilities"] if not v.get("is_false_positive")]
        severity_icon = ""
        if any(v["severity"] == "critical" for v in non_fp_vulns):
            severity_icon = "🔴 "
        elif any(v["severity"] == "high" for v in non_fp_vulns):
            severity_icon = "🟠 "
        elif non_fp_vulns:
            severity_icon = "⚠️ "

        tags_display = ""
        if component.get("tags"):
            tags_display = " · " + " ".join(f"`{t.strip()}`" for t in component["tags"].split(",") if t.strip())

        display_name = f"{severity_icon}**{component['name']}** — {component['version']}{tags_display}"

        with st.expander(display_name):
            # ── Metadata ──────────────────────────────────────────────────────
            st.text(f"Type: {component['type']}")
            st.text(f"Identifier: {component['identifier']}")
            last_updated = datetime.fromisoformat(str(component['last_updated'])).strftime("%d.%m.%Y %H:%M")
            st.text(f"Last Updated: {last_updated}")
            if component.get("ecosystem"):
                st.text(f"Ecosystem: {component['ecosystem']}")
            if component.get("notes"):
                st.markdown(f"**Notes:** {component['notes']}")

            # ── Edit form ─────────────────────────────────────────────────────
            edit_key = f"editing_{component['id']}"
            if st.session_state.get(edit_key):
                st.subheader("Edit")
                new_notes = st.text_area("Notes", value=component.get("notes") or "", key=f"edit_notes_{component['id']}")
                new_tags = st.text_input("Tags", value=component.get("tags") or "", key=f"edit_tags_{component['id']}")
                save_col, cancel_col = st.columns(2)
                with save_col:
                    if st.button("💾 Save", key=f"save_{component['id']}", use_container_width=True):
                        try:
                            r = requests.patch(
                                f"{API_URL}/components/{component['id']}",
                                json={
                                    "notes": new_notes or None,
                                    "tags": new_tags.strip() or None,
                                }
                            )
                            r.raise_for_status()
                            st.success("Saved.")
                            st.session_state[edit_key] = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"Save failed: {e}")
                with cancel_col:
                    if st.button("Cancel", key=f"cancel_{component['id']}", use_container_width=True):
                        st.session_state[edit_key] = False
                        st.rerun()

            # ── Vulnerabilities ───────────────────────────────────────────────
            if component.get("vulnerabilities"):
                st.markdown("**Vulnerabilities:**")
                for vuln in component["vulnerabilities"]:
                    vuln_id = vuln.get("cve_id", "Unknown")
                    is_fp = vuln.get("is_false_positive", False)
                    reason = vuln.get("false_positive_reason", "")
                    severity = vuln.get("severity", "unknown").lower()
                    color_map = {
                        "critical": "red", "high": "orange",
                        "medium": "#cccc00", "low": "green", "unknown": "gray"
                    }
                    color = color_map.get(severity, "gray")
                    url = vuln_url(vuln_id)
                    icon = SEVERITY_COLOR.get(severity, "⚪")

                    label_html = f'<span style="color:{color};font-weight:bold;">{icon} {vuln_id} ({severity.upper()})</span>'
                    if not is_fp:
                        vuln_display = f'<a href="{url}" target="_blank">{label_html}</a>'
                    else:
                        vuln_display = f"<s>{label_html}</s>"

                    cols = st.columns([0.35, 0.1, 0.55], vertical_alignment="center")
                    with cols[0]:
                        st.markdown(vuln_display, unsafe_allow_html=True)
                    with cols[1]:
                        new_fp = st.checkbox("FP", value=is_fp, key=f"fp_{component['id']}_{vuln_id}")
                    with cols[2]:
                        new_reason = st.text_input(
                            "Reason", value=reason or "",
                            key=f"reason_{component['id']}_{vuln_id}",
                            placeholder="why is FP",
                            label_visibility="collapsed"
                        )

                    if new_fp != is_fp:
                        try:
                            requests.patch(
                                f"{API_URL}/vulnerabilities/{vuln['id']}/false_positive",
                                json={"is_false_positive": new_fp, "reason": new_reason}
                            )
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to mark as FP: {e}")
            else:
                st.success("No vulnerabilities found for this component.")

            # ── Action buttons ────────────────────────────────────────────────
            st.divider()
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🔄 Refresh", key=f"refresh_{component['id']}", use_container_width=True):
                    try:
                        r = requests.post(f"{API_URL}/components/{component['id']}/refresh")
                        r.raise_for_status()
                        st.success("Refreshed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Refresh failed: {e}")
            with c2:
                if st.button("✏️ Edit", key=f"edit_btn_{component['id']}", use_container_width=True):
                    st.session_state[f"editing_{component['id']}"] = True
                    st.rerun()
            with c3:
                if st.button("❌ Delete", key=f"delete_{component['id']}", use_container_width=True):
                    try:
                        r = requests.delete(f"{API_URL}/components/{component['id']}")
                        r.raise_for_status()
                        st.success("Deleted.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e}")
