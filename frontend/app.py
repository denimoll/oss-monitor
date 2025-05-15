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

# Initialize session state for components
if "components" not in st.session_state:
    st.session_state.components = []

# App title
st.title("Open Source Software Monitor")

# === Component Form ===
st.header("Add Component")

component_type = st.radio("Component Type", ["library", "product"])
name = st.text_input("Name", key="name")
version = st.text_input("Version", key="version")

ecosystem = None
if component_type == "library":
    ecosystem = st.selectbox("Ecosystem", ["maven", "npm", "pypi", "go", "nuget", "crates.io"])

# Generate identifier
with st.columns(3)[0]:
    if st.button("Generate Identifier", use_container_width=True):
        payload = {
            "type": component_type,
            "name": name,
            "version": version,
        }
        if ecosystem:
            payload["ecosystem"] = ecosystem

        try:
            response = requests.post(f"{API_URL}/generate_identifier", json=payload)
            response.raise_for_status()
            identifier = response.json()["identifier"]
            st.session_state.identifier = identifier
            logger.info(f"Identifier generated: {identifier}")
        except Exception as e:
            logger.error(f"Identifier generation failed: {e}")
            st.error(f"Identifier generation failed: {e}")
            st.stop()

# === Analyze Component ===
if "identifier" in st.session_state:
    identifier = st.text_input("Edit Identifier", value=st.session_state.identifier)
    
    if st.button("Analyze"):
        try:
            payload = {
                "type": component_type,
                "name": name,
                "version": version,
                "identifier_override": identifier
            }
            if ecosystem:
                payload["ecosystem"] = ecosystem

            response = requests.post(f"{API_URL}/analyze", json=payload)
            response.raise_for_status()
            st.session_state.analysis_payload = payload
            analysis = response.json()

            st.subheader("Vulnerabilities")
            for vuln in analysis["vulnerabilities"]:
                st.markdown(f"- **{vuln}**")

            st.success("Analysis complete. Click '+' to add this component.")

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            st.error(f"Analysis failed: {e}")

# === Show Analysis Result & Add ===
if "analysis_payload" in st.session_state:
    notes = st.text_area("Notes (optional)")
    cols = st.columns(3)
    with cols[0]:
        if st.button("➕ Add", use_container_width=True):
            try:
                payload = st.session_state.analysis_payload
                payload["notes"] = notes
                add_response = requests.post(f"{API_URL}/components", json=payload)
                add_response.raise_for_status()
            except requests.HTTPError as e:
                st.error(f"Add failed: {e.response.status_code} — {e.response.text}")
                logger.error(f"Add failed: {e.response.status_code} — {e.response.text}")
                st.stop()
            logger.info(f"Component added: {name} {version}")
            st.success("Component added.")
            for key in ["identifier", "analysis_payload", "name", "version"]:
                st.session_state.pop(key, None)
            st.rerun()
    with cols[2]:
        if st.button("🧹 Clear", use_container_width=True):
            for key in ["identifier", "analysis_payload", "name", "version"]:
                st.session_state.pop(key, None)
            st.rerun()

# === Component List Display ===
st.header("Your Components")

try:
    response = requests.get(f"{API_URL}/components")
    response.raise_for_status()
    components = response.json()
except Exception as e:
    logger.error(f"Failed to load components: {e}")
    st.error(f"Failed to load components: {e}")
    components = []

for component in components:
    # Show warning icon if vulnerabilities exist and not FP
    non_fp_vulns = [v for v in component["vulnerabilities"] if not v.get("is_false_positive")]
    display_name = f"**{component['name']}** — {component['version']}"
    if non_fp_vulns:
        display_name = "⚠️  " + display_name

    with st.expander(display_name):
        # Component metadata
        st.text(f"Type: {component['type']}")
        st.text(f"Identifier: {component['identifier']}")
        last_updated = datetime.fromisoformat(component['last_updated']).strftime("%d.%m.%Y %H:%M")
        if component.get("notes"):
            st.markdown(f"Notes: {component['notes']}")
        st.text(f"Last Updated: {last_updated}")
        if component.get("ecosystem"):
            st.text(f"Ecosystem: {component['ecosystem']}")

        # Vulnerability list with links
        if component.get("vulnerabilities"):
            st.text("Vulnerabilities:")

            for vuln in component["vulnerabilities"]:
                vuln_id = vuln.get("cve_id", "Unknown")
                is_fp = vuln.get("is_false_positive", False)
                reason = vuln.get("false_positive_reason", "")
                severity = vuln.get("severity", "unknown").lower()
                color = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "green",
                    "unknown": "gray"
                }.get(severity.lower(), "gray")

                if vuln_id.startswith("CVE"):
                    url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
                elif vuln_id.startswith("GHSA"):
                    url = f"https://github.com/advisories/{vuln_id}"
                else:
                    url = "#"
                
                label_html = f"""<span style="color:{color}; font-weight:bold;">{vuln_id} ({severity.upper()})</span>"""
                if not is_fp:
                    vuln_display = f'<a href="{url}" target="_blank">{label_html}</a>'
                else:
                    vuln_display = f"<s>{label_html}</s>"

                cols = st.columns([0.3, 0.1, 0.6], vertical_alignment="center")
                with cols[0]:
                    st.markdown(vuln_display, unsafe_allow_html=True)
                with cols[1]:
                    checkbox_key = f"fp_cb_{component['id']}_{vuln_id}"
                    new_fp = st.checkbox("FP", value=is_fp, key=checkbox_key)
                with cols[2]:
                    reason_key = f"fp_reason_{component['id']}_{vuln_id}"
                    new_reason = st.text_input("Reason", value=reason, key=reason_key,
                                    placeholder="why is fp", label_visibility="collapsed")
                
                if new_fp != is_fp:
                    try:
                        payload = {
                            "is_false_positive": new_fp,
                            "reason": new_reason
                        }
                        requests.patch(
                            f"{API_URL}/vulnerabilities/{vuln.get('id')}/false_positive",
                            json=payload
                        )
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to mark as FP: {e}")
                

        # Action buttons
        cols = st.columns(3)
        with cols[0]:
            if st.button("🔄 Refresh", key=f"refresh_{component['id']}", use_container_width=True):
                try:
                    refresh_resp = requests.post(f"{API_URL}/components/{component['id']}/refresh")
                    refresh_resp.raise_for_status()
                    logger.info(f"Component ID: {component['id']} refreshed.")
                    st.success("Component refreshed.")
                    st.rerun()
                except Exception as e:
                    logger.error(f"Refresh failed: {e}")
                    st.error(f"Refresh failed: {e}")
        with cols[1]:
            if st.button("✏️ Edit", key=f"edit_{component['id']}", use_container_width=True, disabled=True):
                st.warning("Edit functionality coming soon.")
        with cols[2]:
            if st.button("❌ Delete", key=f"delete_{component['id']}", use_container_width=True):
                try:
                    del_resp = requests.delete(f"{API_URL}/components/{component['id']}")
                    del_resp.raise_for_status()
                    logger.info(f"Deleted component ID: {component['id']}")
                    st.success("Component deleted.")
                    st.rerun()
                except Exception as e:
                    logger.error(f"Delete failed: {e}")
                    st.error(f"Delete failed: {e}")
