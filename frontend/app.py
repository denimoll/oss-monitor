import logging

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
name = st.text_input("Name")
version = st.text_input("Version")

ecosystem = None
if component_type == "library":
    ecosystem = st.selectbox("Ecosystem", ["maven", "npm", "pypi", "go", "nuget", "crates.io"])

# Generate identifier
if st.button("Generate Identifier"):
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

# === Analyze + Add Component ===
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
            analysis = response.json()

            st.subheader("Vulnerabilities")
            for vuln in analysis["vulnerabilities"]:
                st.markdown(f"- **{vuln['id']}** (source: {vuln['source']})")

            st.success("Analysis complete. Click '+' to add this component.")

            if st.button("➕ Add to List"):
                add_payload = {
                    "type": component_type,
                    "name": name,
                    "version": version,
                    "identifier": identifier,
                    "ecosystem": ecosystem,
                    "vulnerabilities": analysis["vulnerabilities"]
                }
                add_payload = {k: v for k, v in add_payload.items() if v is not None}
                add_response = requests.post(f"{API_URL}/components", json=add_payload)
                add_response.raise_for_status()
                logger.info(f"Component added: {name} {version}")
                st.success("Component added.")
                st.rerun()

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            st.error(f"Analysis failed: {e}")

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
    # Show warning icon if vulnerabilities exist
    display_name = f"**{component['name']}** — {component['version']}"
    if component.get("vulnerabilities"):
        display_name = "⚠️  " + display_name

    with st.expander(display_name):
        # Component metadata
        st.text(f"Type: {component['type']}")
        st.text(f"Identifier: {component['identifier']}")
        if component.get("ecosystem"):
            st.text(f"Ecosystem: {component['ecosystem']}")

        # Vulnerability list with links
        if component.get("vulnerabilities"):
            st.text("Vulnerabilities:")
            for vuln in component["vulnerabilities"]:
                vuln_id = vuln.get("id", "Unknown")
                if vuln_id.startswith("CVE"):
                    url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
                elif vuln_id.startswith("GHSA"):
                    url = f"https://github.com/advisories/{vuln_id}"
                else:
                    url = "#"
                st.markdown(f"- [**{vuln_id}**]({url})")

        # Action buttons
        cols = st.columns(6)
        with cols[0]:
            if st.button("✏️ Edit", key=f"edit_{component['id']}"):
                st.warning("Edit functionality coming soon.")
        with cols[5]:
            if st.button("❌ Delete", key=f"delete_{component['id']}"):
                try:
                    del_resp = requests.delete(f"{API_URL}/components/{component['id']}")
                    del_resp.raise_for_status()
                    logger.info(f"Deleted component ID: {component['id']}")
                    st.success("Component deleted.")
                    st.rerun()
                except Exception as e:
                    logger.error(f"Delete failed: {e}")
                    st.error(f"Delete failed: {e}")
