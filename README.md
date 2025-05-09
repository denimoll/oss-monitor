# oss-monitor
Platform for control your Open Source Software for vulnerabilities and updates.

**oss-monitor** is a tool for managing and monitoring third-party software components, including open-source libraries and standalone applications. It helps identify known vulnerabilities using public vulnerability databases such as OSV and NVD.

## ✨ Features
- 🔍 Add components by name, version, type (library or product), and ecosystem
- 🔗 Automatically generate unique identifiers:
  - **PURL** (Package URL) for libraries
  - **CPE** (Common Platform Enumeration) for products
- 📡 Query public vulnerability databases:
  - [OSV.dev](https://osv.dev)
  - [NVD (National Vulnerability Database)](https://nvd.nist.gov)
- 💾 Store components and their associated vulnerabilities in a local database
- 🌐 REST API with interactive Swagger documentation
- 🖥️ Web UI built with Streamlit for easy, no-code interaction

## 🚀 Getting Started with Docker Compose

### 🧰 Prerequisites
- Docker [https://docs.docker.com/get-docker/](installed)
- Docker Compose [https://docs.docker.com/compose/install/](installed)

### 🐳 Build & Run
From the project root directory:
```
docker-compose up --build
```
This will:
- Build the backend and frontend images
- Mount a volume for persistent SQLite storage
- Start the oss-monitor

### 📺 Web Interface (Streamlit)
The frontend UI will be available at [localhost:8501](localhost:8501).

### 📚 API Usage
Once running, open your browser at [localhost:8000/docs](localhost:8000/docs). There, you’ll find the full interactive API documentation powered by Swagger UI.
