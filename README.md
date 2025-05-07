# oss-monitor
Platform for control your Open Source Software for vulnerabilities and updates.

**oss-monitor** is a tool for managing and monitoring third-party software components, including open-source libraries and standalone applications. It helps identify known vulnerabilities using public vulnerability databases such as OSV and NVD.

## ✨ Features
- Add software components by name, version, type (library or product), and ecosystem
- Automatically generate and validate identifiers (PURL, CPE)
- Query vulnerability databases:
  - [OSV.dev](https://osv.dev)
  - [NVD (National Vulnerability Database)](https://nvd.nist.gov)
- Store components and vulnerability data in a local database.
- REST API with interactive documentation (Swagger UI).

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

### 📚 API Usage
Once running, open your browser at [localhost:8000/docs](localhost:8000/docs). There, you’ll find the full interactive API documentation powered by Swagger UI.
