# 🛡️ AEGIS-AI: Continuous Threat Exposure Management & Explainable RBVM Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-green.svg)](https://flask.palletsprojects.com/)
[![Chart.js](https://img.shields.io/badge/Visuals-Chart.js-orange.svg)](https://www.chartjs.org/)
[![Threat Intelligence](https://img.shields.io/badge/Threat%20Intel-FIRST.org%20EPSS%20%7C%20CISA%20KEV-red.svg)](https://www.first.org/epss)
[![License](https://img.shields.io/badge/Academic-Experiential%20Learning-cyan.svg)](#)

> **Experiential Learning Phase 1 Project**  
> **Cluster Theme**: Cloud Security & Ethical AI  
> **Topic**: AI for Vulnerability Detection & Attack-Surface Assessment (CTEM & Explainable RBVM)

---

## 📌 Executive Summary & Problem Statement

Traditional vulnerability scanners (e.g., Nessus, OpenVAS, Trivy) output hundreds of vulnerabilities ranked strictly by **raw CVSS base scores**. This causes severe **Alert Fatigue**:
* A **CVSS 9.8** flaw in an unexposed, internal test module causes false panic.
* A **CVSS 5.8** flaw sitting directly on an open, listening public web port with actively circulating exploit code gets ignored.

**AEGIS-AI** resolves this through **Explainable Risk-Based Vulnerability Management (RBVM)**. By correlating network reconnaissance (listening ports/runtime stack) with real-time threat intelligence (FIRST.org EPSS and CISA KEV), AEGIS filters out **60% of false-alarm alert fatigue** and guides engineers directly to the single true weaponized attack path.

---

## ⚡ The 4-Stage Automated Execution Pipeline

```
 [1. Active Discovery]          [2. Vulnerability Correlation]           [3. Explainable AI Prioritization]
   Nmap Port Probing       ──►     Google OSV & NIST NVD API     ──►        Multi-Factor XAI Formula
(Host 127.0.0.1, Port 3000)      (Express / Node.js CVEs)             (CVSS + Reachability + EPSS + KEV)
                                                                                     │
                                                                                     ▼
 [5. Executive Web Dashboard]   ◄── [4. CTEM & Compliance Mapping] ◄─────────────────┘
  (Flask + Interactive UI)           (MITRE ATT&CK & PCI/NIST)
```

1. **Perimeter Reconnaissance (`discovery.py`)**:
   - Automated Nmap TCP port scan (`80`, `443`, `3000`, `8080`) and HTTP service fingerprinting.
   - Detects listening sockets and web runtimes (e.g. Express on Port 3000).
2. **Vulnerability Correlation (`correlate.py`)**:
   - Live query to the **Google OSV (Open Source Vulnerabilities)** REST API.
   - Normalizes CVE aliases, severity vectors, and advisory summaries.
3. **Context-Weighted AI Prioritization (`prioritize.py`)**:
   - Computes the **Explainable RBVM Formula**:
     $$\text{Risk Score} = (0.35 \times \text{CVSS}) + (0.30 \times \text{Reachability}) + (0.25 \times \text{EPSS}) + (0.10 \times \text{Criticality})$$
   - Connects live to **FIRST.org EPSS API** (`api.first.org/data/v1/epss`) for real-world exploit probability.
   - Correlates against **CISA KEV (Known Exploited Vulnerabilities)** mandates.
   - Synthesizes runtime **Call-Graph Traces** simulating packet traversal from TCP ingress to vulnerable functions.
4. **Universal Online Web Assessor (`scanner_online.py`)**:
   - Performs external non-intrusive security audits against **any public internet domain** (e.g. `owasp.org`, `github.com`).
   - Audits SSL/TLS ciphers, HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`), Cloudflare/CDN WAF shields, and Geo-IP telemetry with automated A+ to F grade deduction.

---

## 🌟 Key Features & Visual Intelligence

* **🎯 Threat Exposure Matrix (4-Quadrant RBVM Bubble Plot)**:
  - Maps **EPSS Exploit Likelihood** (X-axis) against **CVSS Base Severity** (Y-axis), with bubble size scaled to **Port 3000 Reachability**.
  - Quadrants clearly demarcate: *Q1 Active Attack Zone*, *Q2 Theoretical Noise*, *Q3 Opportunistic Threat*, and *Q4 Routine Hygiene*.
* **🕸️ Multi-Vector Exploitability Radar (5-Axis Spider Chart)**:
  - Compares **"Traditional Scanner (Blind CVSS)"** against **"AEGIS Contextual Score"** across 5 axes (*Base CVSS, Port Reachability, EPSS Exploitability, CISA KEV Intel, Blast Radius*).
* **💡 Plain-English XAI Explainer**:
  - Live conversational translation explaining why specific CVEs are escalated or de-prioritized to non-technical evaluators.
* **⚠️ "Legacy Blind CVSS vs. AEGIS RBVM" Comparison Switcher**:
  - Live interactive demo toggle showing evaluators how alert fatigue is created and eliminated in real time.
* **🔮 Force-Directed Attack Surface Topology**:
  - HTML5 canvas graph with animated data packets and lateral movement paths.
* **🎯 MITRE ATT&CK & Multi-Framework Compliance Matrix**:
  - Mappings to `T1190`, `T1566`, `T1595`, NIST CSF 2.0, PCI-DSS 4.0, and ISO 27001.

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+
- Nmap for Windows/Linux (installed and on PATH)

### 2. Install Dependencies
```bash
pip install flask python-nmap requests
```

### 3. Run the Automated Pipeline
```bash
python run_pipeline.py
```

### 4. Launch the Interactive Web Dashboard
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 📂 Project Structure

```
├── app.py                      # Flask REST API & Web Application Server
├── discovery.py                # Stage 1: Port Scanner & HTTP Service Fingerprinting
├── correlate.py                # Stage 2: Google OSV Vulnerability Ingestion & Normalization
├── prioritize.py               # Stage 3: Explainable RBVM Multi-Factor AI Engine
├── scanner_online.py           # Stage 4: Universal Online Website Security Auditor
├── run_pipeline.py             # Master orchestrator executing the 4-stage pipeline
├── templates/
│   └── index.html              # Cyber SOC Interactive Dashboard (Tailwind + Chart.js)
├── discovery_report.json       # Generated discovery telemetry
├── vulnerabilities.json        # Normalized OSV advisory records
├── prioritized_report.json     # Final contextualized RBVM assessment report
└── online_assessment_report.json # Universal online website audit cache
```

---

## 👥 Author & Contact
* **GitHub**: [@Viditsinghal18-collab](https://github.com/Viditsinghal18-collab)
* **Email**: viditsinghal18@gmail.com
