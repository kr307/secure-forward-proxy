# Aegis Gate: Secure Forward Proxy & URL Filtering Gateway

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![AsyncIO](https://img.shields.io/badge/Concurrency-AsyncIO%20Streams-purple.svg)](https://docs.python.org/3/library/asyncio.html)
[![Tests](https://img.shields.io/badge/Tests-12%20Passed%20(Pytest)-brightgreen.svg)](https://pytest.org)
[![Throughput](https://img.shields.io/badge/Throughput-2%2C600%2B%20req%2Fs-orange.svg)](#performance-benchmarks)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, asynchronous **HTTP/HTTPS Forward Proxy & Secure Web Gateway (SWG)** in miniature — engineered to demonstrate low-level network programming, TCP/TLS fundamentals, socket streaming, and real-time security policy enforcement.

---

## ✨ Features

- **⚡ Asynchronous High-Concurrency Core:** Built on Python's native `asyncio` streams (`asyncio.start_server`). Supports thousands of concurrent connections with minimal memory overhead.
- **🔒 RFC 7231 HTTPS `CONNECT` Tunneling:** Handles end-to-end bidirectional TCP streaming between clients and destination servers.
- **🛡️ In-Memory TLS SNI Inspection:** Zero-dependency binary parser for RFC 6066 / RFC 5246 TLS `ClientHello` packets to inspect the Server Name Indication without breaking end-to-end TLS encryption or installing MITM certificates.
- **🎯 Multi-Tier Policy Engine:**
  - **Categorized Threat Database:** Pre-configured rules for `malware`, `phishing`, `social-media`, `gambling`, `crypto-scams`, and `streaming`.
  - **Custom Overrides:** Real-time exact matches, wildcard domain patterns (`*.domain.com`), and regex rules.
  - **Per-User / Identity Policies:** Enforce granular access based on `Proxy-Authorization` credentials.
- **📊 Real-Time Web Admin Dashboard (Port 8081):**
  - **Live Intercept Feed:** Inspect incoming requests, target hosts, latency, and enforcement outcomes in real time.
  - **Interactive Security Toggles:** 1-click toggle to block/allow entire threat categories without server restart.
  - **Live Policy Simulator:** Test any domain or URL against active policies with instant feedback.
- **💾 Zero-Lock Asynchronous Audit Logger:** Asynchronously batches access logs into SQLite via memory queues, avoiding disk I/O bottlenecks.
- **🚀 Concurrency & Latency Benchmark Suite:** Integrated tool measuring req/sec throughput and latency percentiles ($p50, p95, p99$).

---

## 🏛️ System Architecture

```
                                      +---------------------------------------------+
                                      |                 AEGIS GATE                  |
+-------------+                       |  +---------------------------------------+  |       +---------------------+
|   Client    | --- HTTP Request ---> |  |      Async TCP Listener (Port 8080)   |  | ----> | External Web Server |
| Application |                       |  +---------------------------------------+  |       |  (e.g., origin.com) |
+-------------+                       |                      |                      |       +---------------------+
                                      |  +---------------------------------------+  |                  ^
                                      |  |        Policy Engine Pipeline         |  |                  |
                                      |  | - User Rules  - Wildcards  - Category |  |                  |
                                      |  +---------------------------------------+  |                  |
                                      |         | (Allowed)           | (Blocked)   |                  |
                                      |         v                     v             |                  |
                                      |  +-------------+      +------------------+  |                  |
                                      |  | CONNECT /   |      | 403 Forbidden    |  |                  |
                                      |  | TCP Tunnel  |      | HTML Block Page  |  |                  |
                                      |  +-------------+      +------------------+  |                  |
                                      |         |                      |            |                  |
                                      |         +----------+-----------+            |                  |
                                      |                    v                        |                  |
                                      |  +---------------------------------------+  |                  |
                                      |  |   Async Non-Blocking Queue Writer     |  |                  |
                                      |  +---------------------------------------+  |                  |
                                      +--------------------|------------------------+                  |
                                                           v                                           |
                                               +------------------------+                              |
                                               | SQLite Audit Database  |                              |
                                               +------------------------+                              |
                                                           ^                                           |
                                                           |                                           |
                                               +------------------------+                              |
                                               |  Admin Web Dashboard   | -----------------------------+
                                               |     (Port 8081)        |
                                               +------------------------+
```

---

## ⚡ Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Git

### 1. Clone & Install
```bash
git clone https://github.com/kr307/secure-forward-proxy.git
cd secure-forward-proxy

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Gateway & Dashboard
```bash
python main.py
```

The services will start automatically:
- **Proxy Server:** `http://0.0.0.0:8080`
- **Admin Dashboard:** `http://localhost:8081`

---

## 🧪 Testing the Proxy

### A. Test Allowed Traffic
```bash
# Route a standard request through the proxy
curl -x http://127.0.0.1:8080 -L http://example.com/
```

### B. Test Category Interception (Blocked Social Media)
```bash
# facebook.com is blocked by default under corporate policy
curl -x http://127.0.0.1:8080 -i http://facebook.com/
```
**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Proxy-Action: BLOCKED
X-Proxy-Category: social-media
...
[Zscaler-style responsive HTML Block Page]
```

### C. Test HTTPS CONNECT Tunneling
```bash
curl -x http://127.0.0.1:8080 -I https://www.bbc.com/
```

---

## 📈 Performance Benchmarks

Run the built-in async load testing suite:
```bash
python benchmark/benchmark.py -c 50 -n 500 --mode blocked
```

### Results on Standard Hardware:
| Metric | Result |
| :--- | :--- |
| **Concurrency Level** | 50 simultaneous asynchronous workers |
| **Total Requests** | 500 requests |
| **Throughput** | **2,616.45 requests/sec** |
| **Total Test Duration** | **0.191 seconds** |
| **Median Latency ($p50$)** | **18.89 ms** |
| **95th Percentile ($p95$)** | **22.31 ms** |
| **99th Percentile ($p99$)** | **22.60 ms** |
| **Success Rate** | 100% |

---

## 🧪 Running the Automated Test Suite

```bash
python -m pytest tests/ -v
```

```
tests/test_policy.py::test_category_block PASSED                        [  8%]
tests/test_policy.py::test_category_subdomain_inheritance PASSED        [ 16%]
tests/test_policy.py::test_category_allow PASSED                        [ 25%]
tests/test_policy.py::test_custom_wildcard_rule PASSED                  [ 33%]
tests/test_policy.py::test_custom_exact_rule PASSED                     [ 41%]
tests/test_policy.py::test_default_allow_fallback PASSED                 [ 50%]
tests/test_proxy.py::test_proxy_blocks_forbidden_domain_get PASSED      [ 58%]
tests/test_proxy.py::test_proxy_blocks_forbidden_connect PASSED         [ 66%]
tests/test_sni.py::test_sni_extraction_success PASSED                   [ 75%]
tests/test_sni.py::test_sni_extraction_non_tls PASSED                   [ 83%]
tests/test_sni.py::test_sni_extraction_truncated PASSED                 [ 91%]
tests/test_sni.py::test_sni_extraction_empty PASSED                     [100%]

============================= 12 passed in 0.24s ==============================
```

---

## 🐳 Docker Deployment

Run with Docker Compose:
```bash
docker-compose up --build -d
```
Access the dashboard at `http://localhost:8081`.

---

## 📂 Project Structure

```
secure-forward-proxy/
├── proxy/                   # Core Proxy Engine
│   ├── server.py            # Asyncio TCP Server Listener & Worker Manager
│   ├── handler.py           # HTTP/CONNECT Protocol Parser & Block Pages
│   ├── sni_parser.py        # Binary TLS ClientHello SNI Extractor
│   └── tunnel.py            # High-Throughput Bidirectional TCP Pipe
├── policy/                  # Policy & Threat Intelligence Engine
│   └── engine.py            # Hierarchical Pattern, Regex & Category Evaluator
├── storage/                 # Storage & Auditing Engine
│   └── db.py                # Asynchronous SQLite Queue & Analytical Queries
├── dashboard/               # Administrative Management
│   ├── app.py               # REST API & Web Router (aiohttp)
│   └── templates/
│       └── index.html       # Cybersecurity Dark-Mode UI
├── config/                  # Configuration & Threat Data
│   ├── config.yaml          # Core Settings (Ports, Auth, Policies)
│   └── categories.yaml      # Categorized Domain Threat Intelligence Lists
├── benchmark/               # Performance Testing
│   └── benchmark.py         # Async Concurrency & Latency Benchmarking Tool
├── tests/                   # Automated Pytest Suite
│   ├── test_proxy.py        # Integration Interception Tests
│   ├── test_policy.py       # Engine Rule Precedence Tests
│   └── test_sni.py          # Binary SNI Parsing Tests
├── Dockerfile               # Production Containerfile
├── docker-compose.yml       # Multi-service Orchestration
├── ARCHITECTURE.md          # Technical Architecture & RFC Mechanics Deep Dive
├── INTERVIEW_PREP.md        # 10 Detailed Technical Interview Q&As
└── main.py                  # CLI Entrypoint
```

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

## 👤 Author

**Kritika** ([@kr307](https://github.com/kr307))
- Portfolio: [https://github.com/kr307](https://github.com/kr307)
