# SPECTRE — API Discovery Engine

> **S**hadow, **P**hantom, **C**lassified, **T**erminated & **R**ogue API **E**ngine

[![Live Demo](https://img.shields.io/badge/Live%20Demo-spectre--ai--xi.vercel.app-00e676?style=flat-square&logo=vercel&logoColor=black)](https://spectre-ai-xi.vercel.app/)
[![Backend](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat-square&logo=render&logoColor=black)](https://spectre-ai-gls6.onrender.com/ping)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

---

## What this is

This is the **discovery engine** for SPECTRE — a platform built to answer one question every security team should be asking:

> *"What APIs are currently live on our network, and are any of them dangerous?"*

Modern organizations accumulate APIs over years of development. Endpoints get deprecated but never switched off. Debug routes get forgotten in production. Services get migrated but old APIs keep running with no authentication, no rate limiting, and nobody watching them. These are called **Shadow APIs** and **Zombie APIs** — and they are one of the most common and underreported attack surfaces in software systems today.

This engine finds them. It scans four sources simultaneously, cross-references what it finds across all of them, and surfaces every endpoint — including the ones that exist nowhere on paper.

---

## Live demo

**[spectre-ai.vercel.app](https://spectre-ai-xi.vercel.app/)**

The demo runs your actual Python scanner on a bundled test environment with a planted shadow API. You can also upload your own Nginx configs, Kong YAML, or Python service files to scan them directly.

---

## How it works

The scanner runs a four-source discovery pipeline:
```
Nginx configs ──────┐
Kong YAML ──────────┤──► Merge & deduplicate ──► discovered_endpoints.json
Python source code ─┤
Network traffic ────┘
         (mitmproxy)
```

**Stage 1 — Nginx parser** reads gateway config files and extracts every `location` block, detecting auth mechanisms like `auth_jwt` and `auth_basic` at the config level.

**Stage 2 — Kong parser** reads Kong declarative YAML configs, traverses the service/route/plugin tree, and handles auth detection at both service level and route level independently.

**Stage 3 — AST parser** uses Python's built-in `ast` module to walk the syntax tree of FastAPI and Flask source files, extracting route decorators without executing any code. Detects auth via function argument analysis.

**Stage 4 — Traffic capture** runs a script inside mitmproxy that intercepts live HTTP traffic and logs every unique endpoint observed. An endpoint that appears here but in none of the other three sources is a **shadow API** — the core finding SPECTRE is built around.

The main scanner merges all four sources, deduplicates by endpoint ID, and produces a single `discovered_endpoints.json` file. Each record carries where the endpoint was found, whether authentication was detected, what HTTP status codes were observed in traffic, and a `state` field that the classifier uses downstream.

---

## Shadow API detection

The defining feature of this scanner. An endpoint is flagged as a shadow API when:
```
seen_in_traffic = true
AND in_gateway   = false
AND in_repo      = false
```

It exists. It is receiving real traffic. But it appears in no config file and no codebase. This is **OWASP API9: Improper Inventory Management** — and it is the root cause of some of the most serious API breaches on record.

---

## Endpoint record format

Every discovered endpoint produces one record matching this schema:
```json
{
  "id": "1316b67f45e6",
  "method": "GET",
  "path": "/api/v1/users",
  "service_name": "user-service",
  "sources": ["nginx_config", "code_repository"],
  "in_repo": true,
  "in_gateway": true,
  "seen_in_traffic": false,
  "auth_detected": false,
  "auth_type": "none",
  "status_codes": [200, 401],
  "last_seen": "2025-03-17T10:00:00Z",
  "tags": ["nginx", "python"],
  "raw_context": "location /api/v1/users { proxy_pass http://user-service; }",
  "also_found_in_conflict_with": null,
  "state": "unknown",
  "owasp_flags": [],
  "risk_reason": ""
}
```

`state`, `owasp_flags`, and `risk_reason` are populated by the classifier in the next stage of the SPECTRE pipeline.

**Valid source values:** `nginx_config` · `kong_gateway` · `code_repository` · `network_traffic` · `kubernetes`

**Valid state values:** `active` · `shadow` · `zombie` · `rogue` · `unknown`

---

## Project structure
```
spectre-discovery/
├── scanner/
│   ├── schema.py               ← shared data contract, all stages import this
│   ├── main.py                 ← entry point, runs all parsers, merges output
│   └── parsers/
│       ├── nginx_parser.py     ← regex-based Nginx location block extractor
│       ├── kong_parser.py      ← YAML parser, handles service + route plugins
│       ├── ast_parser.py       ← Python syntax tree walker, FastAPI + Flask
│       └── traffic_parser.py   ← mitmproxy script, logs every HTTP endpoint
├── backend/
│   ├── main.py                 ← FastAPI wrapper, exposes scanner via HTTP
│   └── requirements.txt
├── test_files/
│   ├── test_nginx.conf         ← sample config with 5 routes, mixed auth
│   ├── test_kong.yml           ← sample Kong config with plugin-level auth
│   └── test_fastapi_service.py ← sample FastAPI app with 7 routes
├── output/                     ← gitignored, generated at runtime
│   └── discovered_endpoints.json
├── index.html                  ← frontend demo, single file
├── render.yaml                 ← Render deployment config
├── vercel.json                 ← Vercel deployment config
└── .gitignore
```

---

## Setup

**Requirements:** Python 3.11+, Git
```bash
# Clone
git clone https://github.com/neerajgandhii/spectre-ai.git
cd spectre-discovery

# Virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac / Linux

# Dependencies
pip install -r backend/requirements.txt
pip install mitmproxy        # only needed for traffic capture

# Verify
python scanner/schema.py
# Should print a sample endpoint and "Valid — no errors found."
```

---

## Running the scanner

### Quick run — file parsers only
```bash
python scanner/main.py
```

Scans `test_files/` and writes `output/discovered_endpoints.json`.

### Full run — including live traffic capture

You need three terminals open at the same time.

**Terminal 1 — start a test service:**
```bash
pip install fastapi uvicorn
uvicorn test_files.test_fastapi_service:app --port 8001
```

**Terminal 2 — start mitmproxy:**
```bash
mitmdump -s scanner/parsers/traffic_parser.py --listen-port 8080
```

**Terminal 3 — send traffic through the proxy:**
```bash
# Windows
curl.exe --proxy http://localhost:8080 http://localhost:8001/api/v1/users
curl.exe --proxy http://localhost:8080 http://localhost:8001/internal/debug
```

Watch Terminal 2 — you will see endpoints being logged in real time. Then run the full scanner:
```bash
python scanner/main.py
```

### Running individual parsers
```bash
python scanner/parsers/nginx_parser.py
python scanner/parsers/ast_parser.py
python scanner/parsers/kong_parser.py
```

Each one reads from `test_files/`, prints findings, and saves sample output to `output/`.

---

## Running the backend locally
```bash
uvicorn backend.main:app --reload --port 8000
```

Test it:
```bash
curl http://localhost:8000/ping
curl -X POST http://localhost:8000/scan/sample
```

The `/scan/sample` endpoint runs your real parsers on the bundled test files and returns the full discovered endpoint list as JSON.

---

## Deployment

**Backend → Render (free tier)**

The repo includes `render.yaml` which Render reads automatically. Connect your GitHub repo on render.com, select "Web Service", and it deploys itself. The service sleeps after 15 minutes of inactivity — the frontend sends a wake-up ping the moment the page loads so it's warm before the user clicks anything.

**Frontend → Vercel (free tier)**

The repo includes `vercel.json`. Connect your GitHub repo on vercel.com or run:
```bash
npm install -g vercel
vercel
```

After deploying the backend, update `const BACKEND` in `index.html` to your Render URL before deploying the frontend.

---

## Part of a larger system

This repository is the discovery stage of the SPECTRE platform. The output file feeds into three downstream components built by the rest of the team:

| Stage | What it does |
|-------|-------------|
| Classifier | Labels each endpoint as Active, Shadow, Zombie, or Rogue using deterministic rules |
| OWASP Checker | Tests each endpoint against API2, API4, API8, and API9 via active HTTP probing |
| AI Layer | Generates plain-English risk summaries and remediation steps using LangChain + RAG |
| Dashboard | Displays everything in a real-time React monitoring interface |

---

## Tech stack

| Tool | Purpose |
|------|---------|
| Python 3.11 | Core language |
| `ast` module | Syntax tree parsing for route extraction from source code |
| `pyyaml` | Kong YAML config parsing |
| `mitmproxy` | Live HTTP traffic interception and logging |
| `FastAPI` | Backend API wrapper for the demo |
| `uvicorn` | ASGI server |
| Docker Compose | Mock service environment for testing |

---

## References

1. OWASP Foundation — OWASP API Security Top 10, 2023 Edition
2. Haupt et al. — A Framework for the Structural Analysis of REST APIs, IEEE SOSE 2017
3. Fang et al. — LLM Agents Can Autonomously Exploit One-Day Vulnerabilities, arXiv 2024
4. Postman Inc. — 2023 State of the API Report
5. Salt Security — State of API Security Report Q1 2023

---

## Author

**Neeraj Gandhi**
B.Tech Computer Science & Engineering — Semester VIII
Guru Tegh Bahadur Institute of Technology, Delhi
Affiliated to Guru Gobind Singh Indraprastha University

[![LinkedIn](https://img.shields.io/badge/LinkedIn-neerajgandhii-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/neerajgandhii/)
[![Email](https://img.shields.io/badge/Email-neerajgandhii2003%40gmail.com-EA4335?style=flat-square&logo=gmail&logoColor=white)](mailto:neerajgandhii2003@gmail.com)

---

## License

MIT License — Copyright (c) 2025 Neeraj Gandhi

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.