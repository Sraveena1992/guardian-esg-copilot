# GUARDIAN — ESG Copilot | Zero-Trust Security Gateway

## 🎥 Final Submission — Live Demo & Verification

### 🎥 Final Demo (2min 12sec): https://www.loom.com/share/8c5fc882055d439b8d7d5c777e3e90d4
**GitHub:** Sraveena1992/guardian-esg-copilot

**Verification:**
Policy context: guardian_esg_policies — EPA GHG 40 CFR Part 98, Financial Fraud Prevention, Prompt Injection Defense, Secrets Management | 7ms observed in current demo UI | MOSS_ENFORCED mode

**Live Demo:** https://guardian-esg-copilot.onrender.com

**Live Proof:** 7ms observed policy-context processing | MOSS_ENFORCED mode | Request-level Audit ID + SHA-256 generated

**Status:** Live Verified — 7ms observed policy-context processing

### What is GUARDIAN?

“GUARDIAN is an ESG AI safety copilot that processes policy context and produces explicit risk outcomes: ALLOW, REVIEW, and BLOCK.”

### Architecture

User
↓
Guardian ESG Copilot
↓
FastAPI Request Entry Point
↓
Policy-Context Processing — 7ms observed
↓
Risk Evaluation
├── 0.05 → ALLOW
├── 0.65 → REVIEW
└── 0.99 → BLOCK
↓
Audit ID + SHA-256 Hash Generated

### Core Features

1. **7ms Observed Policy-Context Processing**
   - Live observed policy-context processing result.
   - MOSS_ENFORCED mode is active.
   - 7ms is not an end-to-end latency benchmark.

2. **Deterministic Risk Decisioning**
   - ALLOW triggers a controlled local Weather API mock execution.
   - REVIEW remains pending human approval with execution disabled.
   - BLOCK prevents execution.
   - Demonstrated mapping: 0.05 → ALLOW
   - Demonstrated mapping: 0.65 → REVIEW
   - Demonstrated mapping: 0.99 → BLOCK

3. **Audit Identifier Generation**
   - A unique audit identifier is generated and returned for each policy evaluation request.
   - A SHA-256 hash is generated for the corresponding runtime audit record.

### How MOSS Supports the Decision

Guardian processes the demonstrated policy context before the deterministic Guardian decision step.

The current demonstrated flow is:

Policy-Context Processing
↓
Processed policy context
↓
Guardian deterministic risk evaluation
↓
Risk outcome
ALLOW / REVIEW / BLOCK

The demonstrated Guardian decision logic maps request patterns to deterministic risk outcomes:

- 0.05 → ALLOW
- 0.65 → REVIEW
- 0.99 → BLOCK

Policy-layer failure is also part of the safety boundary. Guardian includes a fail-closed path where execution is blocked by default when the policy layer is unavailable.

The observed 7ms value refers to the demonstrated policy-context processing display and is not an end-to-end latency benchmark.

### Engineering Verification

The repository includes automated safety tests covering request validation, ALLOW execution gating, REVIEW execution blocking, BLOCK execution blocking, MOSS-unavailable fail-closed behavior, and audit record/hash generation.

A minimal Dockerfile and docker-compose configuration are included for reproducible local container execution. Dependencies are pinned in `requirements.txt`, repository hygiene is covered by `.gitignore`, and GitHub Actions runs the pytest suite on pushes and pull requests.

Rate limiting is configurable through environment variables and supports an optional Redis-backed backend. The local Docker Compose configuration starts Redis; when Redis is not configured, Guardian uses the bounded in-process fallback. Structured audit records are retained as JSONL for the prototype and are also emitted to application logs.

These engineering checks support the demonstrated prototype behavior; they do not claim production authentication, durable external audit storage, or a deployed human-review workflow.

### Live Proof

- Live application: https://guardian-esg-copilot.onrender.com
- **Policy-context processing: 7ms — live observed**
- **MOSS_ENFORCED mode is active**
- **MOSS: CONNECTED**
- **Risk mapping:** 0.05 → ALLOW | 0.65 → REVIEW | 0.99 → BLOCK
- **Audit:** Unique request-level Audit ID + SHA-256 hash generated per policy evaluation request.

### How to Run

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

### Environment Variables

Create a `.env` file with:

```env
MOSS_PROJECT_ID=your_moss_project_id
MOSS_PROJECT_KEY=your_moss_project_key
MOSS_INDEX_NAME=guardian_esg_policies
```

Never commit real credentials or secrets to GitHub.
