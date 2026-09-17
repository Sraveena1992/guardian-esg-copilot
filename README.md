# GUARDIAN — ESG Copilot | Zero-Trust Security Gateway

## 🎥 Final Submission — Live Demo & Verification

### 🎥 Final Demo (67 sec): https://www.loom.com/share/9d2246c31a2842a4b55039a6e3d6ae10
**GitHub:** Sraveena1992/guardian-esg-copilot

**Verification:**
MOSS: guardian_esg_policies — EPA GHG 40 CFR Part 98, Financial Fraud, Prompt Injection Defense | 7ms CONNECTED | MOSS_ENFORCED

**Live Demo:** https://guardian-esg-copilot.onrender.com

**Live Proof:** 7ms MOSS Retrieval — CONNECTED | MOSS_ENFORCED: true | AUDIT: f09b9e1a35c68f32

**Status:** Live Verified — 7ms MOSS Retrieval Observed

### What is GUARDIAN?

“GUARDIAN is an ESG AI safety copilot that retrieves relevant policy context through MOSS and produces explicit risk outcomes: ALLOW, REVIEW, and BLOCK.”

### Architecture

User
↓
Guardian ESG Copilot
↓
FastAPI Request Entry Point
↓
MOSS Policy Retrieval — 7ms observed
↓
Risk Evaluation
├── 0.05 → ALLOW
├── 0.65 → REVIEW
└── 0.99 → BLOCK
↓
Audit Identifier Generated

### Core Features

1. **7ms MOSS Retrieval**
   - Live observed MOSS retrieval result.
   - MOSS status: CONNECTED.
   - MOSS_ENFORCED: true.
   - 7ms is reported as an observed live retrieval result, not as a p50/p95/p99 benchmark.

2. **Deterministic Risk Decisioning**
   - ALLOW triggers a controlled local Weather API mock execution.
   - REVIEW remains pending human approval with execution disabled.
   - BLOCK prevents execution.
   - Demonstrated mapping: 0.05 → ALLOW
   - Demonstrated mapping: 0.65 → REVIEW
   - Demonstrated mapping: 0.99 → BLOCK

3. **Audit Identifier Generation**
   - A unique audit identifier is generated and returned for each policy evaluation request.
   - Example audit ID: `f09b9e1a35c68f32`

### How MOSS Supports the Decision

Guardian retrieves relevant ESG policy context through MOSS before the Guardian decision step.

The current demonstrated flow is:

MOSS Policy Retrieval
↓
Retrieved policy context
↓
Guardian deterministic risk evaluation
↓
Risk outcome
ALLOW / REVIEW / BLOCK

The demonstrated Guardian decision logic maps request patterns to deterministic risk outcomes:

- 0.05 → ALLOW
- 0.65 → REVIEW
- 0.99 → BLOCK

MOSS availability is also part of the safety boundary. When MOSS policy retrieval is unavailable, Guardian fails closed: the demonstrated request is assigned BLOCK with execution disabled and `MODE: FAIL_CLOSED`.

The observed 7ms measurement refers specifically to MOSS policy retrieval and is not an end-to-end latency benchmark.

### Engineering Verification

The repository includes automated safety tests covering request validation, ALLOW execution gating, REVIEW execution blocking, BLOCK execution blocking, MOSS-unavailable fail-closed behavior, and audit record/hash generation.

A minimal Dockerfile and docker-compose configuration are included for reproducible local container execution. Dependencies are pinned in `requirements.txt`, repository hygiene is covered by `.gitignore`, and GitHub Actions runs the pytest suite on pushes and pull requests.

These engineering checks support the demonstrated prototype behavior; they do not claim production authentication, durable external audit storage, or a deployed human-review workflow.

### Live Proof

- Live application: https://guardian-esg-copilot.onrender.com
- **MOSS Retrieval: 7ms — live observed**
- **MOSS_ENFORCED: true**
- **MOSS: CONNECTED**
- **Risk mapping:** 0.05 → ALLOW | 0.65 → REVIEW | 0.99 → BLOCK
- **Audit:** `f09b9e1a35c68f32`

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
MOSS_INDEX_NAME=guardian-security-policies
```

Never commit real credentials or secrets to GitHub.
