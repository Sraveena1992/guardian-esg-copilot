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
   - Live observed Moss retrieval result.
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


### How MOSS Drives the Decision

Guardian uses MOSS to retrieve the relevant ESG policy context before deterministic scoring.

The retrieved policy provides parameters such as `strict_score_threshold` and `risk_factor`. These parameters are used by the deterministic scoring logic to calculate the policy evaluation score, which is then mapped to the demonstrated ALLOW, REVIEW, or BLOCK outcome.

Flow:

MOSS Policy Retrieval
↓
Retrieved policy parameters
(`strict_score_threshold`, `risk_factor`)
↓
Deterministic score calculation
↓
Risk outcome
ALLOW / REVIEW / BLOCK

MOSS is demonstrated as the policy-context retrieval layer preceding Guardian's deterministic risk evaluation. The observed 7ms measurement refers specifically to MOSS policy retrieval and is not an end-to-end latency benchmark.


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
