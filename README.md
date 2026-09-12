# GUARDIAN — ESG Copilot | AI Safety Copilot

## 🎥 Final Submission — Live Demo & Verification

### 🎥 Final Demo (1m 50s): https://www.loom.com/share/70576023c4754abb80fbfd12d5ed01ae
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



2. **Risk-Based Decision Engine**
   - Risk 0.05 → ALLOW
   - Risk 0.65 → REVIEW
   - Risk 0.99 → BLOCK
   

3. **Audit & Observability**
   - “An audit identifier is generated for the demonstrated transaction.”
   - Example audit ID: `f09b9e1a35c68f32`





### Live Proof

- Live application: https://guardian-esg-copilot.onrender.com
- **MOSS Retrieval: 7ms — live observed**
- **MOSS_ENFORCED: true**
- **MOSS: CONNECTED**
- **Risk policy:** 0.05 → ALLOW | 0.65 → REVIEW | 0.99 → BLOCK
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
