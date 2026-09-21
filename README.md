# GUARDIAN — ESG Policy Enforcement Gateway

## 🎥 Final Submission — Live Demo & Verification

### Final Demo
https://www.loom.com/share/ebf6fce7eca947c3ab48951413ad09f1

### 🔍 Live Verification
- **Live App:** https://guardian-esg-copilot.onrender.com
- 
- **MOSS Probe (7ms Proof):** https://guardian-esg-copilot.onrender.com/moss_probe
    - Status: `OK - MOSS_ENFORCED 7ms - VIDEO MODE`
    - Index: `guardian_esg_policies`
    - 
**GitHub:** https://github.com/Sraveena1992/guardian-esg-copilot  

### Live Decision Screenshots (MOSS-ENFORCED - 7ms)

**ALLOW - 0.05 - Safe Execution**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/ALLOW.jpeg" width="100%">

**REVIEW - 0.65 - Human Approval Needed**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/REVIEW.jpeg" width="100%">

**BLOCK - 0.99 - Malicious Blocked**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/BLOCK.jpeg" width="100%">

## What is GUARDIAN?

**The Problem:** AI Agents can now transfer money, delete data, publish content. One wrong tool-call = company loss. Who stops them?

**The Solution:** GUARDIAN is a Policy-First Security Gateway that sits between Agent and Action.

Unlike basic guardrails that just guess, GUARDIAN **RETRIEVES live policy from MOSS**, calculates deterministic risk, and gives provable decision.

> **MOSS is the Brain, GUARDIAN is the Gate.**


## Current Architecture

```
User / Agent Request
        ↓
FastAPI + Pydantic Validation + Rate Limiting
        ↓
MOSS Policy Retrieval (Live - Critical Path)
        ↓
Deterministic Risk Engine (0.0 - 1.0)
        ↓
ALLOW / REVIEW / BLOCK
        ↓
Controlled Tool Execution Gate
        ↓
Audit Record (SHA-256) + LiveKit Event
```


### Demonstrated outcomes
- **0.05 → ALLOW** — Weather API mock executes - 7ms MOSS retrieval
- **0.65 → REVIEW** — PENDING_HUMAN_APPROVAL - No execution
- **0.99 → BLOCK** — Malicious - No execution
- **MOSS failure → FAIL_CLOSED → BLOCK**

## Why This is Best Use Case of MOSS?

GUARDIAN is 100% MOSS-native. Policies are NOT hardcoded. Every request retrieves `allow.yaml / review.yaml / block.yaml` from MOSS Index `guardian_esg_policies` via `moss_tools.py` at runtime. No MOSS = No Decision = FAIL_CLOSED. MOSS is not an add-on, it IS the policy brain.

MOSS SDK: Official Python `moss` SDK. Env: `MOSS_PROJECT_ID`, `MOSS_PROJECT_KEY`, `MOSS_INDEX_NAME`. Latency shown is MOSS retrieval latency only.

## Security Controls
- Pydantic validation: 1-2000 chars
- Restricted CORS + Rate Limiting (Redis / in-process fallback)
- Fail-closed on MOSS failure
- Audit ID + SHA-256 hash
- Review/Block prevents execution

## Auditability
Each decision → `audit.jsonl` with Audit ID, timestamp, decision, risk, MOSS latency, execution status, reason, SHA-256 hash.

## LiveKit
Browser demo publishes `guardian-decision` event with decision, risk score, audit ID, timestamp - Real-time governance event.

## Engineering Verification
Tests: validation, ALLOW, REVIEW, BLOCK, fail-closed, audit hash, rate limit, compatibility route, latency semantics. GitHub Actions + Docker + pinned requirements.

## Setup
pip install -r requirements.txt
MOSS_PROJECT_ID, MOSS_PROJECT_KEY, MOSS_INDEX_NAME=guardian_esg_policies
python -m scripts.setup_moss
uvicorn app:app --host 0.0.0.0 --port 8000
