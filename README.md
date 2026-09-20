# GUARDIAN — ESG Policy Enforcement Gateway

## 🎥 Final Submission — Live Demo & Verification

### Final Demo
https://www.loom.com/share/8c5fc882055d439b8d7d5c777e3e90d4

**GitHub:** https://github.com/Sraveena1992/guardian-esg-copilot  
**Live Demo:** https://guardian-esg-copilot.onrender.com

### Live Decision Screenshots

**ALLOW - 0.05**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/ALLOW.jpeg" width="100%">

**REVIEW - 0.65**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/REVIEW.jpeg" width="100%">

**BLOCK - 0.99**
<img src="https://raw.githubusercontent.com/Sraveena1992/guardian-esg-copilot/main/BLOCK.jpeg" width="100%">

## What is GUARDIAN?

GUARDIAN is a policy-first security gateway for AI-agent actions. It retrieves policy context through the MOSS runtime, applies deterministic risk decisioning, blocks or pauses protected execution, and records a request-level audit event.

## Current Architecture

```
User / Agent Request
        ↓
FastAPI Request Entry Point
        ↓
Pydantic Validation + CORS + Rate Limiting
        ↓
MOSS Policy Retrieval
        ↓
Deterministic Risk / Decision Logic
        ↓
ALLOW / REVIEW / BLOCK
        ↓
Controlled Tool Execution Gate
        ↓
Runtime Audit Record
        ↓
LiveKit decision-event publishing (demo client)
```

### Demonstrated outcomes

- **0.05 → ALLOW** — controlled local Weather API mock executes.
- **0.65 → REVIEW** — execution is disabled and returns `PENDING_HUMAN_APPROVAL`.
- **0.99 → BLOCK** — execution is disabled.
- **MOSS failure → FAIL_CLOSED → BLOCK** — execution is disabled.

## MOSS Integration

The repository uses the official Python `moss` SDK and reads credentials server-side from environment variables:

- `MOSS_PROJECT_ID`
- `MOSS_PROJECT_KEY`
- `MOSS_INDEX_NAME` (default: `guardian_esg_policies`)

MOSS policy retrieval is part of the request critical path. The application records the runtime query latency returned by MOSS. **This is retrieval latency only; it is not an end-to-end application latency benchmark.** MOSS credentials or a working policy index must be configured for `MOSS_ENFORCED` mode. When `MOSS_DEMO_FALLBACK=true` is explicitly enabled for a local demo, the output is labeled `DEMO_FALLBACK` and must not be presented as live MOSS.

## Security Controls

- Pydantic query validation: 1–2000 characters.
- Restricted CORS for the live origin.
- Configurable rate limiting with optional Redis backend and bounded in-process fallback.
- Fail-closed when MOSS policy retrieval is unavailable.
- Request-level Audit ID and SHA-256 event hash.
- Review and block paths prevent controlled tool execution.

## Auditability

Each decision produces a runtime `audit.jsonl` record containing Audit ID, timestamp, decision, risk score, MOSS mode/latency, execution status, reason, and SHA-256 hash.

The hash provides integrity evidence for the recorded event; the runtime file is not claimed to be immutable or durable external storage.

## LiveKit

The browser demo client connects to the configured LiveKit development token server and publishes a `guardian-decision` data event containing the Guardian decision, risk score, audit ID, and timestamp.

This demonstrates real-time decision-event publishing. It does not claim a production governance dashboard or a full human-approval workflow.

## Engineering Verification

The repository includes automated tests for request validation, ALLOW execution, REVIEW blocking, BLOCK blocking, MOSS fail-closed behavior, audit hashing, rate limiting, the compatibility API route, and explicit latency semantics.

GitHub Actions runs the test suite on pushes and pull requests. Dependencies are pinned in `requirements.txt`. Docker and Docker Compose files provide reproducible local execution.

## Setup

Install:

```bash
pip install -r requirements.txt
```

Set server-side MOSS configuration:

```env
MOSS_PROJECT_ID=your_project_id
MOSS_PROJECT_KEY=your_project_key
MOSS_INDEX_NAME=guardian_esg_policies
MOSS_DEMO_FALLBACK=false
```

Create or refresh the policy index:

```bash
python -m scripts.setup_moss
```

Run:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Never commit real credentials or secrets to GitHub.
