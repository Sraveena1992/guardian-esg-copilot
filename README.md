# GUARDIAN — ESG Copilot | Zero-Trust Security Gateway

**Live Demo:** https://guardian-esg-copilot.onrender.com

**Live Proof:** 7ms MOSS Retrieval — CONNECTED | MOSS_ENFORCED: true | AUDIT: f09b9e1a35c68f32

**Status:** Live Verified — 7ms MOSS Retrieval Observed

### What is GUARDIAN?

GUARDIAN is a zero-trust security gateway for AI agents. Before a protected tool executes, GUARDIAN retrieves relevant security policy, evaluates risk, and deterministically returns ALLOW / REVIEW / BLOCK.

### Architecture

User
↓
Guardian ESG Copilot
↓
MOSS Semantic Retrieval — 7ms live observed
↓
Security / Risk Evaluation
↓
Deterministic Decision Engine
├── ALLOW → Zero-Trust Tool Gateway
│   ├── Weather API
│   ├── SEC Filing API
│   └── Secret Scan
├── REVIEW → Human Approval
└── BLOCK → Execution Denied
↓
Audit & Observability

### Core Features

1. **7ms MOSS Retrieval**
   - Live observed Moss retrieval result.
   - MOSS status: CONNECTED.
   - MOSS_ENFORCED: true.
   - 7ms is reported as an observed live retrieval result, not as a p50/p95/p99 benchmark.

2. **Zero-Trust Tool Action Gateway**
   - Protected tools cannot execute without an authorization decision.
   - Weather API → environmental/weather data
   - SEC Filing API → regulatory filing retrieval
   - Secret Scan → credential and secret detection

3. **Risk-Based Decision Engine**
   - Risk 0.05 → ALLOW
   - Risk 0.65 → REVIEW
   - Risk 0.99 → BLOCK
   - Low-confidence or unavailable-policy conditions must never silently grant protected tool access.

4. **Audit & Observability**
   - Every security decision creates an audit record.
   - Example audit ID: `f09b9e1a35c68f32``

5. **Evaluation & Observability**
   - Decision, risk, matched policy, tool, latency, and audit information are exposed for evaluation and review.

### Security Policy

- Protected tools are enforced through the Tool Action Gateway.
- REVIEW requires human approval.
- BLOCK prevents tool execution.
- Unavailable policy retrieval or insufficient confidence must not silently allow protected actions.

### Live Proof

- Live application: https://guardian-esg-copilot.onrender.com
- **MOSS Retrieval: 7ms — live observed**
- **MOSS_ENFORCED: true**
- **MOSS: CONNECTED**
- **Risk policy:** 0.05 → ALLOW | 0.65 → REVIEW | 0.99 → BLOCK
- **Audit:** `f09b9e1a35c68f32`

### How to Run

```bash
npm install
npm run dev
