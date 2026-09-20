# GUARDIAN PRD — Policy-First Gateway

**Goal:** Stop risky AI-agent actions before execution.

**Problem:** AI agents can trigger sensitive or high-risk actions such as financial transfers, data sharing, or instruction-bypass attempts. One unsafe tool call can create operational or compliance risk.

**User:** Companies integrating AI agents with tool-call workflows.

## Core Features

- **P1: Deterministic Risk Decisioning**
  - Guardian produces explicit `ALLOW`, `REVIEW`, or `BLOCK` outcomes.
  - The demonstrated mappings are `0.05 → ALLOW`, `0.65 → REVIEW`, and `0.99 → BLOCK`.

- **P1: MOSS Policy Retrieval**
  - MOSS policy retrieval runs in the request critical path.
  - Retrieved policy context is captured as evidence for the decision.
  - Runtime MOSS query latency is recorded when available.
  - Recorded latency refers to MOSS retrieval only, not end-to-end application latency.

- **P1: FAIL_CLOSED**
  - If MOSS policy retrieval is unavailable, Guardian returns `BLOCK`.
  - Tool execution remains disabled.

- **P2: SHA-256 Audit Trail**
  - Each decision generates an Audit ID, timestamp, decision, risk score, execution status, and SHA-256 event hash.
  - Runtime records are stored in `audit.jsonl`.

- **P2: API Security**
  - Pydantic request validation limits queries to 1–2000 characters.
  - Restricted CORS is configured for the live application origin.
  - Configurable rate limiting is supported with an in-memory fallback and optional Redis backend.

- **P3: LiveKit Real-Time Event**
  - The demo client publishes a `guardian-decision` event containing the Guardian decision, risk score, Audit ID, and timestamp.

## Architecture Decisions

- FastAPI is the request entry point.
- Pydantic provides request validation.
- MOSS provides policy context in the critical path.
- Deterministic Guardian logic produces the demonstrated `ALLOW / REVIEW / BLOCK` outcomes.
- REVIEW and BLOCK prevent controlled tool execution.
- Only the ALLOW path executes the controlled Weather API mock.
- MOSS retrieval failure follows a fail-closed path.

## Success Criteria

- Demonstrate deterministic `ALLOW`, `REVIEW`, and `BLOCK` paths.
- Demonstrate that REVIEW and BLOCK prevent tool execution.
- Demonstrate MOSS retrieval and `MOSS_ENFORCED` operation when configured.
- Demonstrate fail-closed behavior when MOSS is unavailable.
- Produce request-level audit records with SHA-256 integrity evidence.
- Demonstrate real-time `guardian-decision` event publishing.

## Demo Flow

`0.05 ALLOW → Weather API (controlled mock) executes`

`0.65 REVIEW → PENDING_HUMAN_APPROVAL → execution disabled`

`0.99 BLOCK → execution disabled`

`MOSS failure → FAIL_CLOSED → BLOCK`
