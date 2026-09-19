# GUARDIAN — Current Architecture

This document describes the repository as implemented on `main`. It is intentionally evidence-aligned.

## Request path

User / Agent Request
→ FastAPI Request Entry Point
→ Pydantic Validation + CORS + Rate Limiting
→ MOSS Policy Retrieval
→ Deterministic Risk / Decision Logic
→ Execution Decision
→ Runtime Audit Record
→ Optional LiveKit decision-event publishing by the demo client

## Enforcement states

- `0.05 → ALLOW`: controlled local Weather API mock may execute.
- `0.65 → REVIEW`: execution is disabled and status is `PENDING_HUMAN_APPROVAL`.
- `0.99 → BLOCK`: execution is disabled.
- MOSS retrieval failure: `FAIL_CLOSED` → `BLOCK` with `executed=false`.

## Current implementation boundaries

- MOSS is a real SDK dependency when `MOSS_PROJECT_ID`, `MOSS_PROJECT_KEY`, and `MOSS_INDEX_NAME` are configured.
- The observed MOSS runtime measurement comes from the SDK query result; application end-to-end latency is not claimed.
- `audit.jsonl` is runtime prototype storage, not a durable external compliance store.
- REVIEW is a deterministic safety state; a production approval queue is not implemented.
- The Weather API is a controlled mock used to demonstrate execution gating.
- LiveKit is used by the browser demo client to publish a `guardian-decision` event; the repo does not claim a production governance dashboard.

## Security controls

- Pydantic query length: 1–2000 characters.
- Restricted CORS for the deployed origin.
- Configurable rate limiting with an optional Redis backend and bounded in-process fallback.
- Fail-closed behavior for unavailable MOSS policy retrieval.
- Request-level Audit ID and SHA-256 event hash.
