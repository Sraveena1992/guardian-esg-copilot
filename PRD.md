# GUARDIAN PRD - Policy-First Gateway

**Goal:** Stop risky AI agent actions before execution.

**Problem:** AI Agents can transfer money, delete data, publish content. One wrong tool-call = company loss.

**User:** Any company using AI agents for tool calls.

**Core Features:**
- P1: Deterministic Risk Scoring (0.0-1.0) - No LLM hallucination, only MOSS policy
- P1: MOSS Policy Retrieval in critical path (7ms) via moss_tools.py
- P1: FAIL_CLOSED - If MOSS fails, BLOCK everything
- P2: SHA-256 Audit Trail - audit.jsonl with Audit ID, timestamp, decision, hash
- P2: Security - Pydantic validation (1-2000 chars), Rate Limiting (Redis fallback), Restricted CORS
- P3: LiveKit Real-time - Publishes guardian-decision event

**Architecture Decisions:**
- FastAPI for speed + Pydantic for validation
- MOSS as Brain, not cache - Live retrieval every request
- Review/Block prevents execution - Only ALLOW executes mock tool

**Success Metric:** Block 99% malicious (0.99), Allow 100% safe (0.05) in <10ms MOSS retrieval.

**Demo Flow:** 0.05 ALLOW -> Weather API executes | 0.65 REVIEW -> PENDING_HUMAN_APPROVAL | 0.99 BLOCK -> No execution
