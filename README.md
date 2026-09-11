# GUARDIAN — Real-Time AI Agent Security & Reliability Gateway

> Security shouldn't slow an AI agent down.

GUARDIAN is a real-time security and reliability gateway for AI agents.

Before an agent executes a tool or sensitive action, GUARDIAN retrieves the relevant security policy using Moss, evaluates the request against risk and permission signals, and produces a deterministic decision:

ALLOW • REVIEW • BLOCK

Every decision is explainable and auditable.

## Core Flow

Agent Request
→ Moss Policy Retrieval
→ Security & Risk Evaluation
→ Decision Engine
→ ALLOW / REVIEW / BLOCK
→ Tool Execution

High-risk or low-confidence actions are routed to REVIEW instead of being executed automatically.

## Why Moss

Moss is used as the semantic retrieval layer for retrieving the most relevant policies and security rules in the real-time decision path.

The target is sub-10ms policy retrieval; benchmark results will be reported only after measurement.

## Reliability & Security

- Prompt-injection risk detection
- Sensitive-data risk detection
- Agent/tool permission checks
- Policy-based decisions
- Human review for uncertain actions
- Explainable decisions
- Tamper-aware audit trail
- Asynchronous evaluation and observability

## Status

Competition MVP under active development.

Performance figures are measured experimentally and will not be presented as verified until benchmarked.
