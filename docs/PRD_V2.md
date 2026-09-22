# GUARDIAN — Pilot PRD (V2)

## 1. Product summary

GUARDIAN is a policy-first security gateway for AI-agent actions. It creates a controlled boundary between an agent's request and tool execution.

The product objective is not to make every AI response safe; it is to make **protected actions explicitly governed before execution**.

## 2. Problem

Agentic systems can trigger actions that affect money, data, external systems, or sensitive credentials. Traditional application validation is usually disconnected from the agent's action intent.

GUARDIAN addresses the gap with a request-time sequence:

`validate → retrieve policy → decide → enforce → audit → observe`

## 3. Users

### Primary user
Engineering, security, compliance, and platform teams integrating tool-using AI agents.

### Secondary user
Operators who need a clear explanation of why an action was allowed, held for review, or blocked.

## 4. User jobs

- Safely place an enforcement boundary around agent actions.
- Retrieve relevant policy context at request time.
- Produce deterministic, inspectable outcomes.
- Prevent protected execution on REVIEW/BLOCK.
- Trace a decision through an Audit ID and policy provenance.
- Observe decisions in real time without coupling the security decision to the realtime transport.

## 5. Product principles

1. **Policy before execution.**
2. **Fail closed on required-policy failure.**
3. **Deterministic enforcement at the gateway.**
4. **Least privilege at the tool boundary.**
5. **Every decision is explainable and auditable.**
6. **Observability never becomes the security authority.**
7. **Current capability and future capability are explicitly separated.**

## 6. Functional requirements

### FR-01 Request validation
Accept a structured request with a bounded query field.

Acceptance:
- empty request rejected;
- requests longer than 2000 characters rejected.

### FR-02 Policy retrieval
Use the official MOSS Python SDK with server-side credentials.

Acceptance:
- configured MOSS index can be loaded and queried;
- retrieved documents include policy identity and action metadata;
- retrieval latency is recorded when returned by the SDK.

### FR-03 Policy resolution
Resolve a selected policy document to:
- policy ID;
- policy category;
- default action;
- policy provenance.

### FR-04 Deterministic decisioning
Produce exactly one of:
- ALLOW;
- REVIEW;
- BLOCK.

Project mappings:
- 0.05 → ALLOW;
- 0.65 → REVIEW;
- 0.99 → BLOCK.

### FR-05 Defense in depth
Clearly dangerous patterns may force BLOCK even when retrieved policy context is less specific.

Acceptance:
- prompt-injection and secret-exfiltration patterns cannot be downgraded to ALLOW.

### FR-06 Execution control
- ALLOW may execute the controlled Weather API mock.
- REVIEW must not execute the tool.
- BLOCK must not execute the tool.

### FR-07 Fail closed
If a required policy operation fails, return BLOCK and `executed=false`.

Failure examples:
- credentials missing;
- index unavailable;
- empty policy result;
- malformed policy action metadata;
- query failure.

### FR-08 Audit event
Write a structured audit record containing at least:
- Audit ID;
- timestamp;
- request;
- decision;
- risk score;
- policy ID;
- MOSS mode;
- MOSS latency;
- execution status;
- reason;
- SHA-256 event hash.

### FR-09 Realtime observation
Publish a `guardian-decision` LiveKit data event when the browser demo is connected.

Realtime publishing must not decide ALLOW/REVIEW/BLOCK.

## 7. Non-functional requirements

### Performance
Report the MOSS retrieval latency returned by the runtime. Do not label this as end-to-end application latency unless measured separately.

### Reliability
Required policy failures fail closed.

### Security
- server-side credentials;
- bounded input;
- restricted CORS;
- rate limiting;
- explicit execution gate;
- no secret values in logs.

### Explainability
A decision should be traceable to a policy ID and deterministic action source.

### Operability
CI must execute the automated test suite for request validation, all decision states, failure behavior, audit integrity, and rate limiting.

## 8. MVP scope

Current demonstrated scope:
- FastAPI gateway;
- MOSS retrieval;
- deterministic decisions;
- controlled Weather API mock;
- runtime audit.jsonl;
- LiveKit demo event.

## 9. Pilot scope

Next implementation layer:
- authentication and authorization;
- durable audit storage;
- human approval queue;
- tool adapters and least-privilege scopes;
- idempotency;
- centralized metrics/tracing;
- policy versioning and rollout controls.

## 10. Explicit non-goals

The product should not claim:
- immutable ledger storage;
- production human-approval infrastructure;
- universal arbitrary-tool enforcement;
- production authentication unless implemented;
- end-to-end 7ms performance;
- a production governance dashboard unless implemented.

## 11. Acceptance test matrix

| Scenario | Expected action | Execution |
|---|---|---|
| Low-risk weather request | ALLOW / 0.05 | Controlled mock executes |
| Customer data to external API | REVIEW / 0.65 | Held |
| Ignore previous instructions / reveal prompt | BLOCK / 0.99 | Denied |
| Secret exfiltration | BLOCK / 0.99 | Denied |
| MOSS unavailable | FAIL_CLOSED / BLOCK | Denied |
| Invalid empty query | Validation error | No decision |
| Oversized query >2000 chars | Validation error | No decision |

## 12. Product success measures

For the pilot, measure:
- percentage of protected requests producing an explicit decision;
- percentage of REVIEW/BLOCK requests with zero tool execution;
- percentage of decisions with complete policy provenance;
- policy retrieval latency distribution;
- failure-to-BLOCK correctness;
- test coverage of critical decision paths.

These are measurement definitions, not current performance claims.

## 13. Demo narrative

`Agent request → FastAPI gateway → MOSS policy retrieval → deterministic enforcement → execution gate → audit → realtime observation`

The demo should make the security boundary visually obvious and should show one ALLOW, one REVIEW, one BLOCK, and one fail-closed case.
