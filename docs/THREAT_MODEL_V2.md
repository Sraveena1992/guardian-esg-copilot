# GUARDIAN — Threat Model (V2)

## Security objective

Prevent an AI-agent action from crossing the tool boundary when the applicable policy requires REVIEW or BLOCK, and prevent any policy-unavailable state from silently becoming ALLOW.

## Trust boundaries

1. **Untrusted request boundary** — agent/user input enters FastAPI.
2. **Policy boundary** — MOSS returns policy context and metadata.
3. **Decision boundary** — deterministic Guardian logic converts policy + safety signals into ALLOW/REVIEW/BLOCK.
4. **Execution boundary** — only the execution gate may invoke a tool.
5. **Observation boundary** — audit and LiveKit record/report decisions but do not authorize execution.

## Threats and controls

| Threat | Control | Current evidence | Future hardening |
|---|---|---|---|
| Prompt injection | Explicit BLOCK policy + defense-in-depth safety override | Demonstrated BLOCK path | Broader policy corpus and adversarial evaluation |
| Secret exfiltration | Secret-pattern detection + BLOCK | Demonstrated BLOCK path and tests | Secret scanners and secret-aware tool policies |
| Sensitive data sent externally | REVIEW policy | Demonstrated REVIEW path | Human approval queue with identity and authorization |
| Tool bypass | Execution gate after decision | REVIEW/BLOCK do not execute controlled mock | Per-tool authorization and scoped credentials |
| MOSS outage | Fail-closed | MOSS failure returns BLOCK and executed=false | Health/readiness alerts and retry policy |
| Oversized input | Pydantic max length | 2000-character limit is tested | Request-body and infrastructure limits |
| Request flooding | Rate limiting | Configurable in-process limiter | Distributed limiter |
| Audit tampering | SHA-256 event hash | Hash is recorded per event | Durable append-only audit backend |
| Realtime spoofing | LiveKit isolated from decision authority | Event publish is downstream of decision | Signed/encrypted event pipeline and authorization |
| Policy drift | Policy files/index definition | Versionable policy documents in repository | Versioned promotion and rollback controls |
| Ambiguous policy | Deterministic supported action contract | Unsupported/missing action should fail closed | Formal policy schema and CI validation |

## Abuse cases

### Prompt injection
An attacker asks the agent to ignore prior instructions and reveal a system prompt. Guardian must produce BLOCK before execution.

### Secret exfiltration
A request attempts to send an API key or credential to an external destination. Guardian must block the protected action.

### Data exfiltration
A request attempts to send a customer database to an external API. Guardian should place the action in REVIEW and prevent execution until approval exists.

### Policy service failure
MOSS is unreachable, credentials are invalid, or the policy index cannot be loaded. Guardian must fail closed.

## Security invariants

- REVIEW never executes the protected tool.
- BLOCK never executes the protected tool.
- Required policy failure never produces ALLOW.
- Realtime publishing cannot change a decision.
- Audit output never contains project keys or other credentials.
