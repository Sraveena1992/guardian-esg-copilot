# GUARDIAN — ESG Policy Enforcement Gateway

GUARDIAN is a policy-first gateway for AI-agent actions. It validates requests, retrieves policy context through MOSS, applies deterministic enforcement, prevents protected execution when required, records an audit event, and can publish a real-time decision event to LiveKit.

## Live demo and repository

- Live app: https://guardian-esg-copilot.onrender.com
- GitHub: https://github.com/Sraveena1992/guardian-esg-copilot
- Demo video: https://www.loom.com/share/ebf6fce7eca947c3ab48951413ad09f1

## Current architecture

```
User / Agent Request
        ↓
FastAPI Request Entry Point
        ↓
Pydantic Validation + CORS + Rate Limiting
        ↓
MOSS Runtime Policy Retrieval
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

See [ARCHITECTURE.md](ARCHITECTURE.md) for the evidence-aligned current architecture and [docs/ARCHITECTURE_V2.md](docs/ARCHITECTURE_V2.md) for the pilot target architecture.

## Demonstrated decision paths

- 0.05 → ALLOW → controlled Weather API mock may execute.
- 0.65 → REVIEW → execution remains disabled and reports PENDING_HUMAN_APPROVAL.
- 0.99 → BLOCK → execution remains disabled.
- MOSS retrieval failure → FAIL_CLOSED → BLOCK with executed=false.

## MOSS integration

The backend uses the official Python `moss` SDK with server-side configuration:

- `MOSS_PROJECT_ID`
- `MOSS_PROJECT_KEY`
- `MOSS_INDEX_NAME`

MOSS is on the request critical path. When configured successfully, the application reports the runtime MOSS query latency returned by the SDK; this is retrieval latency, not an end-to-end application benchmark.

For local testing, `MOSS_DEMO_FALLBACK=true` is explicitly labeled `DEMO_FALLBACK` and is not a live-MOSS claim.

## Security controls

- Pydantic query validation: 1–2000 characters.
- Restricted CORS for the deployed origin.
- Configurable rate limiting with optional Redis backend and bounded in-process fallback.
- Fail-closed behavior when MOSS policy retrieval is unavailable.
- Request-level Audit ID, timestamp, and SHA-256 event hash.
- REVIEW and BLOCK states prevent controlled tool execution.

## LiveKit

The browser demo can publish a `guardian-decision` data event containing the decision, risk score, Audit ID, and timestamp.

This is a real-time event demonstration; it is not represented as a production governance dashboard.

## Engineering verification

The repository includes automated tests for validation, ALLOW/REVIEW/BLOCK paths, fail-closed behavior, audit hashing, rate limiting, compatibility routing, and latency semantics.

Dependencies are pinned in `requirements.txt`, and GitHub Actions runs the test suite.

## Documentation

- [Current architecture](ARCHITECTURE.md)
- [Pilot target architecture](docs/ARCHITECTURE_V2.md)
- [Pilot PRD](docs/PRD_V2.md)
- [Threat model](docs/THREAT_MODEL_V2.md)
- [Evidence matrix](docs/EVIDENCE_MATRIX.md)

## Configuration

```env
MOSS_PROJECT_ID=your_project_id
MOSS_PROJECT_KEY=your_project_key
MOSS_INDEX_NAME=guardian_esg_policies
MOSS_DEMO_FALLBACK=false
```

Never commit real credentials or secrets to GitHub.
