# Why GUARDIAN is Best Use Case of MOSS

**MOSS is NOT a database for us. MOSS IS the decision-maker.**

Other projects: Call LLM -> Then check MOSS as extra info.
GUARDIAN: Call MOSS FIRST -> MOSS policy decides ALLOW/BLOCK.

### How GUARDIAN Uses MOSS (100% Native)

1. Every user request -> `moss_tools.py` -> MOSS Index `guardian_esg_policies` query
2. Retrieves live yaml: allow.yaml, review.yaml, block.yaml at RUNTIME
3. Risk engine uses ONLY MOSS policy to score 0.0-1.0
4. If MOSS down -> FAIL_CLOSED -> BLOCK (Security first)
5. Latency: 7ms MOSS retrieval (measured & logged, not fake benchmark)

### Why This is Different?

Without MOSS, GUARDIAN cannot function. MOSS is not an add-on, it IS the policy brain.
We use Official Python `moss` SDK with server-side env creds: MOSS_PROJECT_ID, MOSS_PROJECT_KEY, MOSS_INDEX_NAME.

This is true Policy-First, MOSS-Native Security Gateway.
