// GUARDIAN agent manifest — evidence-aligned
// This file documents the active project surface only.
// It intentionally contains no unverified latency, accuracy, cost, or
// third-party evaluation claims.

export const guardianAgent = {
  name: "GUARDIAN ESG Policy Enforcement Gateway",
  version: "1.0.0",
  entryPoint: "FastAPI",
  policyLayer: "MOSS",
  decisionStates: ["ALLOW", "REVIEW", "BLOCK"],
  safetyBoundary: "FAIL_CLOSED on MOSS policy retrieval failure",
  executionDemo: "controlled Weather API mock",
  audit: "request-level Audit ID + timestamp + SHA-256",
  realtimeChannel: "LiveKit guardian-decision",
  notes: {
    latency: "Report only runtime MOSS query measurements; never claim end-to-end latency.",
    review: "REVIEW halts execution; production human-approval workflow is not implemented.",
    storage: "audit.jsonl is runtime prototype storage; durable external retention is future work."
  }
};
