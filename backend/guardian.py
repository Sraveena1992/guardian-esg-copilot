"""
GUARDIAN — Real-Time AI Agent Security & Reliability Gateway
YC Fall 2026 × MOSS — Zero Latency Builder Sprint

Security Design: FAIL-CLOSED
If Moss policy engine is unavailable -> NEVER ALLOW silently -> REVIEW/BLOCK
"""

import os
import time
import asyncio
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List
from moss import MossClient, DocumentInfo, QueryOptions

MOSS_PROJECT_ID = os.getenv("MOSS_PROJECT_ID", "")
MOSS_PROJECT_KEY = os.getenv("MOSS_PROJECT_KEY", "")
INDEX_NAME = os.getenv("MOSS_INDEX_NAME", "guardian-security-policies")
TOP_K = 3
RELEVANCE_THRESHOLD = 0.35

# 5 Core Security Policies
SECURITY_POLICIES = [
    DocumentInfo(id="POL-001", text="Block PII exfiltration to external APIs. Requests that send customer emails, SSN, personal data, financial PII, or sensitive customer information to an external endpoint must be blocked.", metadata={"risk": "high", "action": "BLOCK", "category": "data_exfiltration"}),
    DocumentInfo(id="POL-002", text="Block prompt injection and jailbreak attempts. Requests attempting to ignore previous instructions, disregard system instructions, reveal system prompts, bypass safeguards, or override security controls must be blocked.", metadata={"risk": "critical", "action": "BLOCK", "category": "prompt_injection"}),
    DocumentInfo(id="POL-003", text="Require human review for financial transactions above $1000. Payments, transfers, purchases, refunds, or other financial actions above this threshold require manual approval.", metadata={"risk": "medium", "action": "REVIEW", "category": "financial_action"}),
    DocumentInfo(id="POL-004", text="Block secrets and credential leakage. API keys, passwords, authentication tokens, private keys, credentials, or other secrets must not be exposed to logs, external tools, or unauthorized destinations.", metadata={"risk": "high", "action": "BLOCK", "category": "secret_leakage"}),
    DocumentInfo(id="POL-005", text="Require review for potentially misleading sustainability or ESG claims. Unverified emissions data, unsupported carbon-offset claims, manipulated environmental metrics, or false sustainability statements require human review.", metadata={"risk": "medium", "action": "REVIEW", "category": "esg_reliability"}),
]

class GuardianMossClient:
    def __init__(self) -> None:
        self.client = MossClient(MOSS_PROJECT_ID, MOSS_PROJECT_KEY) if MOSS_PROJECT_ID and MOSS_PROJECT_KEY else None
        self.index_loaded = False

    async def initialize(self) -> None:
        if self.index_loaded or not self.client:
            return
        try:
            await self.client.create_index(INDEX_NAME, SECURITY_POLICIES)
        except Exception:
            pass
        try:
            await self.client.load_index(INDEX_NAME)
            self.index_loaded = True
        except Exception as e:
            raise RuntimeError(f"MOSS_INDEX_LOAD_FAILED: {e}")

    async def search(self, query: str, top_k: int = TOP_K) -> Dict[str, Any]:
        # FAIL-CLOSED: If client not configured, raise
        if not self.client:
            raise RuntimeError("MOSS_CLIENT_UNAVAILABLE")
        
        await self.initialize()
        
        if not self.index_loaded:
            raise RuntimeError("MOSS_INDEX_NOT_READY")

        result = await self.client.query(INDEX_NAME, query, QueryOptions(top_k=top_k))
        policies = [
            {
                "id": d.id,
                "text": d.text,
                "score": float(d.score),
                "risk": (d.metadata or {}).get("risk", "low"),
                "action": (d.metadata or {}).get("action", "ALLOW"),
                "category": (d.metadata or {}).get("category", "unknown")
            }
            for d in result.docs
        ]
        return {"policies": policies, "moss_latency_ms": float(result.time_taken_ms), "query": query}

def calculate_risk(policies: List[Dict[str, Any]], request: str) -> float:
    if not policies:
        return 0.0
    relevant = [p for p in policies if float(p.get("score", 0.0)) >= RELEVANCE_THRESHOLD]
    if not relevant:
        return 0.0
    risk_score = 0.0
    for policy in relevant:
        base = 0.90 if policy.get("risk") == "critical" else 0.70 if policy.get("risk") == "high" else 0.40 if policy.get("risk") == "medium" else 0.10
        relevance = max(0.0, min(float(policy.get("score", 0.0)), 1.0))
        candidate = base * (0.5 + 0.5 * relevance)
        if policy.get("action") == "BLOCK":
            candidate = max(candidate, 0.75 if policy.get("risk") == "critical" else 0.70)
        elif policy.get("action") == "REVIEW":
            candidate = max(candidate, 0.35)
        risk_score = max(risk_score, candidate)
    return round(min(risk_score, 1.0), 4)

def decide(risk_score: float) -> str:
    if risk_score >= 0.70:
        return "BLOCK"
    if risk_score >= 0.35:
        return "REVIEW"
    return "ALLOW"

def create_audit_id(agent_request: str, tool_name: str) -> str:
    raw = f"{agent_request}|{tool_name}|{datetime.now(timezone.utc).isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

moss_guardian = GuardianMossClient()

async def guardian_check_async(agent_request: str, tool_name: str = "unknown") -> Dict[str, Any]:
    if not agent_request or not agent_request.strip():
        raise ValueError("agent_request must not be empty.")
    
    start = time.perf_counter()
    
    try:
        moss_result = await moss_guardian.search(agent_request, top_k=TOP_K)
        retrieved = moss_result["policies"]
        moss_latency = moss_result["moss_latency_ms"]
    except RuntimeError as e:
        # ========== FAIL-CLOSED LOGIC ==========
        total_latency = (time.perf_counter() - start) * 1000
        audit_id = create_audit_id(agent_request, tool_name)
        error_type = str(e)
        
        # NEVER ALLOW when security engine is down
        return {
            "audit_id": audit_id,
            "decision": "REVIEW",  # Fail closed to REVIEW, not ALLOW
            "risk_score": 0.99,
            "tool": tool_name,
            "moss_latency_ms": 0.0,
            "total_latency_ms": round(total_latency, 2),
            "policies_matched": [],
            "matched_rules": [],
            "reason": f"SECURITY ERROR: Policy engine unavailable ({error_type}). Request routed to human review per fail-closed design. Never silently allowed.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "explainable": True,
            "retrieval": "fail-closed",
            "execution": "BLOCKED_PENDING_HUMAN_REVIEW",
            "security_mode": "FAIL_CLOSED"
        }

    relevant = [p for p in retrieved if float(p.get("score", 0.0)) >= RELEVANCE_THRESHOLD]
    risk_score = calculate_risk(relevant, agent_request)
    decision = decide(risk_score)
    total_latency = (time.perf_counter() - start) * 1000
    audit_id = create_audit_id(agent_request, tool_name)

    matched_rules = [
        {"id": p["id"], "category": p["category"], "risk": p["risk"], "action": p["action"], "score": round(p["score"], 4), "rule": p["text"][:200]}
        for p in relevant
    ]
    reason = f"{decision} because {len(relevant)} relevant security policy/policies matched with score >= {RELEVANCE_THRESHOLD}." if relevant else f"No security policy exceeded relevance threshold {RELEVANCE_THRESHOLD}; request treated as low risk."

    execution_status = "PREVENTED" if decision == "BLOCK" else "BLOCKED_PENDING_HUMAN_REVIEW" if decision == "REVIEW" else "ALLOWED"

    return {
        "audit_id": audit_id,
        "decision": decision,
        "risk_score": round(risk_score, 2),
        "tool": tool_name,
        "moss_latency_ms": round(moss_latency, 2),
        "total_latency_ms": round(total_latency, 2),
        "policies_matched": [p["id"] for p in relevant],
        "matched_rules": matched_rules,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "explainable": True,
        "retrieval": "moss-semantic",
        "execution": execution_status,
        "security_mode": "FAIL_CLOSED_ACTIVE"
    }

def guardian_check(agent_request: str, tool_name: str = "unknown") -> Dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(guardian_check_async(agent_request, tool_name))
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, guardian_check_async(agent_request, tool_name))
        return future.result()
