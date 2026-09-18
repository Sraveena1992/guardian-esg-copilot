import os


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return value


RATE_LIMIT = _positive_int("GUARDIAN_RATE_LIMIT", 30)
RATE_WINDOW = _positive_int("GUARDIAN_RATE_WINDOW_SECONDS", 60)
AUDIT_FILE = os.getenv("GUARDIAN_AUDIT_FILE", "audit.jsonl").strip() or "audit.jsonl"
REDIS_URL = os.getenv("REDIS_URL", "").strip()
