import re
from dataclasses import dataclass, field
from typing import Literal

from config import TENANT_NAMES, SECURITY_PATTERNS

Severity = Literal["High", "Medium", "Low"]
RiskRating = Literal["Safe", "Low", "Medium", "High"]

# Scan in 400 KB chunks with 5 KB overlap so matches near boundaries aren't missed
_CHUNK_SIZE = 400_000
_OVERLAP = 5_000


@dataclass
class TenantMatch:
    tenant_name: str
    occurrences: int
    excerpts: list[str]


@dataclass
class SecurityFinding:
    category: str
    description: str
    excerpt: str
    severity: Severity


@dataclass
class ScanResult:
    file_name: str
    tenant_matches: list[TenantMatch] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    overall_risk: RiskRating = "Safe"
    recommendation: str = ""
    extraction_error: bool = False


def _redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    keep = max(2, len(value) // 4)
    return value[:keep] + "****" + value[-keep:]


def _get_excerpt(text: str, start: int, end: int, context: int = 80) -> str:
    s = max(0, start - context)
    e = min(len(text), end + context)
    snippet = text[s:e].replace("\n", " ").strip()
    if s > 0:
        snippet = "…" + snippet
    if e < len(text):
        snippet += "…"
    return snippet


def _chunks(text: str):
    """Yield overlapping chunks of text for scanning large documents."""
    if len(text) <= _CHUNK_SIZE:
        yield text
        return
    start = 0
    while start < len(text):
        end = min(start + _CHUNK_SIZE, len(text))
        yield text[start:end]
        if end == len(text):
            break
        start = end - _OVERLAP


def scan_tenants(text: str) -> list[TenantMatch]:
    # Aggregate counts across all chunks, deduplicate excerpts
    agg: dict[str, dict] = {}
    for chunk in _chunks(text):
        for tenant in TENANT_NAMES:
            pattern = re.compile(re.escape(tenant), re.IGNORECASE)
            found = list(pattern.finditer(chunk))
            if not found:
                continue
            entry = agg.setdefault(tenant, {"occurrences": 0, "excerpts": []})
            entry["occurrences"] += len(found)
            for m in found[:2]:
                excerpt = _get_excerpt(chunk, m.start(), m.end())
                if excerpt not in entry["excerpts"]:
                    entry["excerpts"].append(excerpt)

    return [
        TenantMatch(tenant_name=name, occurrences=d["occurrences"], excerpts=d["excerpts"][:3])
        for name, d in agg.items()
    ]


def scan_security(text: str) -> list[SecurityFinding]:
    seen_keys: set[str] = set()
    findings: list[SecurityFinding] = []

    for chunk in _chunks(text):
        for category, meta in SECURITY_PATTERNS.items():
            severity: Severity = meta["severity"]
            for pattern, label in meta["patterns"]:
                for match in pattern.finditer(chunk):
                    full_match = match.group(0)
                    # Deduplicate by (category, label, first-40-chars-of-match)
                    dedup_key = f"{category}|{label}|{full_match[:40]}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    if match.lastindex and match.lastindex >= 1:
                        secret_val = match.group(match.lastindex)
                        redacted_match = full_match.replace(secret_val, _redact_secret(secret_val))
                    else:
                        redacted_match = full_match

                    findings.append(SecurityFinding(
                        category=_category_label(category),
                        description=label,
                        excerpt=redacted_match[:200],
                        severity=severity,
                    ))

    return findings


def _category_label(key: str) -> str:
    return {
        "api_keys_tokens": "API Keys / Access Tokens",
        "internal_pricing": "Internal Pricing Information",
        "customer_pii": "Customer Names / Contract Details / PII",
        "competitor_intel": "Competitor-Sensitive Data",
    }.get(key, key)


def compute_risk_rating(findings: list[SecurityFinding]) -> RiskRating:
    if not findings:
        return "Safe"
    severities = {f.severity for f in findings}
    if "High" in severities:
        return "High"
    if "Medium" in severities:
        return "Medium"
    return "Low"


def build_recommendation(risk: RiskRating, findings: list[SecurityFinding], matches: list[TenantMatch]) -> str:
    if risk == "Safe" and not matches:
        return "Clear for human review."
    if risk in ("High", "Medium"):
        reasons = list({f.category for f in findings})
        return f"Hold for redaction — {', '.join(reasons)}."
    if matches:
        names = ", ".join(m.tenant_name for m in matches[:3])
        suffix = f" (+{len(matches)-3} more)" if len(matches) > 3 else ""
        return f"Hold for redaction — tenant names found: {names}{suffix}."
    return "Clear for human review."


def scan_document(file_name: str, text: str) -> ScanResult:
    if text.startswith("[EXTRACTION ERROR"):
        result = ScanResult(file_name=file_name, extraction_error=True)
        result.overall_risk = "High"
        result.recommendation = "Hold for redaction — document could not be extracted for scanning."
        return result

    tenant_matches = scan_tenants(text)
    security_findings = scan_security(text)
    risk = compute_risk_rating(security_findings)
    if tenant_matches and risk == "Safe":
        risk = "Low"
    recommendation = build_recommendation(risk, security_findings, tenant_matches)

    return ScanResult(
        file_name=file_name,
        tenant_matches=tenant_matches,
        security_findings=security_findings,
        overall_risk=risk,
        recommendation=recommendation,
    )
