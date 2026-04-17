import re
from dataclasses import dataclass, field
from typing import Literal

from config import TENANT_NAMES, SECURITY_PATTERNS, FEATURE_PRICING_EXCLUSION_RE

Severity = Literal["High", "Medium", "Low"]
RiskRating = Literal["Safe", "Low", "Medium", "High", "Error"]

_CHUNK_SIZE = 400_000
_OVERLAP = 5_000
# Context window (chars each side) used to check for feature-pricing phrases
_PRICING_CONTEXT_WINDOW = 150


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


def _is_feature_pricing_context(chunk: str, match_start: int, match_end: int) -> bool:
    """True if the match sits within a feature-documentation pricing phrase context."""
    ctx_start = max(0, match_start - _PRICING_CONTEXT_WINDOW)
    ctx_end = min(len(chunk), match_end + _PRICING_CONTEXT_WINDOW)
    context = chunk[ctx_start:ctx_end]
    return bool(FEATURE_PRICING_EXCLUSION_RE.search(context))


def scan_tenants(text: str) -> list[TenantMatch]:
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

                    # Suppress pricing findings that are feature-documentation context
                    if category == "internal_pricing" and _is_feature_pricing_context(chunk, match.start(), match.end()):
                        continue

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
    if risk == "Error":
        return "Could not be read — manual review required."
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
        return ScanResult(
            file_name=file_name,
            extraction_error=True,
            overall_risk="Error",
            recommendation="Could not be read — manual review required.",
        )

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
