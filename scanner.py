import re
from dataclasses import dataclass, field
from typing import Literal

from config import TENANT_NAMES, SECURITY_PATTERNS

Severity = Literal["High", "Medium", "Low"]
RiskRating = Literal["Safe", "Low", "Medium", "High"]


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


def _get_excerpt(text: str, match_start: int, match_end: int, context: int = 80) -> str:
    start = max(0, match_start - context)
    end = min(len(text), match_end + context)
    snippet = text[start:end].replace("\n", " ").strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet


def scan_tenants(text: str) -> list[TenantMatch]:
    matches = []
    for tenant in TENANT_NAMES:
        # Escape special regex chars in the tenant name, then do case-insensitive word-boundary search
        pattern = re.compile(re.escape(tenant), re.IGNORECASE)
        found = list(pattern.finditer(text))
        if found:
            excerpts = [_get_excerpt(text, m.start(), m.end()) for m in found[:3]]
            matches.append(TenantMatch(
                tenant_name=tenant,
                occurrences=len(found),
                excerpts=excerpts,
            ))
    return matches


def scan_security(text: str) -> list[SecurityFinding]:
    findings = []
    for category, meta in SECURITY_PATTERNS.items():
        severity: Severity = meta["severity"]
        for pattern, label in meta["patterns"]:
            for match in pattern.finditer(text):
                full_match = match.group(0)
                # Redact the captured secret group if present
                if match.lastindex and match.lastindex >= 1:
                    secret_val = match.group(match.lastindex)
                    redacted_match = full_match.replace(secret_val, _redact_secret(secret_val))
                else:
                    redacted_match = full_match
                excerpt = _get_excerpt(text, match.start(), match.end())
                # Replace the raw secret in the excerpt too
                if match.lastindex and match.lastindex >= 1:
                    secret_val = match.group(match.lastindex)
                    excerpt = excerpt.replace(secret_val, _redact_secret(secret_val))
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


def compute_risk_rating(security_findings: list[SecurityFinding]) -> RiskRating:
    if not security_findings:
        return "Safe"
    severities = {f.severity for f in security_findings}
    if "High" in severities:
        return "High"
    if "Medium" in severities:
        return "Medium"
    return "Low"


def build_recommendation(
    risk: RiskRating,
    security_findings: list[SecurityFinding],
    tenant_matches: list[TenantMatch],
) -> str:
    if risk == "Safe" and not tenant_matches:
        return "Clear for human review."
    if risk in ("High", "Medium"):
        reasons = list({f.category for f in security_findings})
        return f"Hold for redaction — {', '.join(reasons)}."
    if tenant_matches:
        names = ", ".join(m.tenant_name for m in tenant_matches[:3])
        suffix = f" (+{len(tenant_matches)-3} more)" if len(tenant_matches) > 3 else ""
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
    # Elevate risk if tenant names present and risk was Safe
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
