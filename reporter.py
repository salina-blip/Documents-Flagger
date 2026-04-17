import json
from datetime import datetime
from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from scanner import ScanResult, RiskRating

colorama_init(autoreset=True)

RISK_COLORS = {
    "Safe": Fore.GREEN,
    "Low": Fore.YELLOW,
    "Medium": Fore.MAGENTA,
    "High": Fore.RED,
}

SEVERITY_COLORS = {
    "High": Fore.RED,
    "Medium": Fore.MAGENTA,
    "Low": Fore.YELLOW,
}


def _risk_colored(risk: RiskRating) -> str:
    color = RISK_COLORS.get(risk, "")
    return f"{color}{Style.BRIGHT}{risk}{Style.RESET_ALL}"


def print_document_report(result: ScanResult, index: int, total: int) -> None:
    print()
    print(f"{Style.BRIGHT}{'='*70}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}[{index}/{total}] {result.file_name}{Style.RESET_ALL}")
    print(f"{'='*70}")

    if result.extraction_error:
        print(f"{Fore.RED}  !! Could not extract text from this document.{Style.RESET_ALL}")
        print(f"  Overall Risk : {_risk_colored(result.overall_risk)}")
        print(f"  Recommendation: {Fore.RED}{result.recommendation}{Style.RESET_ALL}")
        return

    # --- Tenant matches ---
    if result.tenant_matches:
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}TENANT NAME FLAGS ({len(result.tenant_matches)} tenant(s) found){Style.RESET_ALL}")
        for tm in result.tenant_matches:
            print(f"\n    Tenant  : {Style.BRIGHT}{tm.tenant_name}{Style.RESET_ALL}")
            print(f"    Count   : {tm.occurrences} occurrence(s)")
            for i, excerpt in enumerate(tm.excerpts, 1):
                print(f"    Excerpt {i}: \"{excerpt}\"")
    else:
        print(f"\n  {Fore.GREEN}  No tenant names detected.{Style.RESET_ALL}")

    # --- Security findings ---
    if result.security_findings:
        print(f"\n  {Fore.RED}{Style.BRIGHT}SECURITY FINDINGS ({len(result.security_findings)} issue(s)){Style.RESET_ALL}")
        rows = []
        for f in result.security_findings:
            sev_colored = f"{SEVERITY_COLORS.get(f.severity, '')}{f.severity}{Style.RESET_ALL}"
            rows.append([sev_colored, f.category, f.description, f.excerpt[:80]])
        headers = ["Severity", "Category", "Type", "Excerpt"]
        print(tabulate(rows, headers=headers, tablefmt="simple", maxcolwidths=[10, 35, 30, 80]))
    else:
        print(f"\n  {Fore.GREEN}  No security issues detected.{Style.RESET_ALL}")

    # --- Summary ---
    print(f"\n  Overall Risk  : {_risk_colored(result.overall_risk)}")
    rec_color = Fore.RED if "Hold" in result.recommendation else Fore.GREEN
    print(f"  Recommendation: {rec_color}{result.recommendation}{Style.RESET_ALL}")


def print_summary(results: list[ScanResult], folder_path: str, duration_seconds: float) -> None:
    print()
    print(f"{Style.BRIGHT}{'#'*70}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}  SCAN SUMMARY — {folder_path}{Style.RESET_ALL}")
    print(f"  Scanned    : {len(results)} document(s)")
    print(f"  Duration   : {duration_seconds:.1f}s")
    print(f"  Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*70}")

    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}
    flagged_tenants: dict[str, list[str]] = {}

    for r in results:
        risk_counts[r.overall_risk] = risk_counts.get(r.overall_risk, 0) + 1
        for tm in r.tenant_matches:
            flagged_tenants.setdefault(tm.tenant_name, []).append(r.file_name)

    print(f"\n  Risk Breakdown:")
    for risk, count in [("High", risk_counts["High"]), ("Medium", risk_counts["Medium"]),
                         ("Low", risk_counts["Low"]), ("Safe", risk_counts["Safe"])]:
        bar = "█" * count
        print(f"    {_risk_colored(risk):>8}  {bar} ({count})")

    if flagged_tenants:
        print(f"\n  Tenant Names Flagged Across All Documents:")
        rows = [[name, len(files), ", ".join(files[:3]) + (" …" if len(files) > 3 else "")]
                for name, files in sorted(flagged_tenants.items())]
        print(tabulate(rows, headers=["Tenant", "Docs", "Files"], tablefmt="simple"))

    hold_docs = [r.file_name for r in results if "Hold" in r.recommendation]
    if hold_docs:
        print(f"\n  {Fore.RED}{Style.BRIGHT}Documents requiring redaction before human review:{Style.RESET_ALL}")
        for name in hold_docs:
            print(f"    {Fore.RED}• {name}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}All documents cleared for human review.{Style.RESET_ALL}")

    print(f"\n{'#'*70}\n")


def save_json_report(results: list[ScanResult], output_path: str, raw: list[dict] = None) -> None:
    if raw is not None:
        # Called from web app with pre-serialised dicts
        documents = raw
    else:
        documents = [
            {
                "file_name": r.file_name,
                "overall_risk": r.overall_risk,
                "recommendation": r.recommendation,
                "extraction_error": r.extraction_error,
                "tenant_matches": [
                    {"tenant_name": tm.tenant_name, "occurrences": tm.occurrences, "excerpts": tm.excerpts}
                    for tm in r.tenant_matches
                ],
                "security_findings": [
                    {"category": f.category, "description": f.description, "excerpt": f.excerpt, "severity": f.severity}
                    for f in r.security_findings
                ],
            }
            for r in results
        ]
    data = {"generated_at": datetime.now().isoformat(), "documents": documents}
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"  JSON report saved → {output_path}")
