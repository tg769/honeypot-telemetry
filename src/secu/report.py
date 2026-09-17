"""Generates a recurring markdown report: top attackers, credential
trends, new-since-last-run, enrichment highlights. Maps directly to the
JD's "generating recurring reports" line.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from secu import events, statefile
from secu.config import DATA_DIR

REPORTS_DIR = DATA_DIR / "reports"


def build_report() -> str:
    all_events = list(events.read_all())
    findings_data = statefile.load("findings", {"findings": [], "botnet_clusters": [], "mirai_provenance": {}})
    enrich_cache = statefile.load("enrich_cache", {})

    ip_counts = Counter(e.get("src_ip") for e in all_events if e.get("src_ip"))
    cred_counts = Counter(
        (e.get("username"), e.get("password"))
        for e in all_events
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success") and e.get("username")
    )
    findings_by_rule = Counter(f["rule_id"] for f in findings_data["findings"])

    lines = [
        f"# Honeypot report, generated {datetime.now(timezone.utc).isoformat()}",
        "",
        f"- Total events: {len(all_events)}",
        f"- Distinct source IPs: {len(ip_counts)}",
        f"- Botnet clusters identified (2+ IPs): "
        f"{sum(1 for c in findings_data.get('botnet_clusters', []) if c['size'] > 1)}",
        "",
        "## Findings by rule",
        "",
    ]
    for rule, count in findings_by_rule.most_common():
        lines.append(f"- `{rule}`: {count}")

    mirai = findings_data.get("mirai_provenance", {})
    if mirai:
        lines += [
            "",
            "## Mirai credential-list provenance",
            "",
            f"- {mirai.get('mirai_matches', 0)}/{mirai.get('total_attempts', 0)} attempts "
            f"({mirai.get('mirai_match_pct', 0)}%) matched Mirai's published hardcoded credential table.",
        ]

    lines += ["", "## Top 15 source IPs", ""]
    for ip, count in ip_counts.most_common(15):
        enrichment = enrich_cache.get(ip, {})
        tags = enrichment.get("internetdb", {}).get("tags", [])
        confidence = enrichment.get("abuseipdb", {}).get("abuseConfidenceScore")
        extra = f", tags: {tags}" if tags else ""
        extra += f", abuseConfidence: {confidence}" if confidence is not None else ""
        lines.append(f"- {ip}: {count} events{extra}")

    lines += ["", "## Top 15 credential pairs attempted", ""]
    for (user, pw), count in cred_counts.most_common(15):
        lines.append(f"- `{user}` / `{pw}`: {count}")

    lines += ["", "## Botnet clusters (2+ correlated IPs, by size)", ""]
    multi_ip_clusters = [c for c in findings_data.get("botnet_clusters", []) if c["size"] > 1]
    for cluster in sorted(multi_ip_clusters, key=lambda c: -c["size"])[:10]:
        lines.append(
            f"- cluster of {cluster['size']} IPs ({', '.join(cluster['member_ips'][:5])}"
            f"{'...' if cluster['size'] > 5 else ''}), "
            f"sample client version: `{cluster.get('sample_client_version') or 'unknown'}`"
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = build_report()
    out_path = REPORTS_DIR / f"report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.md"
    out_path.write_text(report)
    print(f"wrote {out_path}")
    print("this is scratch working data (gitignored). Hand-curate the real deliverable at "
          "docs/findings/weekend-report.md once the weekend is over")


if __name__ == "__main__":
    main()
