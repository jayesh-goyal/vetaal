"""Generates a Markdown pentest report from what Vetaal actually found and
did — hosts, services, audit log, and playbook attempts. Every line comes
from recorded data; nothing here is inferred or fabricated. This is the
actual deliverable of running a pentest: a written account someone can
read afterward, not just a live dashboard.
"""
import time
from typing import Any, Dict, List, Optional


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "unknown time"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def generate_report(db: Any, cve_db: Optional[Any] = None) -> str:
    """Build the full Markdown report as a string. `db` is a
    DatabaseManager (or anything exposing the same get_* methods);
    `cve_db`, if given, adds CVE context per service using the same
    matching CveDatabase already uses live."""
    summary = db.get_summary()
    hosts = db.get_hosts(limit=1000)
    logs = db.get_logs(limit=1000)

    lines: List[str] = []
    lines.append("# Vetaal Security Scan Report")
    lines.append("")
    lines.append(f"Generated: {_fmt_ts(time.time())}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Hosts discovered: **{summary.get('total_hosts', 0)}**")
    lines.append(f"- Services found open: **{summary.get('total_services', 0)}**")
    lines.append(f"- Commands executed: **{summary.get('total_commands', 0)}**")
    lines.append("")

    if not hosts:
        lines.append("_No hosts have been discovered yet — run a scan first._")
        return "\n".join(lines)

    lines.append("## Hosts")
    lines.append("")

    # Group audit log entries by target IP for the per-host "Activity" section
    logs_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for entry in logs:
        target = entry.get("target", "")
        ip = target.split(":")[0] if target else ""
        logs_by_ip.setdefault(ip, []).append(entry)

    for host in hosts:
        ip = host.get("ip_address", "unknown")
        mac = host.get("mac_address", "")
        os_guess = host.get("os_guess", "Unknown")
        services = host.get("services", [])

        lines.append(f"### {ip}")
        lines.append("")
        if mac:
            lines.append(f"- MAC address: `{mac}`")
        lines.append(f"- OS guess: {os_guess}")
        lines.append(f"- Status: {host.get('status', 'unknown')}")
        lines.append("")

        if services:
            lines.append("**Open services:**")
            lines.append("")
            lines.append("| Port | Protocol | Service | Banner |")
            lines.append("|---|---|---|---|")
            for svc in services:
                banner = svc.get("banner", "") or "—"
                lines.append(
                    f"| {svc.get('port')} | {svc.get('protocol', 'tcp')} | "
                    f"{svc.get('service_name', 'unknown')} | {banner} |"
                )
            lines.append("")

            if cve_db is not None:
                cve_lines = []
                for svc in services:
                    matches = cve_db.lookup(svc.get("service_name", ""), svc.get("banner", ""))
                    for m in matches[:5]:
                        cve_lines.append(
                            f"- **{m.get('cve', 'unknown')}** ({m.get('severity', 'unknown')}) "
                            f"on port {svc.get('port')}: {m.get('desc', '')}"
                        )
                if cve_lines:
                    lines.append("**Matched CVEs (version-based, not confirmed exploited):**")
                    lines.append("")
                    lines.extend(cve_lines)
                    lines.append("")
        else:
            lines.append("_No open services found in the scanned port range._")
            lines.append("")

        host_logs = logs_by_ip.get(ip, [])
        if host_logs:
            lines.append("**Activity against this host:**")
            lines.append("")
            for entry in sorted(host_logs, key=lambda e: e.get("timestamp", 0)):
                status = entry.get("status", "unknown")
                cmd = entry.get("command", "")
                ts = _fmt_ts(entry.get("timestamp", 0))
                lines.append(f"- `[{status}]` {cmd} — {ts}")
            lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- \"Matched CVEs\" means the detected service name/version fell within a "
        "known-vulnerable range in the local CVE database — it is a lead to "
        "investigate, not confirmation the target is actually exploitable."
    )
    lines.append(
        "- Command status `ok`/`failed` reflects the process exit code only — "
        "it does not mean an attack succeeded or failed in a security sense "
        "(e.g. a failed login attempt can still exit 0)."
    )
    lines.append(
        "- This report only includes what was actually scanned within the "
        "configured scope; absence of a finding is not proof of absence of a "
        "vulnerability."
    )

    return "\n".join(lines)
