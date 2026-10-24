import json
import os
import pytest

from vetaal.utils.db import DatabaseManager
from vetaal.modules.cve_db import CveDatabase
from vetaal.utils.report_generator import generate_report


def test_report_with_no_hosts_says_so(tmp_path):
    db = DatabaseManager(str(tmp_path / "test.db"))
    report = generate_report(db)
    assert "No hosts have been discovered yet" in report
    assert "# Vetaal Security Scan Report" in report


def test_report_includes_real_host_service_and_log_data(tmp_path):
    db = DatabaseManager(str(tmp_path / "test.db"))
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_host(mac_address=mac, ip_address="10.0.0.5", os_info="Linux")
    db.upsert_service(mac_address=mac, port=22, service_name="ssh", banner="OpenSSH 8.9p1")
    db.record_audit(["nxc", "ssh", "10.0.0.5", "-u", "pi", "-p", "raspberry"], "failed", "10.0.0.5:22")

    report = generate_report(db)

    assert "10.0.0.5" in report
    assert mac in report
    assert "ssh" in report
    assert "OpenSSH 8.9p1" in report
    assert "nxc ssh 10.0.0.5 -u pi -p raspberry" in report
    assert "[failed]" in report
    assert "Matched CVEs" not in report or "10.0.0.5" in report


def test_report_includes_cve_matches_when_cve_db_given(tmp_path):
    db = DatabaseManager(str(tmp_path / "test.db"))
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_host(mac_address=mac, ip_address="10.0.0.5", os_info="Linux")
    db.upsert_service(mac_address=mac, port=22, service_name="ssh", banner="OpenSSH 8.9p1")

    cve_path = os.path.join(tmp_path, "cve_exploits.json")
    with open(cve_path, "w") as f:
        json.dump({"exploits": [{
            "service": "openssh", "version_re": r"8\.[5-9]", "cve": "CVE-2024-6387",
            "desc": "regreSSHion", "severity": "critical", "commands": ["nmap -T2 --script=vulners -p 22 {ip}"]
        }]}, f)
    cve_db = CveDatabase(db_path=cve_path)

    report = generate_report(db, cve_db)
    assert "CVE-2024-6387" in report
    assert "regreSSHion" in report


def test_report_notes_section_present_for_honesty_caveats(tmp_path):
    db = DatabaseManager(str(tmp_path / "test.db"))
    db.upsert_host(mac_address="AA:BB:CC:DD:EE:FF", ip_address="10.0.0.5", os_info="Linux")
    report = generate_report(db)
    assert "## Notes" in report
    assert "not confirmation" in report
