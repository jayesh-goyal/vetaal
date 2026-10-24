import json
import os
import tempfile

from vetaal.modules.cve_db import CveDatabase

SAMPLE_DB = {
    "exploits": [
        {
            "service": "openssh",
            "version_re": r"8\.[5-9]",
            "cve": "CVE-2024-6387",
            "desc": "regreSSHion race condition RCE",
            "severity": "critical",
            "commands": ["nmap -T2 --script=vulners -p 22 {ip}"],
        },
        {
            "service": "vsftpd",
            "version_re": r"2\.3\.4",
            "cve": "CVE-2011-2523",
            "desc": "vsftpd 2.3.4 backdoor",
            "severity": "critical",
            "commands": ["nmap -T2 --script=ftp-vsftpd-backdoor -p 21 {ip}"],
        },
    ]
}


def _write_sample_db(tmp_path) -> str:
    path = os.path.join(tmp_path, "cve_exploits.json")
    with open(path, "w") as f:
        json.dump(SAMPLE_DB, f)
    return path


def test_matches_service_and_version():
    with tempfile.TemporaryDirectory() as tmp:
        db = CveDatabase(db_path=_write_sample_db(tmp))
        ctx = db.get_context("ssh", "OpenSSH 8.9p1", "10.0.0.5")
        assert "CVE-2024-6387" in ctx
        assert "10.0.0.5" in ctx


def test_no_match_when_version_out_of_range():
    with tempfile.TemporaryDirectory() as tmp:
        db = CveDatabase(db_path=_write_sample_db(tmp))
        ctx = db.get_context("ssh", "OpenSSH 7.2p1", "10.0.0.5")
        assert ctx == ""


def test_no_match_for_unrelated_service():
    with tempfile.TemporaryDirectory() as tmp:
        db = CveDatabase(db_path=_write_sample_db(tmp))
        ctx = db.get_context("mysql", "MySQL 8.0", "10.0.0.5")
        assert ctx == ""


def test_missing_file_returns_empty():
    db = CveDatabase(db_path="/nonexistent/cve_exploits.json")
    assert db.get_context("ssh", "OpenSSH 8.9", "10.0.0.5") == ""
