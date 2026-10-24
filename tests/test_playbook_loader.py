import json
import os
import tempfile

from vetaal.modules.playbook_loader import PlaybookLoader

SAMPLE_PLAYBOOKS = {
    "playbooks": [
        {
            "id": "ftp_attack",
            "trigger_obs": "ftp",
            "trigger_ports": [21],
            "repeatable": True,
            "desc": "FTP anonymous + default creds",
            "steps": ["nxc ftp {ip} -u anonymous -p anonymous"],
        },
        {
            "id": "smb_share_read",
            "trigger_obs": "shares accessible",
            "trigger_ports": [445, 139],
            "repeatable": False,
            "desc": "Read contents of accessible SMB shares",
            "steps": ["smbclient -N //{ip}/{share} -c 'recurse ON; ls'"],
        },
        {
            "id": "wordlist_probe",
            "trigger_obs": "",
            "trigger_ports": [80],
            "repeatable": False,
            "desc": "Generic web probe using a shared wordlist path",
            "steps": ["gobuster dir -u http://{ip} -w {{VETAAL_DATA_DIR}}/wordlists/dirb/common.txt"],
        },
    ]
}


def _write_sample_playbooks(tmp_path) -> str:
    path = os.path.join(tmp_path, "playbooks.json")
    with open(path, "w") as f:
        json.dump(SAMPLE_PLAYBOOKS, f)
    return path


def test_matches_on_port_and_service_name():
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp))
        ctx = loader.get_playbook_context("ftp", 21, ip="10.0.0.5")
        assert "ftp_attack" in ctx
        assert "10.0.0.5" in ctx


def test_no_match_when_port_differs():
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp))
        ctx = loader.get_playbook_context("ftp", 2121, ip="10.0.0.5")
        assert ctx == ""


def test_requires_derived_observation_text_when_present():
    """A playbook whose trigger_obs describes a real finding (not just a
    port-scan service name) should NOT fire off a bare service_name/banner —
    that's the correct, expected behavior until real enumeration data exists."""
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp))
        ctx = loader.get_playbook_context("microsoft-ds", 445, ip="10.0.0.5")
        assert ctx == ""


def test_data_dir_placeholder_resolved():
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp), data_dir="/opt/vetaal-data")
        ctx = loader.get_playbook_context("http", 80, ip="10.0.0.9")
        assert "/opt/vetaal-data/wordlists/dirb/common.txt" in ctx
        assert "{{VETAAL_DATA_DIR}}" not in ctx


def test_missing_file_returns_empty_context():
    loader = PlaybookLoader(playbooks_path="/nonexistent/playbooks.json")
    assert loader.get_playbook_context("ftp", 21) == ""


def test_exclude_ids_removes_matched_playbook():
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp))
        ctx = loader.get_playbook_context("ftp", 21, ip="10.0.0.5", exclude_ids={"ftp_attack"})
        assert ctx == ""


def test_get_top_match_id_returns_first_matching_playbook_id():
    with tempfile.TemporaryDirectory() as tmp:
        loader = PlaybookLoader(playbooks_path=_write_sample_playbooks(tmp))
        assert loader.get_top_match_id("ftp", 21) == "ftp_attack"
        assert loader.get_top_match_id("ftp", 21, exclude_ids={"ftp_attack"}) is None
        assert loader.get_top_match_id("nonexistent", 9999) is None
