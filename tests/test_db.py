import pytest
import sqlite3
from pathlib import Path
from src.vetaal.utils.db import DatabaseManager

@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a clean DatabaseManager instance for each test."""
    db_file = tmp_path / "test_vetaal.db"
    manager = DatabaseManager(db_file)
    return manager

def test_schema_initialization(db_manager: DatabaseManager):
    """Verify that all required tables are created during initialization."""
    with db_manager._get_connection() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
    
    assert "hosts" in tables
    assert "services" in tables
    assert "audit_execution_history" in tables

def test_upsert_host_dynamic_ip_update(db_manager: DatabaseManager):
    """Verify that upserting an existing MAC with a new IP updates the row instead of duplicating."""
    mac = "00:1A:2B:3C:4D:5E"
    initial_ip = "192.168.1.50"
    updated_ip = "192.168.1.100"

    # Initial Insert
    db_manager.upsert_host(mac_address=mac, ip_address=initial_ip, hostname="workstation-01")
    
    with db_manager._get_connection() as conn:
        row = conn.execute("SELECT * FROM hosts WHERE mac_address = ?", (mac,)).fetchone()
        assert row["ip_address"] == initial_ip
        assert row["hostname"] == "workstation-01"

    # Update with new IP (DHCP lease change scenario)
    db_manager.upsert_host(mac_address=mac, ip_address=updated_ip)

    with db_manager._get_connection() as conn:
        cursor = conn.execute("SELECT * FROM hosts;")
        rows = cursor.fetchall()
        
        # Ensure no duplicates were created
        assert len(rows) == 1
        assert rows[0]["ip_address"] == updated_ip
        # Hostname should be retained through COALESCE
        assert rows[0]["hostname"] == "workstation-01"

def test_upsert_service_foreign_key_and_conflict(db_manager: DatabaseManager):
    """Verify service tracking, foreign key constraints, and conflict resolution."""
    mac = "AA:BB:CC:DD:EE:FF"
    
    # Must insert host first to satisfy FK constraint
    db_manager.upsert_host(mac_address=mac, ip_address="10.0.0.5")
    
    # Insert Service
    db_manager.upsert_service(
        mac_address=mac, 
        port=22, 
        protocol="tcp", 
        service_name="ssh", 
        state="open"
    )

    with db_manager._get_connection() as conn:
        row = conn.execute("SELECT * FROM services WHERE mac_address = ? AND port = ?", (mac, 22)).fetchone()
        assert row["service_name"] == "ssh"
        assert row["state"] == "open"

    # Update Service state
    db_manager.upsert_service(
        mac_address=mac, 
        port=22, 
        protocol="tcp", 
        state="filtered"
    )

    with db_manager._get_connection() as conn:
        row = conn.execute("SELECT * FROM services WHERE mac_address = ? AND port = ?", (mac, 22)).fetchone()
        assert row["state"] == "filtered"
        assert row["service_name"] == "ssh"  # Should be retained

def test_missing_host_violates_foreign_key(db_manager: DatabaseManager):
    """Verify that inserting a service for a non-existent MAC fails."""
    with pytest.raises(sqlite3.IntegrityError):
        db_manager.upsert_service(
            mac_address="FF:FF:FF:FF:FF:FF", 
            port=80, 
            protocol="tcp"
        )

def test_record_and_verify_playbook_execution(db_manager: DatabaseManager):
    """Verify stateful memory of executed playbooks to prevent redundancy."""
    mac = "11:22:33:44:55:66"
    port = 443
    playbook_id = "PB_TLS_COMPLIANCE_01"

    # Setup target
    db_manager.upsert_host(mac_address=mac, ip_address="172.16.0.10")
    db_manager.upsert_service(mac_address=mac, port=port, protocol="tcp")

    # Initially, it has not run
    assert db_manager.has_playbook_run(mac, port, playbook_id) is False

    # Mark as pending/failed
    db_manager.record_playbook_execution(mac, port, playbook_id, status="failed")
    assert db_manager.has_playbook_run(mac, port, playbook_id) is False

    # Mark as completed
    db_manager.record_playbook_execution(mac, port, playbook_id, status="completed")
    assert db_manager.has_playbook_run(mac, port, playbook_id) is True

    # Verify underlying DB record updated
    with db_manager._get_connection() as conn:
        row = conn.execute(
            "SELECT status FROM audit_execution_history WHERE mac_address = ? AND playbook_id = ?", 
            (mac, playbook_id)
        ).fetchone()
        assert row["status"] == "completed"

def test_record_audit_and_get_logs_and_summary(db_manager: DatabaseManager):
    """audit_logs powers /api/summary's total_commands and the Live Audit
    Log panel — dropped from the original schema rewrite, added back."""
    db_manager.record_audit(["dig", "axfr", "@10.0.0.5"], "ok", "10.0.0.5:53")
    db_manager.record_audit(["nxc", "ftp", "10.0.0.5"], "failed", "10.0.0.5:21")

    logs = db_manager.get_logs()
    assert len(logs) == 2
    assert logs[0]["command"] == "nxc ftp 10.0.0.5"  # most recent first

    summary = db_manager.get_summary()
    assert summary["total_commands"] == 2


def test_upsert_state_and_get_state(db_manager: DatabaseManager):
    """agent_state powers /api/health — before this existed, that
    endpoint was hardcoded to always claim {'status': 'ok', 'phase':
    'IDLE'} regardless of reality."""
    assert db_manager.get_state()["phase"] == "UNKNOWN"

    db_manager.upsert_state({"phase": "ENUMERATION", "error": ""})
    assert db_manager.get_state()["phase"] == "ENUMERATION"
    assert db_manager.get_state()["error"] == ""

    db_manager.upsert_state({"phase": "ENUMERATION", "error": "nmap not found"})
    assert db_manager.get_state()["error"] == "nmap not found"


def test_get_hosts_and_get_pending_targets_reflect_mac_schema(db_manager: DatabaseManager):
    mac = "AA:BB:CC:DD:EE:FF"
    db_manager.upsert_host(mac_address=mac, ip_address="10.0.0.5", os_info="Linux")
    db_manager.upsert_service(mac_address=mac, port=22, service_name="ssh", banner="OpenSSH 8.9")

    hosts = db_manager.get_hosts()
    assert hosts[0]["ip_address"] == "10.0.0.5"
    assert hosts[0]["mac_address"] == mac
    assert hosts[0]["os_guess"] == "Linux"
    assert hosts[0]["services"][0]["service_name"] == "ssh"

    targets = db_manager.get_pending_targets()
    assert targets[0]["mac_address"] == mac
    assert targets[0]["services"][0]["port"] == 22


def test_resolve_mac_key_falls_back_for_hosts_with_no_mac(db_manager: DatabaseManager):
    """mac_address is the schema's primary key and can't be null — hosts
    with no resolvable MAC (loopback, or reached through a router hop)
    need a stable substitute key rather than being silently unstorable."""
    assert DatabaseManager.resolve_mac_key("127.0.0.1", None) == "ip:127.0.0.1"
    assert DatabaseManager.resolve_mac_key("127.0.0.1", "") == "ip:127.0.0.1"
    real_mac = "AA:BB:CC:DD:EE:FF"
    assert DatabaseManager.resolve_mac_key("10.0.0.5", real_mac) == real_mac.lower()

    # And it actually round-trips through get_hosts() without exposing
    # the synthetic key as if it were a real MAC
    key = DatabaseManager.resolve_mac_key("127.0.0.1", None)
    db_manager.upsert_host(mac_address=key, ip_address="127.0.0.1")
    hosts = db_manager.get_hosts()
    assert hosts[0]["mac_address"] == ""  # synthetic key hidden from API consumers


def test_playbook_retry_cap_prevents_infinite_repetition(db_manager: DatabaseManager):
    """The exact regression we already fixed once before (a playbook
    whose underlying tool always exits non-zero running every single
    cycle forever) — must not come back just because status semantics
    changed to 'retry until completed'."""
    mac = "11:22:33:44:55:66"
    db_manager.upsert_host(mac_address=mac, ip_address="10.0.0.50")
    db_manager.upsert_service(mac_address=mac, port=21)

    for _ in range(3):
        assert db_manager.has_playbook_run(mac, 21, "ftp_attack") is False
        db_manager.record_playbook_execution(mac, 21, "ftp_attack", status="failed", max_attempts=3)

    # After 3 attempts, it must stop being retried even though it never
    # actually succeeded
    assert db_manager.has_playbook_run(mac, 21, "ftp_attack") is True


def test_playbook_real_success_stops_retries_immediately(db_manager: DatabaseManager):
    mac = "11:22:33:44:55:66"
    db_manager.upsert_host(mac_address=mac, ip_address="10.0.0.50")
    db_manager.upsert_service(mac_address=mac, port=21)

    db_manager.record_playbook_execution(mac, 21, "ftp_attack", status="failed", max_attempts=3)
    assert db_manager.has_playbook_run(mac, 21, "ftp_attack") is False
    db_manager.record_playbook_execution(mac, 21, "ftp_attack", status="completed", max_attempts=3)
    assert db_manager.has_playbook_run(mac, 21, "ftp_attack") is True  # immediate, not waiting for the cap

def test_get_exhausted_playbook_ids(db_manager: DatabaseManager):
    mac = "11:22:33:44:55:66"
    db_manager.upsert_host(mac_address=mac, ip_address="10.0.0.50")
    db_manager.upsert_service(mac_address=mac, port=21)
    db_manager.upsert_service(mac_address=mac, port=22)

    assert db_manager.get_exhausted_playbook_ids(mac, 21) == []

    db_manager.record_playbook_execution(mac, 21, "ftp_attack", status="completed")
    db_manager.record_playbook_execution(mac, 22, "ssh_full_attack", status="failed", max_attempts=3)

    assert db_manager.get_exhausted_playbook_ids(mac, 21) == ["ftp_attack"]
    assert db_manager.get_exhausted_playbook_ids(mac, 22) == []  # only failed once so far, not exhausted yet

def test_resolve_mac_key_normalizes_case(db_manager: DatabaseManager):
    """The same physical device must resolve to the same key regardless
    of whether nmap (uppercase) or passive capture (lowercase) reported
    the MAC — otherwise it silently fragments into two host rows."""
    assert DatabaseManager.resolve_mac_key("10.0.0.5", "AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert DatabaseManager.resolve_mac_key("10.0.0.5", "aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
