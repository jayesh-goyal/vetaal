import pytest
from unittest.mock import AsyncMock, MagicMock
from vetaal.core.orchestrator import AgentOrchestrator, AgentPhase
from vetaal.security.scope_validator import ScopeViolationError


def _make_mock_db(pending_targets, exhausted=None):
    """AsyncMock() auto-creates ALL child attributes as AsyncMock too, so
    genuinely synchronous DatabaseManager methods (get_exhausted_playbook_ids,
    resolve_mac_key, etc) must be explicitly overridden with plain MagicMock
    — otherwise calling them without 'await' (correct, since they're sync in
    the real class) returns an unawaited coroutine object instead of a real
    value, breaking orchestrator code that reads their result directly."""
    db = AsyncMock()
    db.get_pending_targets = MagicMock(return_value=pending_targets)
    db.get_exhausted_playbook_ids = MagicMock(return_value=exhausted or [])
    db.resolve_mac_key = MagicMock(side_effect=lambda ip, mac: mac or f"ip:{ip}")
    db.upsert_state = MagicMock()
    db.record_audit = MagicMock()
    db.record_playbook_execution = MagicMock()
    db.upsert_host = MagicMock()
    db.upsert_service = MagicMock()
    return db


@pytest.mark.asyncio
async def test_safety_gate_drop_mechanism():
    db = _make_mock_db([{"ip_address": "10.0.0.99", "mac_address": "10.0.0.99", "services": [{"port": 80, "service_name": "http"}]}])
    validator = MagicMock()
    validator.validate_command.side_effect = ScopeViolationError("Out of scope.")
    executor = AsyncMock()
    parser = MagicMock()
    net_detector = AsyncMock()
    llm_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.content = '{"command": ["nmap", "10.0.0.99"]}'
    llm_client.generate_action = AsyncMock(return_value=mock_resp)
    playbook_loader = MagicMock()
    playbook_loader.get_playbook_context.return_value = ""
    playbook_loader.get_top_match_id.return_value = None

    orchestrator = AgentOrchestrator(db, validator, net_detector, executor, parser, llm_client, playbook_loader)
    orchestrator.current_phase = AgentPhase.ENUMERATION
    await orchestrator._handle_enumeration()
    validator.validate_command.assert_called_once()
    executor.run.assert_not_called()


@pytest.mark.asyncio
async def test_command_execution_does_not_overwrite_service_identity():
    """Regression test: after a real command runs against a service,
    orchestrator must NOT call upsert_service() with the command's raw
    stdout as a fake 'banner refresh' — that overwrites the real
    service_name/banner discovery found (e.g. a DNS server's identity
    flipping to 'unknown' with dig's own output stuffed in as the
    banner). Command results belong in record_audit only."""
    db = _make_mock_db([{"ip_address": "10.0.0.99", "mac_address": "10.0.0.99", "services": [{"port": 53, "service_name": "domain"}]}])
    validator = MagicMock()
    validator.validate_command.return_value = True
    executor = AsyncMock()
    exec_result = MagicMock()
    exec_result.return_code = 0
    exec_result.stdout = "; <<>> DiG 9.20.23-1-Debian <<>> axfr @10.0.0.99"
    executor.run = AsyncMock(return_value=exec_result)
    parser = MagicMock()
    net_detector = AsyncMock()
    llm_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.content = '{"command": ["dig", "axfr", "@10.0.0.99"]}'
    llm_client.generate_action = AsyncMock(return_value=mock_resp)
    playbook_loader = MagicMock()
    playbook_loader.get_playbook_context.return_value = ""
    playbook_loader.get_top_match_id.return_value = None

    orchestrator = AgentOrchestrator(db, validator, net_detector, executor, parser, llm_client, playbook_loader)
    orchestrator.current_phase = AgentPhase.ENUMERATION
    await orchestrator._handle_enumeration()

    executor.run.assert_called_once()
    db.record_audit.assert_called_once_with(["dig", "axfr", "@10.0.0.99"], "ok", "10.0.0.99:53")
    db.upsert_service.assert_not_called()


@pytest.mark.asyncio
async def test_playbook_execution_recorded_after_running():
    """When a playbook match drives the command, orchestrator must
    record the outcome against the host's MAC key + port so
    PlaybookLoader can later stop suggesting it (host memory)."""
    db = _make_mock_db(
        [{"ip_address": "10.0.0.50", "mac_address": "AA:BB:CC:DD:EE:FF", "services": [{"port": 21, "service_name": "ftp"}]}],
    )
    validator = MagicMock()
    validator.validate_command.return_value = True
    executor = AsyncMock()
    exec_result = MagicMock()
    exec_result.return_code = 1
    exec_result.stdout = ""
    executor.run = AsyncMock(return_value=exec_result)
    parser = MagicMock()
    net_detector = AsyncMock()
    llm_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.content = '{"command": ["nxc", "ftp", "10.0.0.50", "-u", "anonymous", "-p", "anonymous"]}'
    llm_client.generate_action = AsyncMock(return_value=mock_resp)
    playbook_loader = MagicMock()
    playbook_loader.get_playbook_context.return_value = (
        "Playbook 'ftp_attack': FTP anonymous + default creds\n"
        "    - nxc ftp 10.0.0.50 -u anonymous -p anonymous"
    )
    playbook_loader.get_top_match_id.return_value = "ftp_attack"

    orchestrator = AgentOrchestrator(db, validator, net_detector, executor, parser, llm_client, playbook_loader)
    orchestrator.current_phase = AgentPhase.ENUMERATION
    await orchestrator._handle_enumeration()

    db.record_playbook_execution.assert_called_once_with("AA:BB:CC:DD:EE:FF", 21, "ftp_attack", status="failed")
    db.get_exhausted_playbook_ids.assert_called_once_with("AA:BB:CC:DD:EE:FF", 21)


@pytest.mark.asyncio
async def test_exhausted_playbook_excluded_from_matching():
    """A playbook already completed for this host+port must be passed as
    exclude_ids to PlaybookLoader so it stops being suggested."""
    db = _make_mock_db(
        [{"ip_address": "10.0.0.50", "mac_address": "10.0.0.50", "services": [{"port": 21, "service_name": "ftp"}]}],
        exhausted=["ftp_attack"],
    )
    validator = MagicMock()
    executor = AsyncMock()
    parser = MagicMock()
    net_detector = AsyncMock()
    llm_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.content = '{"command": []}'
    llm_client.generate_action = AsyncMock(return_value=mock_resp)
    playbook_loader = MagicMock()
    playbook_loader.get_playbook_context.return_value = ""
    playbook_loader.get_top_match_id.return_value = None

    orchestrator = AgentOrchestrator(db, validator, net_detector, executor, parser, llm_client, playbook_loader)
    orchestrator.current_phase = AgentPhase.ENUMERATION
    await orchestrator._handle_enumeration()

    _, kwargs = playbook_loader.get_playbook_context.call_args
    assert kwargs["exclude_ids"] == {"ftp_attack"}


@pytest.mark.asyncio
async def test_stuck_phase_self_heals_to_idle(monkeypatch):
    """Self-healing: if a phase keeps throwing, the loop must not retry
    it forever at the (capped) backoff interval — after enough
    consecutive failures it should force a reset to IDLE rather than
    getting permanently stuck."""
    import asyncio as real_asyncio

    async def no_sleep(_seconds):
        return None
    monkeypatch.setattr(real_asyncio, "sleep", no_sleep)

    db = AsyncMock()
    db.upsert_state = MagicMock()
    validator = MagicMock()
    net_detector = AsyncMock()
    executor = AsyncMock()
    parser = MagicMock()
    llm_client = AsyncMock()
    playbook_loader = MagicMock()

    orchestrator = AgentOrchestrator(db, validator, net_detector, executor, parser, llm_client, playbook_loader)
    orchestrator.current_phase = AgentPhase.ENUMERATION

    async def always_fails():
        raise RuntimeError("simulated persistent bug in enumeration")

    async def idle_then_shutdown():
        orchestrator.current_phase = AgentPhase.SHUTDOWN

    orchestrator._handle_enumeration = always_fails
    orchestrator._handle_idle = idle_then_shutdown

    await orchestrator._run_loop()

    calls = [c.args[0] for c in db.upsert_state.call_args_list]
    assert any("recovered from stuck" in c.get("error", "") for c in calls)
