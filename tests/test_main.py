import pytest
import signal
from unittest.mock import MagicMock
from vetaal import main

@pytest.mark.asyncio
async def test_graceful_shutdown():
    mock_orchestrator = MagicMock()
    mock_server = MagicMock()
    mock_db = MagicMock()

    await main.graceful_shutdown(signal.SIGINT, mock_orchestrator, mock_server, mock_db)
    assert mock_orchestrator.current_phase == main.AgentPhase.SHUTDOWN
    assert mock_server.should_exit is True


@pytest.mark.asyncio
async def test_graceful_shutdown_stops_passive_capture_when_present():
    mock_orchestrator = MagicMock()
    mock_server = MagicMock()
    mock_db = MagicMock()
    mock_passive = MagicMock()

    await main.graceful_shutdown(signal.SIGTERM, mock_orchestrator, mock_server, mock_db, mock_passive)
    mock_passive.stop.assert_called_once()
    assert mock_orchestrator.current_phase == main.AgentPhase.SHUTDOWN
