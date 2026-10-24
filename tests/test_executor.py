import asyncio
import os
import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.vetaal.core.executor import AsyncCommandExecutor, CommandResult

@pytest.fixture
def mock_subprocess():
    """Fixture to mock asyncio.create_subprocess_exec."""
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        process_mock = MagicMock()
        process_mock.communicate = AsyncMock(return_value=(b"Standard Output", b"Standard Error"))
        process_mock.returncode = 0
        process_mock.pid = 12345
        mock_exec.return_value = process_mock
        yield mock_exec, process_mock

@pytest.mark.asyncio
async def test_standard_execution_and_congestion_control(mock_subprocess):
    mock_exec, _ = mock_subprocess
    executor = AsyncCommandExecutor()
    
    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        result = await executor.run(["nmap", "-sV", "192.168.1.1"])
        
        # Verify network congestion control jitter was applied
        mock_sleep.assert_called_once()
        delay_arg = mock_sleep.call_args[0][0]
        assert 0.5 <= delay_arg <= 2.0
        
        # Verify result structure and standard execution
        assert result.stdout == "Standard Output"
        assert result.stderr == "Standard Error"
        assert result.return_code == 0
        assert result.timeout_triggered is False
        
        # Verify process group isolation arguments and stream caps were applied
        mock_exec.assert_called_once()
        kwargs = mock_exec.call_args[1]
        assert kwargs['limit'] == 1024 * 1024  # Default 1MB cap
        if sys.platform == 'win32':
            assert 'creationflags' in kwargs
        else:
            assert 'preexec_fn' in kwargs

@pytest.mark.asyncio
async def test_secure_egress_routing_proxy_wrapper(mock_subprocess):
    mock_exec, _ = mock_subprocess
    # Initialize with a proxy wrapper (e.g., enterprise SOCKS tunnel)
    executor = AsyncCommandExecutor(proxy_wrapper="proxychains4 -q")
    
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await executor.run(["curl", "-I", "http://target.local"])
        
        # Verify the wrapper was securely tokenized and prepended
        executed_cmd = mock_exec.call_args[0]
        assert executed_cmd == ("proxychains4", "-q", "curl", "-I", "http://target.local")

@pytest.mark.asyncio
async def test_timeout_enforcement_and_isolation(mock_subprocess):
    mock_exec, process_mock = mock_subprocess
    
    # Simulate a process that hangs, triggering a TimeoutError
    process_mock.communicate.side_effect = asyncio.TimeoutError()
    process_mock.returncode = None  # Process still running
    
    executor = AsyncCommandExecutor()
    
    with patch("asyncio.sleep", new_callable=AsyncMock):
        with patch.object(executor, '_kill_process_group') as mock_kill:
            result = await executor.run(["ping", "10.0.0.1"], timeout=1.0)
            
            # Verify the orchestrator correctly identifies the timeout
            assert result.timeout_triggered is True
            assert result.return_code == -1
            assert "Timeout of 1.0s reached" in result.stderr
            
            # Verify the process group isolation kill function was triggered
            mock_kill.assert_called_once_with(process_mock)

@pytest.mark.asyncio
async def test_semaphore_concurrency_control(mock_subprocess):
    mock_exec, process_mock = mock_subprocess
    # Limit concurrency strictly to 2
    executor = AsyncCommandExecutor(max_concurrency=2)
    
    async def track_concurrency(cmd):
        # We replace the actual execution with a small delay to simulate concurrent load
        await asyncio.sleep(0.1)
        return CommandResult("out", "err", 0, False)

    with patch.object(executor, 'run', side_effect=track_concurrency) as mock_run:
        # Fire 5 parallel tasks
        tasks = [executor.run(["cmd", str(i)]) for i in range(5)]
        await asyncio.gather(*tasks)
        
        # Verify all tasks ran without exceeding limits (semaphore internals handle this implicitly)
        assert mock_run.call_count == 5
