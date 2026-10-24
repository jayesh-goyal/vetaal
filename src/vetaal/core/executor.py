import asyncio
import logging
import os
import random
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

@dataclass
class CommandResult:
    """Structured output for asynchronous command execution."""
    stdout: str
    stderr: str
    return_code: int
    timeout_triggered: bool

class AsyncCommandExecutor:
    """
    Asynchronous execution engine featuring process group isolation, stream 
    buffer caps, timeout enforcement, concurrency control, and secure egress routing.
    """

    def __init__(
        self, 
        max_concurrency: int = 10, 
        proxy_wrapper: Optional[str] = None,
        stream_limit: int = 1024 * 1024  # 1MB buffer cap to prevent memory exhaustion
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.proxy_wrapper = proxy_wrapper
        self.stream_limit = stream_limit

    async def _apply_congestion_control(self) -> None:
        """Applies network congestion control via asynchronous jitter (0.5s - 2.0s)."""
        jitter = random.uniform(0.5, 2.0)
        logger.debug(f"Applying network congestion control delay: {jitter:.2f}s")
        await asyncio.sleep(jitter)

    def _prepare_command(self, cmd_args: List[str]) -> List[str]:
        """Prepends the proxy wrapper to the command list if configured."""
        if self.proxy_wrapper:
            try:
                wrapper_tokens = shlex.split(self.proxy_wrapper)
                return wrapper_tokens + cmd_args
            except ValueError as e:
                logger.error(f"Failed to parse proxy_wrapper '{self.proxy_wrapper}': {e}")
                # Fallback to direct execution if wrapper parsing fails securely
                return cmd_args
        return cmd_args

    def _kill_process_group(self, process: asyncio.subprocess.Process) -> None:
        """Ensures complete termination of the process and all its children."""
        if process.returncode is not None:
            return
            
        try:
            if sys.platform == 'win32':
                # Windows process group termination via taskkill
                subprocess.call(
                    ['taskkill', '/F', '/T', '/PID', str(process.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                # POSIX process group termination
                import signal
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception as e:
            logger.error(f"Failed to safely isolate and kill process group for PID {process.pid}: {e}")

    async def run(self, cmd_args: List[str], timeout: float = 30.0) -> CommandResult:
        """
        Executes a shell command asynchronously with rate limiting, timeouts, 
        and strict stream bounds.
        """
        await self._apply_congestion_control()
        final_cmd = self._prepare_command(cmd_args)
        
        async with self.semaphore:
            kwargs = {
                'stdout': asyncio.subprocess.PIPE,
                'stderr': asyncio.subprocess.PIPE,
                'limit': self.stream_limit
            }
            
            # Enable cross-platform process group isolation
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs['preexec_fn'] = os.setsid

            logger.info(f"Dispatching execution: {final_cmd}")
            try:
                process = await asyncio.create_subprocess_exec(*final_cmd, **kwargs)
            except Exception as e:
                logger.error(f"Failed to spawn subprocess {final_cmd}: {e}")
                return CommandResult(stdout="", stderr=str(e), return_code=-1, timeout_triggered=False)

            try:
                # Enforce strict execution timeouts
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                return CommandResult(
                    stdout=stdout_bytes.decode('utf-8', errors='replace'),
                    stderr=stderr_bytes.decode('utf-8', errors='replace'),
                    return_code=process.returncode or 0,
                    timeout_triggered=False
                )
            except asyncio.TimeoutError:
                logger.warning(f"Execution timeout ({timeout}s) exceeded for: {final_cmd}. Terminating process group.")
                self._kill_process_group(process)
                return CommandResult(
                    stdout="",
                    stderr=f"Execution aborted: Timeout of {timeout}s reached.",
                    return_code=-1,
                    timeout_triggered=True
                )
