import asyncio
import enum
import json
import logging
import signal
import time
from typing import List, Optional, Dict, Any

logger = logging.getLogger("AgentOrchestrator")

class AgentPhase(enum.Enum):
    INITIALIZATION = enum.auto()
    DISCOVERY = enum.auto()
    ENUMERATION = enum.auto()
    ANALYSIS = enum.auto()
    IDLE = enum.auto()
    SHUTDOWN = enum.auto()

class AgentOrchestrator:
    """Central orchestration finite state machine managing scanning and execution loops."""
    def __init__(
        self,
        db_manager: Any,
        scope_validator: Any,
        net_detector: Any,
        executor: Any,
        output_parser: Any,
        llm_client: Any,
        playbook_loader: Any,
        cve_db: Any = None
    ):
        self.db = db_manager
        self.scope_validator = scope_validator
        self.net_detector = net_detector
        self.executor = executor
        self.output_parser = output_parser
        self.llm_client = llm_client
        self.playbook_loader = playbook_loader
        self.cve_db = cve_db

        self.current_phase = AgentPhase.INITIALIZATION
        self._shutdown_event = asyncio.Event()
        self.error_count = 0
        self.max_backoff = 60.0

    def _setup_signal_handlers(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self._initiate_shutdown)
        except (NotImplementedError, RuntimeError):
            pass

    def _initiate_shutdown(self) -> None:
        logger.info("Shutdown signal received. Transitioning to SHUTDOWN phase.")
        self.current_phase = AgentPhase.SHUTDOWN
        self._shutdown_event.set()

    async def start(self) -> None:
        self._setup_signal_handlers()
        logger.info("Starting AgentOrchestrator loop.")
        await self._run_loop()

    async def _run_loop(self) -> None:
        STUCK_THRESHOLD = 5  # consecutive failures in the same phase before we force a reset
        while self.current_phase != AgentPhase.SHUTDOWN:
            phase_at_start = self.current_phase
            try:
                if self.current_phase == AgentPhase.INITIALIZATION:
                    await self._handle_initialization()
                elif self.current_phase == AgentPhase.DISCOVERY:
                    await self._handle_discovery()
                elif self.current_phase == AgentPhase.ENUMERATION:
                    await self._handle_enumeration()
                elif self.current_phase == AgentPhase.ANALYSIS:
                    await self._handle_analysis()
                elif self.current_phase == AgentPhase.IDLE:
                    await self._handle_idle()

                self.error_count = 0
                await self._checkpoint_state("")
            except Exception as exc:
                self.error_count += 1
                backoff = min(2.0 ** self.error_count, self.max_backoff)
                logger.error(f"Unhandled exception in phase {phase_at_start.name}: {exc}")
                await self._checkpoint_state(str(exc))

                if self.error_count >= STUCK_THRESHOLD:
                    # Self-healing: a phase that keeps throwing isn't going
                    # to fix itself by retrying the same phase forever at
                    # the (capped) backoff interval — force back to a known
                    # safe state instead of getting permanently stuck.
                    logger.error(
                        f"{phase_at_start.name} failed {self.error_count} times in a row — "
                        f"forcing reset to IDLE rather than retrying it forever."
                    )
                    self.current_phase = AgentPhase.IDLE
                    self.error_count = 0
                    await self._checkpoint_state(f"recovered from stuck {phase_at_start.name}")

                await asyncio.sleep(backoff)

    async def _checkpoint_state(self, error_message: str) -> None:
        if self.db and hasattr(self.db, "upsert_state"):
            try:
                self.db.upsert_state({
                    "phase": self.current_phase.name,
                    "error": error_message,
                    "timestamp": time.time()
                })
            except Exception as db_err:
                logger.error(f"Failed to checkpoint state: {db_err}")

    async def _handle_initialization(self) -> None:
        self.current_phase = AgentPhase.DISCOVERY

    async def _handle_discovery(self) -> None:
        if self.net_detector and hasattr(self.net_detector, "scan"):
            hosts = await self.net_detector.scan()
            for host in hosts:
                mac_key = self.db.resolve_mac_key(host["ip_address"], host.get("mac_address"))
                if self.db and hasattr(self.db, "upsert_host"):
                    self.db.upsert_host(
                        mac_address=mac_key,
                        ip_address=host["ip_address"],
                        os_info=host.get("os_guess"),
                    )
                if self.db and hasattr(self.db, "upsert_service"):
                    for service in host.get("services", []):
                        port = service.get("port")
                        if port is None:
                            continue
                        self.db.upsert_service(
                            mac_address=mac_key,
                            port=port,
                            protocol=service.get("protocol", "tcp"),
                            service_name=service.get("service_name"),
                            banner=service.get("banner"),
                        )
        self.current_phase = AgentPhase.ENUMERATION

    async def _handle_enumeration(self) -> None:
        pending_targets = []
        if self.db and hasattr(self.db, "get_pending_targets"):
            pending_targets = self.db.get_pending_targets()

        if not pending_targets:
            self.current_phase = AgentPhase.ANALYSIS
            return

        for target in pending_targets:
            ip = target.get("ip_address")
            host_key = target.get("mac_address") or ip
            services = target.get("services", [])

            for service in services:
                port = service.get("port")
                svc_name = service.get("service_name", "unknown")
                banner = service.get("banner", "")

                exhausted_ids = set()
                if self.db and hasattr(self.db, "get_exhausted_playbook_ids"):
                    exhausted_ids = set(self.db.get_exhausted_playbook_ids(host_key, port))

                playbook_context = ""
                top_playbook_id = None
                if self.playbook_loader:
                    playbook_context = self.playbook_loader.get_playbook_context(
                        svc_name, port, ip=ip, banner=banner, exclude_ids=exhausted_ids
                    )
                    top_playbook_id = self.playbook_loader.get_top_match_id(
                        svc_name, port, banner=banner, exclude_ids=exhausted_ids
                    )

                cve_context = ""
                if self.cve_db:
                    cve_context = self.cve_db.get_context(svc_name, banner, ip)

                combined_context = "\n\n".join(filter(None, [playbook_context, cve_context]))

                messages = [{"role": "user", "content": f"Target {ip}:{port} running {svc_name}."}]
                if self.llm_client:
                    response = await self.llm_client.generate_action(
                        messages, combined_context, require_json=True, ip=ip, port=port
                    )
                    content = response.content if hasattr(response, "content") else str(response)
                    cmd_args = self._extract_command_from_response(content)
                    if not cmd_args:
                        continue

                    try:
                        if self.scope_validator:
                            self.scope_validator.validate_command(cmd_args)
                    except Exception as sve:
                        logger.warning(f"Safety gate blocked command {cmd_args}: {sve}")
                        continue

                    exec_result = await self.executor.run(cmd_args)
                    status = "ok" if exec_result.return_code == 0 else "failed"

                    if self.db and hasattr(self.db, "record_audit"):
                        self.db.record_audit(cmd_args, status, f"{ip}:{port}")

                    # Remember that this playbook was tried against this
                    # host+port (keyed by MAC when known, so it survives
                    # the host later getting a different IP from DHCP) —
                    # stops the same attack running every single cycle
                    # forever. record_playbook_execution retries a
                    # 'failed' playbook up to max_attempts before forcing
                    # it to 'completed' regardless of real outcome.
                    if top_playbook_id and self.db and hasattr(self.db, "record_playbook_execution"):
                        exec_status = "completed" if exec_result.return_code == 0 else "failed"
                        self.db.record_playbook_execution(host_key, port, top_playbook_id, status=exec_status)

                    # NOTE: earlier versions also called
                    # output_parser.parse_banner(exec_result.stdout) and fed
                    # that into upsert_service() here, treating whatever this
                    # arbitrary playbook/CVE command printed as a "banner
                    # refresh" for the service. That made a kind of sense
                    # when every command was the same hardcoded curl, but
                    # with real, varied commands (dig, nxc, nmap --script=
                    # vulners, ...) it overwrites the correct service_name/
                    # banner that discovery's real nmap -sV scan already
                    # found, with garbage like a DNS server's service_name
                    # flipping to "unknown" and its banner becoming dig's own
                    # command-echo line. Service identity now comes ONLY
                    # from discovery; command output here is captured via
                    # record_audit above, not treated as an identity update.

        self.current_phase = AgentPhase.ANALYSIS

    def _extract_command_from_response(self, content: str) -> List[str]:
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "command" in data:
                return [str(c) for c in data["command"]]
            elif isinstance(data, list):
                return [str(c) for c in data]
        except json.JSONDecodeError:
            pass
        return []

    async def _handle_analysis(self) -> None:
        await asyncio.sleep(0.1)
        self.current_phase = AgentPhase.IDLE

    async def _handle_idle(self) -> None:
        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            if not self._shutdown_event.is_set():
                self.current_phase = AgentPhase.DISCOVERY
