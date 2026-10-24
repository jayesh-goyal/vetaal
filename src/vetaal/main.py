import argparse
import asyncio
import logging
from logging.handlers import RotatingFileHandler
import signal
import sys
from pathlib import Path
from typing import Any
import yaml
import uvicorn

from vetaal.utils.db import DatabaseManager
from vetaal.modules.net_detect import NetworkDetector
from vetaal.security.scope_validator import ScopeValidator
from vetaal.core.executor import AsyncCommandExecutor
from vetaal.utils.output_parser import OutputParser
from vetaal.modules.llm_client import LocalLLMClient
from vetaal.modules.playbook_loader import PlaybookLoader
from vetaal.modules.cve_db import CveDatabase
from vetaal.modules.passive_capture import PassiveCapture
from vetaal.core.orchestrator import AgentOrchestrator, AgentPhase
from vetaal.web import webui

logger = logging.getLogger("VetaalMain")

def setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    fh = RotatingFileHandler("vetaal.log", maxBytes=10 * 1024 * 1024, backupCount=5)
    fh.setLevel(level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

async def main() -> None:
    parser = argparse.ArgumentParser(description="Vetaal Security Auditing Framework")
    parser.add_argument("--config", type=str, required=True, help="Path to config YAML")
    parser.add_argument("--db", type=str, default="vetaal.db", help="SQLite DB path")
    parser.add_argument("--port", type=int, default=8888, help="Web UI port")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(args.debug)
    logger.info("Initializing Vetaal framework...")

    db_manager = DatabaseManager(args.db)

    config_path = Path(args.config)
    config_data = {}
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}

    scope_cfg = config_data.setdefault("scope", {})
    net_detector = NetworkDetector(excluded_ports=scope_cfg.get("excluded_ports", []))
    env_info = await net_detector.detect_environment()
    local_ip = env_info.get("local_ip", "127.0.0.1")

    excluded = scope_cfg.setdefault("excluded_ips", [])
    if local_ip and local_ip not in excluded:
        excluded.append(local_ip)

    scope_validator = ScopeValidator(config_data)
    executor_cfg = config_data.get("executor", {})
    executor = AsyncCommandExecutor(
        max_concurrency=executor_cfg.get("max_concurrency", 4),
        proxy_wrapper=executor_cfg.get("proxy_wrapper"),
    )
    output_parser = OutputParser()
    playbook_loader = PlaybookLoader()
    cve_db = CveDatabase()
    llm_cfg = config_data.get("llm", {})
    llm_client = LocalLLMClient(
        base_url=llm_cfg.get("base_url", "http://127.0.0.1:8080/v1"),
        model_name=llm_cfg.get("model_name", "local-model"),
    )

    orchestrator = AgentOrchestrator(
        db_manager=db_manager,
        scope_validator=scope_validator,
        net_detector=net_detector,
        executor=executor,
        output_parser=output_parser,
        llm_client=llm_client,
        playbook_loader=playbook_loader,
        cve_db=cve_db
    )

    webui.set_database_manager(db_manager)
    webui.set_cve_db(cve_db)

    passive_cfg = config_data.get("passive_discovery", {})
    passive_capture = None
    if passive_cfg.get("enabled", True):

        def on_passive_host(host_data: dict) -> None:
            # upsert_host is synchronous and opens/closes its own sqlite
            # connection per call, so it's safe to call directly from
            # scapy's sniffer thread — no asyncio bridging needed.
            mac_key = db_manager.resolve_mac_key(host_data["ip_address"], host_data.get("mac_address"))
            try:
                db_manager.upsert_host(mac_address=mac_key, ip_address=host_data["ip_address"])
            except Exception as exc:
                logger.error(f"Passive discovery failed to record host: {exc}")

        passive_capture = PassiveCapture(
            interface=passive_cfg.get("interface"),
            on_host_seen=on_passive_host,
        )
        started = passive_capture.start()
        if started:
            logger.info("Passive discovery (ARP) running in the background.")
        else:
            logger.info(
                "Passive discovery unavailable this run (needs root/CAP_NET_RAW, "
                "or scapy isn't installed) — active scanning is unaffected."
            )
            passive_capture = None

    uvicorn_config = uvicorn.Config(
        app=webui.app,
        host="127.0.0.1",
        port=args.port,
        log_level="debug" if args.debug else "info",
        loop="asyncio"
    )
    server = uvicorn.Server(uvicorn_config)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(
                graceful_shutdown(s, orchestrator, server, db_manager, passive_capture)
            ),
        )

    async with asyncio.TaskGroup() as tg:
        tg.create_task(orchestrator.start())
        tg.create_task(server.serve())

async def graceful_shutdown(sig: signal.Signals, orchestrator: Any, server: Any, db_manager: Any, passive_capture: Any = None) -> None:
    logger.info(f"Received {sig.name} — initiating graceful shutdown...")
    if passive_capture:
        passive_capture.stop()
    if orchestrator:
        orchestrator.current_phase = AgentPhase.SHUTDOWN
    if server:
        server.should_exit = True
    if db_manager:
        db_manager.close()

if __name__ == "__main__":
    asyncio.run(main())
