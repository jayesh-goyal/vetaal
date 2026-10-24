"""Loads and matches exploit/enumeration playbooks from data/playbooks.json.

Ported from the matching pattern used by Nightcrawler (garagehq/nightcrawler,
MIT licensed) — trigger on port + a loose text match against the observed
service — but simplified: Vetaal doesn't yet track per-host history
(tried/failed/done playbooks), so every matching playbook is returned each
time. That bookkeeping is a natural follow-up once host_memory-style
persistence exists.
"""
import json
import logging
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("PlaybookLoader")

# Some trigger_obs values are natural-language phrases that, in the
# original Nightcrawler pipeline, get written by its on-device LLM into a
# per-host observation log after it interprets command output — not
# literal nmap service names. Vetaal doesn't have that observation-logging
# step yet, so this maps the raw nmap service_name to the phrase(s) a
# playbook might expect, closing the gap for the cases where that's a
# reasonable inference. Playbooks whose trigger_obs describes an actual
# finding that can only come from real enumeration/exploitation output
# (e.g. "shares accessible", "ACCESS GAINED") are deliberately left
# unmapped — they SHOULD stay unmatched until that real data exists.
SERVICE_NAME_SYNONYMS: Dict[str, List[str]] = {
    "ssh": ["ssh:"],
    "http": ["http server"],
    "https": ["http server"],
    "http-proxy": ["http server"],
    "domain": ["dns resolver"],
    "microsoft-ds": ["samba version"],
    "netbios-ssn": ["samba version"],
    "ms-wbt-server": ["rdp"],
    "asf-rmcp": ["ipmi"],
}


def _default_data_dir() -> str:
    """Best-effort default for {{VETAAL_DATA_DIR}} when nothing is configured.
    Override with the VETAAL_DATA_DIR environment variable on any platform."""
    env_override = os.environ.get("VETAAL_DATA_DIR")
    if env_override:
        return env_override
    if platform.system() == "Windows":
        # No universal equivalent of /usr/share on Windows; fall back to a
        # folder next to the executable until a real install layout exists.
        return str(Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Vetaal")
    return "/usr/share"


class PlaybookLoader:
    """Loads playbooks.json and matches candidate playbooks against a
    discovered service, returning ready-to-inject prompt context."""

    def __init__(self, playbooks_path: Optional[str] = None, data_dir: Optional[str] = None):
        if playbooks_path is None:
            # data/playbooks.json relative to the project root (two levels
            # up from src/vetaal/modules/)
            playbooks_path = str(
                Path(__file__).resolve().parents[3] / "data" / "playbooks.json"
            )
        self.playbooks_path = playbooks_path
        self.data_dir = data_dir or _default_data_dir()
        self._playbooks: Optional[List[Dict[str, Any]]] = None
        self._mtime: Optional[float] = None

    def _load(self) -> List[Dict[str, Any]]:
        """Load playbooks.json, re-reading if the file changed on disk
        (cheap hot-reload, mirrors get_phase_context()'s approach)."""
        try:
            mtime = os.path.getmtime(self.playbooks_path)
        except OSError:
            logger.warning(f"playbooks.json not found at {self.playbooks_path}")
            return []

        if self._playbooks is not None and self._mtime == mtime:
            return self._playbooks

        try:
            with open(self.playbooks_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._playbooks = data.get("playbooks", [])
            self._mtime = mtime
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Failed to load playbooks.json: {exc}")
            self._playbooks = []

        return self._playbooks

    def _matches(self, playbook: Dict[str, Any], port: int, service_name: str, observed_text: str) -> bool:
        trigger_ports = set(playbook.get("trigger_ports", []))
        trigger_obs = playbook.get("trigger_obs", "").strip().lower()

        port_match = (not trigger_ports) or (port in trigger_ports)
        if not port_match:
            return False

        if not trigger_obs:
            return True

        if trigger_obs in observed_text:
            return True

        # Check synonym phrases for this raw service_name
        for synonym in SERVICE_NAME_SYNONYMS.get(service_name.lower(), []):
            if trigger_obs == synonym:
                return True

        return False

    def _resolve_step(self, step: str, ip: str, port: int) -> str:
        resolved = step.replace("{{VETAAL_DATA_DIR}}", self.data_dir)
        # {share}/{user}/{password} are left as literal placeholders for now —
        # Vetaal doesn't yet persist discovered share names or credentials
        # the way Nightcrawler's host_memory does. A real LLM (or a future
        # credential store) is expected to fill these in before execution.
        try:
            resolved = resolved.format(
                ip=ip, port=port, share="{share}", user="{user}", password="{password}"
            )
        except (KeyError, IndexError):
            # step used a format field we don't recognize — leave as-is
            # rather than raising, so one malformed playbook doesn't break
            # the whole enumeration cycle.
            pass
        return resolved

    def get_playbook_context(
        self,
        service_name: str,
        port: int,
        ip: str = "{ip}",
        banner: str = "",
        exclude_ids: Optional[set] = None,
    ) -> str:
        """Return formatted context describing candidate playbooks for this
        service, for injection into the LLM prompt. Empty string if none
        match or playbooks.json is empty/missing. exclude_ids skips
        playbooks already attempted enough times against this host (see
        DatabaseManager.get_exhausted_playbooks)."""
        matches = self._find_matches(service_name, port, banner, exclude_ids)
        if not matches:
            return ""

        blocks = []
        for pb in matches[:3]:  # cap context size — top 3 candidates
            steps = [self._resolve_step(s, ip, port) for s in pb.get("steps", [])]
            step_lines = "\n".join(f"    - {s}" for s in steps)
            blocks.append(
                f"Playbook '{pb.get('id', 'unknown')}': {pb.get('desc', '')}\n{step_lines}"
            )

        return "\n\n".join(blocks)

    def get_top_match_id(
        self,
        service_name: str,
        port: int,
        banner: str = "",
        exclude_ids: Optional[set] = None,
    ) -> Optional[str]:
        """Return just the id of the first matching playbook (the one
        whose steps get_playbook_context lists first, and therefore the
        one LocalLLMClient's fallback picks from) — used so the
        orchestrator knows which playbook_id to record an attempt
        against after running the resulting command."""
        matches = self._find_matches(service_name, port, banner, exclude_ids)
        return matches[0]["id"] if matches else None

    def _find_matches(
        self,
        service_name: str,
        port: int,
        banner: str,
        exclude_ids: Optional[set],
    ) -> List[Dict[str, Any]]:
        playbooks = self._load()
        if not playbooks:
            return []
        exclude_ids = exclude_ids or set()
        observed_text = f"{service_name} {banner}".lower()
        return [
            pb for pb in playbooks
            if pb.get("id") not in exclude_ids
            and self._matches(pb, port, service_name, observed_text)
        ]
