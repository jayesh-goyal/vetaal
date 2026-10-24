"""Local CVE -> command database, loaded from data/cve_exploits.json.

Ported from Nightcrawler's agent/cve_db.py (garagehq/nightcrawler, MIT
licensed): match a detected service+version against a curated list of
service/version-regex/CVE/detection-command entries. All "commands" in
this dataset are read-only detection/enumeration commands (nmap NSE
vulnerability scripts, auth-method probes, etc.) — not exploit payloads.

Fully offline, no network calls; loaded once and cached in memory.
"""
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CveDatabase")


class CveDatabase:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(
                Path(__file__).resolve().parents[3] / "data" / "cve_exploits.json"
            )
        self.db_path = db_path
        self._entries: Optional[List[Dict[str, Any]]] = None
        self._mtime: Optional[float] = None

    def _load(self) -> List[Dict[str, Any]]:
        import os
        try:
            mtime = os.path.getmtime(self.db_path)
        except OSError:
            logger.warning(f"cve_exploits.json not found at {self.db_path}")
            return []

        if self._entries is not None and self._mtime == mtime:
            return self._entries

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._entries = data.get("exploits", [])
            self._mtime = mtime
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Failed to load cve_exploits.json: {exc}")
            self._entries = []

        return self._entries

    def lookup(self, service: str, version: str = "") -> List[Dict[str, Any]]:
        """Return matching CVE entries for a service (+ optional version)."""
        entries = self._load()
        results = []
        svc = service.lower()
        for entry in entries:
            entry_svc = entry.get("service", "")
            if entry_svc in svc or svc in entry_svc:
                if not version:
                    results.append(entry)
                else:
                    try:
                        if re.search(entry.get("version_re", ""), version):
                            results.append(entry)
                    except re.error:
                        continue
        return results

    def get_context(self, service_name: str, banner: str, ip: str) -> str:
        """Return formatted CVE hints for injection into the LLM prompt,
        same shape as PlaybookLoader.get_playbook_context(). Extracts a
        version string from the banner when present."""
        # banner is typically "<product> <version>", e.g. "OpenSSH 8.9p1"
        version = ""
        m = re.search(r"(\d+(?:\.\d+){0,3}\S*)", banner)
        if m:
            version = m.group(1)

        matches = self.lookup(service_name, version)
        if not matches:
            return ""

        blocks = []
        for entry in matches[:3]:  # cap context size
            cmds = [c.format(ip=ip) for c in entry.get("commands", [])]
            cmd_lines = "\n".join(f"    - {c}" for c in cmds)
            blocks.append(
                f"{entry.get('cve', 'unknown CVE')} ({entry.get('severity', 'unknown')}): "
                f"{entry.get('desc', '')}\n{cmd_lines}"
            )
        return "\n\n".join(blocks)
