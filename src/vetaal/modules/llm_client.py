"""LLM-driven (or, absent a real LLM, context-driven) next-action selection.

Tries a real OpenAI-compatible chat completion endpoint first (per
config.yaml's llm.base_url). Until the user actually runs a local model
there, that will simply be unreachable — the expected, common case — so
this falls back to deterministic logic: pick the first candidate command
out of whatever PlaybookLoader/CveDatabase context was found for this
service. This replaces the previous stub, which always returned
`curl 127.0.0.1` regardless of the real target or any matched context.
"""
import json
import logging
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("LocalLLMClient")


@dataclass
class Message:
    role: str
    content: str


@dataclass
class LLMResponse:
    content: str


class LocalLLMClient:
    """Interface for interacting with local LLM inference engines."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080/v1",
        model_name: str = "local-model",
        connect_timeout: float = 2.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.connect_timeout = connect_timeout

    async def health_check(self) -> bool:
        """Return whether a real LLM server actually answers at base_url.
        False (not an exception) whenever nothing is listening there —
        which is expected until the user configures a real local model."""
        try:
            import httpx
        except ImportError:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.connect_timeout) as client:
                resp = await client.get(f"{self.base_url}/models")
                return resp.status_code < 500
        except Exception:
            return False

    async def generate_action(
        self,
        messages: List[Any],
        playbook_context: str,
        require_json: bool = True,
        ip: str = "",
        port: int = 0,
    ) -> LLMResponse:
        llm_result = await self._try_real_llm(messages, playbook_context)
        if llm_result is not None:
            return llm_result

        fallback_cmd = self._pick_from_context(playbook_context)
        if fallback_cmd:
            return LLMResponse(content=json.dumps({"command": fallback_cmd}))

        # Nothing matched this service at all (no playbook, no CVE hit) —
        # fall back to a safe, read-only, always-informative default
        # rather than a meaningless hardcoded command: a version scan of
        # the specific port that was actually found open.
        if ip and port:
            return LLMResponse(content=json.dumps({"command": ["nmap", "-sV", "-p", str(port), ip]}))
        return LLMResponse(content=json.dumps({"command": []}))

    async def _try_real_llm(self, messages: List[Any], playbook_context: str) -> Optional[LLMResponse]:
        try:
            import httpx
        except ImportError:
            return None

        if playbook_context:
            system_prompt = (
                "You are a network enumeration assistant. Given the target "
                "and candidate commands below, respond with ONLY a JSON "
                "object of the form {\"command\": [\"arg0\", \"arg1\", ...]} "
                "— the single best next command to run, as an argv list. "
                "No prose, no markdown fences.\n\nCandidates:\n" + playbook_context
            )
        else:
            system_prompt = (
                "You are a network enumeration assistant. Respond with "
                "ONLY a JSON object of the form "
                "{\"command\": [\"arg0\", \"arg1\", ...]}. No prose."
            )

        payload_messages = [{"role": "system", "content": system_prompt}]
        for m in messages:
            if isinstance(m, dict):
                payload_messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
            else:
                payload_messages.append({"role": getattr(m, "role", "user"), "content": getattr(m, "content", str(m))})

        try:
            async with httpx.AsyncClient(timeout=self.connect_timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json={"model": self.model_name, "messages": payload_messages, "temperature": 0},
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return LLMResponse(content=content)
        except Exception:
            # No local LLM server reachable at base_url — expected/common
            # until the user actually runs one; fall through to the
            # deterministic context-based path instead of erroring.
            return None

    def _pick_from_context(self, playbook_context: str) -> Optional[List[str]]:
        """Pull the first '    - <command>' line out of playbook/CVE
        context text (as produced by PlaybookLoader/CveDatabase) and turn
        it into an argv list."""
        if not playbook_context:
            return None
        for line in playbook_context.splitlines():
            line = line.strip()
            if line.startswith("- "):
                cmd_str = line[2:].strip()
                try:
                    return shlex.split(cmd_str)
                except ValueError:
                    continue
        return None
