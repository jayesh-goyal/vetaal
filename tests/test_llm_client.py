import json
import pytest
from vetaal.modules.llm_client import LocalLLMClient


@pytest.mark.asyncio
async def test_health_check_false_when_nothing_listening():
    """With no real LLM server running at base_url (the common/default
    case), health_check must honestly report False — not the old stub's
    unconditional True."""
    client = LocalLLMClient(base_url="http://127.0.0.1:59999/v1", connect_timeout=0.5)
    assert await client.health_check() is False


@pytest.mark.asyncio
async def test_falls_back_to_playbook_context_when_no_llm():
    """With no LLM reachable, generate_action must pick the first
    candidate command out of the given context instead of a hardcoded
    stub command."""
    client = LocalLLMClient(base_url="http://127.0.0.1:59999/v1", connect_timeout=0.5)
    context = "Playbook 'ftp_attack': FTP anonymous + default creds\n    - nxc ftp 10.0.0.5 -u anonymous -p anonymous"
    messages = [{"role": "user", "content": "Target 10.0.0.5:21 running ftp."}]
    response = await client.generate_action(messages, context, ip="10.0.0.5", port=21)
    data = json.loads(response.content)
    assert data["command"] == ["nxc", "ftp", "10.0.0.5", "-u", "anonymous", "-p", "anonymous"]


@pytest.mark.asyncio
async def test_safe_default_when_no_context_matches():
    """With no playbook/CVE context at all, fall back to a safe,
    read-only version scan of the specific port rather than nothing."""
    client = LocalLLMClient(base_url="http://127.0.0.1:59999/v1", connect_timeout=0.5)
    messages = [{"role": "user", "content": "Target 10.0.0.9:9999 running unknown."}]
    response = await client.generate_action(messages, "", ip="10.0.0.9", port=9999)
    data = json.loads(response.content)
    assert data["command"] == ["nmap", "-sV", "-p", "9999", "10.0.0.9"]
