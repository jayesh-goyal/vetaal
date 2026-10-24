import ipaddress
from typing import List, Dict, Any, Union

class ScopeViolationError(Exception):
    """Raised when a generated command violates defined operational scope boundaries."""
    pass

class ScopeValidator:
    """Validates generated command tokens against authorized network scopes and command whitelists."""
    def __init__(self, config: Union[str, Dict[str, Any]] = None):
        self.allowed_networks = [ipaddress.ip_network("127.0.0.0/8", strict=False)]
        self.excluded_ips = set()
        self.allowed_commands = {"curl", "nmap", "ping", "dig", "nc", "traceroute"}
        
        if isinstance(config, dict):
            self._parse_config(config)

    def _parse_config(self, config: Dict[str, Any]) -> None:
        scope_cfg = config.get("scope", config)
        if "allowed_networks" in scope_cfg:
            self.allowed_networks = [ipaddress.ip_network(n, strict=False) for n in scope_cfg["allowed_networks"]]
        if "excluded_ips" in scope_cfg:
            self.excluded_ips = set(scope_cfg["excluded_ips"])
        if "allowed_commands" in scope_cfg:
            self.allowed_commands = set(scope_cfg["allowed_commands"])

    def validate_command(self, cmd_args: List[str]) -> bool:
        if not cmd_args:
            raise ScopeViolationError("Empty command vector provided.")
        
        base_cmd = cmd_args[0]
        if base_cmd not in self.allowed_commands:
            raise ScopeViolationError(f"Command '{base_cmd}' is not permitted by scope policy.")

        for arg in cmd_args[1:]:
            try:
                addr = ipaddress.ip_address(arg)
                ip_str = str(addr)
                if ip_str in self.excluded_ips:
                    raise ScopeViolationError(f"Target IP {ip_str} is explicitly excluded in scope configuration.")
                if not any(addr in net for net in self.allowed_networks):
                    raise ScopeViolationError(f"Target IP {ip_str} falls outside allowed network ranges.")
            except ValueError:
                continue
        return True
