from typing import Dict, Any

class OutputParser:
    """Parses tool output into structured audit telemetries."""
    def parse_banner(self, stdout: str, port: int = 0) -> Dict[str, Any]:
        banner = stdout.strip().splitlines()
        first_line = banner[0] if banner else "unknown"
        return {
            "port": port,
            "protocol": "tcp",
            "service_name": "http" if port in (80, 443, 8080) else "unknown",
            "banner": first_line
        }
