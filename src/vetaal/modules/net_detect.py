import socket
import ipaddress
import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional

logger = logging.getLogger("NetworkDetector")


class NetworkDetector:
    """Detects the local network environment and performs host/service
    discovery using nmap, scoped to localhost plus the machine's own
    local /24 subnet."""

    def __init__(
        self,
        excluded_ports: Optional[List[int]] = None,
        top_ports: int = 100,
        scan_timeout: float = 120.0,
    ):
        self.excluded_ports = excluded_ports or []
        self.top_ports = top_ports
        self.scan_timeout = scan_timeout

    async def detect_environment(self) -> Dict[str, str]:
        local_ip = "127.0.0.1"
        gateway = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        return {"local_ip": local_ip, "gateway": gateway}

    def _local_subnet(self, local_ip: str) -> Optional[str]:
        """Derive the /24 CIDR the machine sits on. Returns None if the
        local IP couldn't be determined (falls back to loopback only)."""
        if local_ip == "127.0.0.1":
            return None
        try:
            iface = ipaddress.ip_interface(f"{local_ip}/24")
            return str(iface.network)
        except ValueError:
            return None

    async def scan(self) -> List[Dict[str, Any]]:
        """Discover live hosts and open services. Always includes
        localhost; also sweeps the machine's own /24 subnet if one could
        be determined. Deliberately does NOT scan the full ranges allowed
        in scope_validator's config (e.g. all of 10.0.0.0/8) — only the
        subnet this machine is actually on."""
        env = await self.detect_environment()
        subnet = self._local_subnet(env["local_ip"])

        targets = ["127.0.0.1"]
        if subnet:
            targets.append(subnet)

        results: Dict[str, Dict[str, Any]] = {}
        for target in targets:
            for host in await self._nmap_scan(target):
                results[host["ip_address"]] = host

        return list(results.values())

    async def _nmap_scan(self, target: str) -> List[Dict[str, Any]]:
        cmd = [
            "nmap", "-sV", "-T4",
            "--top-ports", str(self.top_ports),
            "-oX", "-", target,
        ]
        if self.excluded_ports:
            cmd += ["--exclude-ports", ",".join(str(p) for p in self.excluded_ports)]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=self.scan_timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"nmap scan of {target} timed out after {self.scan_timeout}s")
            try:
                process.kill()
            except (ProcessLookupError, UnboundLocalError):
                pass
            return []
        except FileNotFoundError:
            logger.error("nmap binary not found on PATH; no scanning will occur.")
            return []
        except Exception as exc:
            logger.error(f"nmap scan of {target} failed: {exc}")
            return []

        if process.returncode != 0:
            logger.warning(
                f"nmap exited {process.returncode} for {target}: "
                f"{stderr_bytes[:500].decode('utf-8', errors='replace')}"
            )

        return self._parse_nmap_xml(stdout_bytes)

    def _parse_nmap_xml(self, xml_bytes: bytes) -> List[Dict[str, Any]]:
        hosts: List[Dict[str, Any]] = []
        if not xml_bytes:
            return hosts
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            logger.error(f"Failed to parse nmap XML output: {exc}")
            return hosts

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            if status_el is None or status_el.get("state") != "up":
                continue

            addr_el = host_el.find("address")
            if addr_el is None or not addr_el.get("addr"):
                continue
            ip_address = addr_el.get("addr")

            # nmap includes a SEPARATE <address addrtype="mac"> element
            # (there can be more than one <address> tag per host) when it
            # can resolve the MAC via ARP — reliably true for real devices
            # on the same local subnet when run with sufficient privileges,
            # not for loopback or hosts reached through a router hop.
            mac_address = ""
            for a in host_el.findall("address"):
                if a.get("addrtype") == "mac" and a.get("addr"):
                    # Normalize case — nmap reports MACs uppercase, scapy's
                    # passive capture reports them lowercase. Since MAC is
                    # now the database's primary key for host identity, an
                    # inconsistent case would silently fragment the same
                    # physical device into two separate host rows.
                    mac_address = a.get("addr").lower()
                    break

            os_guess = "Unknown"
            os_el = host_el.find("os")
            if os_el is not None:
                osmatch = os_el.find("osmatch")
                if osmatch is not None and osmatch.get("name"):
                    os_guess = osmatch.get("name")

            services: List[Dict[str, Any]] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    try:
                        port_num = int(port_el.get("portid"))
                    except (TypeError, ValueError):
                        continue
                    protocol = port_el.get("protocol", "tcp")

                    service_el = port_el.find("service")
                    service_name = "unknown"
                    banner = ""
                    if service_el is not None:
                        service_name = service_el.get("name", "unknown")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                        banner = f"{product} {version}".strip()

                    services.append({
                        "port": port_num,
                        "protocol": protocol,
                        "service_name": service_name,
                        "banner": banner,
                    })

            hosts.append({
                "ip_address": ip_address,
                "mac_address": mac_address,
                "os_guess": os_guess,
                "status": "active",
                "services": services,
            })

        return hosts
