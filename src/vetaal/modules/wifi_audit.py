import asyncio
import csv
import logging
import os
import re
import shlex
import signal
import sys
import tempfile
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

@dataclass
class AccessPoint:
    """Structured, JSON-serializable representation of a discovered wireless network."""
    bssid: str
    essid: str
    channel: int
    signal_level: int
    encryption: str
    cipher: str
    auth: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WirelessAuditor:
    """
    Asynchronous Air-Interface Security Auditor for Enterprise Compliance.
    Handles interface state transitions and parsing of wireless spectrum data.
    """

    def __init__(self, interface: str) -> None:
        self.base_interface = interface
        # Ensure execution is limited to POSIX systems where these utilities exist
        if sys.platform == 'win32':
            logger.warning("Wireless auditing utilities (airmon-ng, airodump-ng) are native to Linux.")

    async def _run_command(self, cmd: str, timeout: Optional[float] = None) -> tuple[int, str, str]:
        """Executes a subprocess asynchronously with process group isolation."""
        cmd_args = shlex.split(cmd)
        kwargs: Dict[str, Any] = {
            'stdout': asyncio.subprocess.PIPE,
            'stderr': asyncio.subprocess.PIPE
        }
        
        if sys.platform != 'win32':
            kwargs['preexec_fn'] = os.setsid

        logger.debug(f"Executing: {cmd}")
        process = await asyncio.create_subprocess_exec(*cmd_args, **kwargs)

        try:
            if timeout:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            else:
                stdout, stderr = await process.communicate()
        except asyncio.TimeoutError:
            logger.debug(f"Command '{cmd}' reached timeout of {timeout}s. Terminating process group.")
            if sys.platform != 'win32':
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
            
            # Wait for process to clean up after kill signal
            stdout, stderr = await process.communicate()

        return process.returncode or 0, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore')

    async def enable_monitor_mode(self) -> str:
        """
        Transitions the designated wireless interface into monitor mode.
        Returns the name of the newly created monitor interface.
        """
        logger.info(f"Attempting to enable monitor mode on {self.base_interface}")
        
        # Kill potentially interfering processes (wpa_supplicant, NetworkManager)
        await self._run_command("airmon-ng check kill")
        
        returncode, stdout, stderr = await self._run_command(f"airmon-ng start {self.base_interface}")
        
        if returncode != 0:
            logger.error(f"Failed to enable monitor mode on {self.base_interface}: {stderr}")
            raise RuntimeError(f"airmon-ng failed: {stderr}")

        # Extract the new monitor interface name (e.g., wlan0mon) from standard output
        # Match patterns like: (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
        # or: monitor mode enabled on mon0
        match = re.search(r'monitor mode (?:vif )?enabled (?:for .*? )?on (?:\[phy\d+\])?(\w+)', stdout, re.IGNORECASE)
        if match:
            monitor_iface = match.group(1)
            logger.info(f"Monitor mode enabled successfully on interface: {monitor_iface}")
            return monitor_iface
        
        # Fallback heuristic: often it appends 'mon' to the base interface
        fallback_iface = f"{self.base_interface}mon"
        logger.warning(f"Could not explicitly parse monitor interface name. Assuming fallback: {fallback_iface}")
        return fallback_iface

    async def disable_monitor_mode(self, monitor_interface: str) -> None:
        """Restores the interface to managed mode and restarts network services."""
        logger.info(f"Disabling monitor mode on {monitor_interface}")
        await self._run_command(f"airmon-ng stop {monitor_interface}")
        
        # Best-effort restoration of network services disrupted by `check kill`
        await self._run_command("systemctl restart NetworkManager")

    async def scan_access_points(self, monitor_interface: str, timeout: int = 15) -> List[AccessPoint]:
        """
        Initiates an asynchronous packet capture to discover and parse 
        802.11 beacons and probe responses.
        """
        logger.info(f"Starting wireless scan on {monitor_interface} for {timeout} seconds.")
        
        discovered_aps: List[AccessPoint] = []
        
        # Use a temporary directory for the packet capture files
        with tempfile.TemporaryDirectory() as tmpdir:
            output_prefix = os.path.join(tmpdir, "audit_scan")
            
            # airodump-ng runs indefinitely; we rely on the AsyncCommandExecutor timeout to halt it
            cmd = f"airodump-ng --output-format csv -w {output_prefix} {monitor_interface}"
            await self._run_command(cmd, timeout=float(timeout))
            
            # airodump-ng appends '-01' to the first execution prefix
            csv_target = f"{output_prefix}-01.csv"
            
            if not os.path.exists(csv_target):
                logger.error("Scan failed: airodump-ng did not generate the expected CSV output.")
                return discovered_aps

            discovered_aps = self._parse_airodump_csv(csv_target)
            
        logger.info(f"Scan complete. Discovered {len(discovered_aps)} access points.")
        return discovered_aps

    def _parse_airodump_csv(self, file_path: str) -> List[AccessPoint]:
        """Parses the specialized CSV format generated by airodump-ng."""
        aps = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row or len(row) < 14:
                        continue
                    
                    bssid = row[0].strip()
                    if bssid == 'BSSID':
                        continue
                    if bssid == 'Station MAC':
                        break  # End of AP section; beginning of client stations section

                    try:
                        channel = int(row[3].strip()) if row[3].strip().isdigit() else 0
                        power = int(row[8].strip()) if row[8].strip().lstrip('-').isdigit() else 0
                        
                        ap = AccessPoint(
                            bssid=bssid,
                            essid=row[13].strip(),
                            channel=channel,
                            signal_level=power,
                            encryption=row[5].strip(),
                            cipher=row[6].strip(),
                            auth=row[7].strip()
                        )
                        aps.append(ap)
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Skipping malformed row in scan data: {row}. Error: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to parse airodump-ng results: {e}")
            
        return aps
