"""Passive network discovery via ARP observation. Never sends anything —
only listens to broadcast traffic devices are already sending on the
network — a strictly passive complement to net_detect.py's active nmap
scanning. Requires raw socket access (root, or CAP_NET_RAW) to actually
capture; degrades gracefully (logs a warning, does nothing) when that
isn't available, rather than crashing the rest of the app.

The packet-parsing logic is kept as plain functions/methods separate
from the live scapy sniffer specifically so it can be unit tested with
lightweight fake packet objects, with no root privileges or real network
interface required.
"""
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("PassiveCapture")


class PassiveCapture:
    def __init__(
        self,
        interface: Optional[str] = None,
        on_host_seen: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.interface = interface
        self.on_host_seen = on_host_seen
        self._sniffer = None
        self._seen: Dict[str, Dict[str, Any]] = {}  # keyed by MAC address
        self._running = False

    @staticmethod
    def parse_arp_packet(pkt: Any) -> Optional[Dict[str, Any]]:
        """Extract {ip_address, mac_address, ...} from a scapy ARP packet.
        Returns None for anything that isn't a usable ARP announcement."""
        arp_layer = None
        try:
            if hasattr(pkt, "haslayer") and pkt.haslayer("ARP"):
                arp_layer = pkt.getlayer("ARP")
        except Exception:
            arp_layer = None
        if arp_layer is None:
            return None

        ip = getattr(arp_layer, "psrc", None)
        mac = getattr(arp_layer, "hwsrc", None)
        if mac:
            mac = mac.lower()  # normalize — see net_detect.py's matching comment
        if not ip or not mac or ip == "0.0.0.0":
            return None

        return {
            "ip_address": ip,
            "mac_address": mac,
            "os_guess": "Unknown",
            "status": "active",
            "source": "passive",
        }

    def _handle_packet(self, pkt: Any) -> None:
        result = self.parse_arp_packet(pkt)
        if result is None:
            return
        key = result["mac_address"]
        if key in self._seen:
            return  # already reported this device this session — avoid callback spam
        self._seen[key] = result
        logger.info(f"Passive discovery: new device {result['ip_address']} ({key})")
        if self.on_host_seen:
            try:
                self.on_host_seen(result)
            except Exception as exc:
                logger.error(f"passive discovery on_host_seen callback failed: {exc}")

    def start(self) -> bool:
        """Start background ARP sniffing. Returns True if it actually
        started, False if it couldn't (scapy missing, no permissions,
        etc) — callers should treat False as 'passive discovery
        unavailable this run', not a fatal error; active scanning still
        works either way."""
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            logger.warning("scapy not installed — passive discovery disabled.")
            return False

        try:
            kwargs: Dict[str, Any] = {"filter": "arp", "prn": self._handle_packet, "store": False}
            if self.interface:
                kwargs["iface"] = self.interface
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self._running = True
            logger.info("Passive discovery started (ARP).")
            return True
        except PermissionError:
            logger.warning(
                "Passive discovery needs raw socket access — run with sudo "
                "or grant the python binary CAP_NET_RAW. Skipping; active "
                "nmap-based scanning is unaffected."
            )
            return False
        except Exception as exc:
            logger.warning(f"Passive discovery failed to start: {exc}")
            return False

    def stop(self) -> None:
        if self._sniffer and self._running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self._running = False

    def get_discovered_hosts(self) -> List[Dict[str, Any]]:
        return list(self._seen.values())
