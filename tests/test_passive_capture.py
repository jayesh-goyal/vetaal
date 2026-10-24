import pytest
from unittest.mock import MagicMock, patch

from vetaal.modules.passive_capture import PassiveCapture


def test_parse_real_arp_packet_extracts_ip_and_mac():
    from scapy.layers.l2 import ARP
    pkt = ARP(op=2, psrc="10.0.0.42", hwsrc="aa:bb:cc:dd:ee:ff")
    result = PassiveCapture.parse_arp_packet(pkt)
    assert result is not None
    assert result["ip_address"] == "10.0.0.42"
    assert result["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert result["source"] == "passive"


def test_parse_non_arp_packet_returns_none():
    from scapy.layers.inet import IP, TCP
    pkt = IP(dst="10.0.0.1") / TCP(dport=80)
    assert PassiveCapture.parse_arp_packet(pkt) is None


def test_parse_arp_with_zero_ip_returns_none():
    """0.0.0.0 shows up in ARP probes (a device checking for IP conflicts
    before it has an address yet) — not a usable discovery."""
    from scapy.layers.l2 import ARP
    pkt = ARP(op=1, psrc="0.0.0.0", hwsrc="aa:bb:cc:dd:ee:ff")
    assert PassiveCapture.parse_arp_packet(pkt) is None


def test_handle_packet_dedupes_by_mac_and_fires_callback_once():
    from scapy.layers.l2 import ARP
    seen = []
    capture = PassiveCapture(on_host_seen=lambda h: seen.append(h))

    pkt1 = ARP(op=2, psrc="10.0.0.42", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = ARP(op=2, psrc="10.0.0.42", hwsrc="aa:bb:cc:dd:ee:ff")  # same device again
    capture._handle_packet(pkt1)
    capture._handle_packet(pkt2)

    assert len(seen) == 1  # callback only fires once per newly-seen device
    assert len(capture.get_discovered_hosts()) == 1


def test_handle_packet_reports_different_devices_separately():
    from scapy.layers.l2 import ARP
    seen = []
    capture = PassiveCapture(on_host_seen=lambda h: seen.append(h))
    capture._handle_packet(ARP(op=2, psrc="10.0.0.42", hwsrc="aa:bb:cc:dd:ee:ff"))
    capture._handle_packet(ARP(op=2, psrc="10.0.0.43", hwsrc="11:22:33:44:55:66"))
    assert len(seen) == 2
    ips = {h["ip_address"] for h in capture.get_discovered_hosts()}
    assert ips == {"10.0.0.42", "10.0.0.43"}


def test_callback_exception_does_not_crash_capture():
    from scapy.layers.l2 import ARP

    def bad_callback(_host):
        raise RuntimeError("db write failed")

    capture = PassiveCapture(on_host_seen=bad_callback)
    # Must not raise, even though the callback throws
    capture._handle_packet(ARP(op=2, psrc="10.0.0.42", hwsrc="aa:bb:cc:dd:ee:ff"))
    assert len(capture.get_discovered_hosts()) == 1


def test_start_returns_false_gracefully_when_scapy_missing():
    capture = PassiveCapture()
    with patch.dict("sys.modules", {"scapy.all": None}):
        # Simulate scapy not being importable at all
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all" or name.startswith("scapy"):
                raise ImportError("no module named scapy")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            assert capture.start() is False


def test_start_returns_false_on_permission_error():
    capture = PassiveCapture()
    with patch("scapy.all.AsyncSniffer", side_effect=PermissionError("Operation not permitted")):
        assert capture.start() is False


def test_stop_is_safe_even_if_never_started():
    capture = PassiveCapture()
    capture.stop()  # must not raise
