import pytest
from vetaal.modules.net_detect import NetworkDetector

@pytest.mark.asyncio
async def test_network_detector():
    detector = NetworkDetector()
    env = await detector.detect_environment()
    assert "local_ip" in env


def test_parse_nmap_xml_extracts_mac_address():
    detector = NetworkDetector()
    xml = b"""<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="10.0.0.42" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Raspberry Pi"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9"/>
</port>
</ports>
</host>
</nmaprun>"""
    hosts = detector._parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0]["ip_address"] == "10.0.0.42"
    assert hosts[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"


def test_parse_nmap_xml_empty_mac_when_absent():
    """Loopback / hosts reached through a router hop won't have a MAC in
    the XML — must not crash, mac_address should just be empty."""
    detector = NetworkDetector()
    xml = b"""<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports></ports>
</host>
</nmaprun>"""
    hosts = detector._parse_nmap_xml(xml)
    assert hosts[0]["mac_address"] == ""
