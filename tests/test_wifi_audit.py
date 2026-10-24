import asyncio
import os
import pytest
from unittest.mock import AsyncMock, patch, mock_open
from src.vetaal.modules.wifi_audit import WirelessAuditor, AccessPoint

@pytest.fixture
def auditor():
    return WirelessAuditor(interface="wlan0")

@pytest.mark.asyncio
@patch('src.vetaal.modules.wifi_audit.sys.platform', 'linux')
async def test_enable_monitor_mode_success(auditor):
    """Verify monitor mode transition and regex extraction of the new interface name."""
    mock_stdout = "(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)"
    
    with patch.object(auditor, '_run_command', new_callable=AsyncMock) as mock_run:
        # Mock `check kill` success
        # Mock `airmon-ng start` success
        mock_run.side_effect = [
            (0, "killed processes", ""), 
            (0, mock_stdout, "")
        ]
        
        monitor_iface = await auditor.enable_monitor_mode()
        
        assert monitor_iface == "wlan0mon"
        assert mock_run.call_count == 2
        mock_run.assert_any_call("airmon-ng start wlan0")

@pytest.mark.asyncio
async def test_enable_monitor_mode_fallback(auditor):
    """Verify fallback behavior if the regex fails to match standard output."""
    with patch.object(auditor, '_run_command', new_callable=AsyncMock) as mock_run:
        mock_run.side_effect = [
            (0, "killed processes", ""), 
            (0, "Unexpected output format here", "")
        ]
        
        monitor_iface = await auditor.enable_monitor_mode()
        
        # Should fallback to base + 'mon'
        assert monitor_iface == "wlan0mon"

@pytest.mark.asyncio
async def test_scan_access_points_timeout_and_parsing(auditor):
    """
    Verify that the orchestrator safely terminates the endless airodump-ng 
    process via timeout, and successfully parses the resulting CSV file.
    """
    csv_data = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, 2026-09-24 02:45:30, 2026-09-24 02:45:45,  1,   54, WPA2 WPA3, CCMP, MGT, -45,       10,        0,  0.  0.  0.  0,  12, EnterpriseCorp,\n"
        "11:22:33:44:55:66, 2026-09-24 02:45:30, 2026-09-24 02:45:45, 11,   54, OPN, , , -70,       5,        0,  0.  0.  0.  0,   9, GuestWiFi,\n"
        "\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "99:88:77:66:55:44, 2026-09-24 02:45:30, 2026-09-24 02:45:45, -55, 12, AA:BB:CC:DD:EE:FF,\n"
    )

    with patch.object(auditor, '_run_command', new_callable=AsyncMock) as mock_run:
        # We simulate the subprocess completing (or timing out and being caught internally)
        mock_run.return_value = (0, "", "")
        
        # Mock file existence checks and file reading
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=csv_data)):
                aps = await auditor.scan_access_points(monitor_interface="wlan0mon", timeout=2)
                
                assert len(aps) == 2
                
                # Check Enterprise WPA3 Network
                assert aps[0].bssid == "AA:BB:CC:DD:EE:FF"
                assert aps[0].essid == "EnterpriseCorp"
                assert aps[0].channel == 1
                assert aps[0].signal_level == -45
                assert aps[0].encryption == "WPA2 WPA3"
                assert aps[0].auth == "MGT"
                
                # Check Open Network
                assert aps[1].bssid == "11:22:33:44:55:66"
                assert aps[1].encryption == "OPN"
                
                # Ensure the dataclass serialization works for the orchestrator payload
                payload = aps[0].to_dict()
                assert isinstance(payload, dict)
                assert payload["bssid"] == "AA:BB:CC:DD:EE:FF"

@pytest.mark.asyncio
async def test_disable_monitor_mode(auditor):
    """Verify monitor mode tear-down sequences."""
    with patch.object(auditor, '_run_command', new_callable=AsyncMock) as mock_run:
        mock_run.return_value = (0, "", "")
        
        await auditor.disable_monitor_mode("wlan0mon")
        
        assert mock_run.call_count == 2
        mock_run.assert_any_call("airmon-ng stop wlan0mon")
        mock_run.assert_any_call("systemctl restart NetworkManager")
