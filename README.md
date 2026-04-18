# WiFi Recon Scanner

> Passive WiFi reconnaissance tool for 2.4GHz networks

**Author:** Bangkit Eldhianpranata ([0xnhsec](https://github.com/0xnhsec))
**Adapter:** Ralink MT7601U (monitor mode supported)
**OS:** CachyOS / Arch Linux

## Features

- **Quick AP Scan** — List all APs with SSID, BSSID, signal, channel, encryption
- **Monitor Mode Scan** — Capture beacon frames + probe requests (see what SSIDs devices are searching for)
- **Continuous Scan** — Repeat scan every 10s, watch APs appear/disappear
- **Channel Map** — Visualize which channels are congested

## Setup

```bash
# Install dependencies
sudo pacman -S iw tcpdump aircrack-ng

# Run
sudo python3 recon.py -i wlp3s0f4u1
```

## Scan Modes

| Mode | Monitor? | What You See |
|---|---|---|
| Quick AP Scan | No | All nearby APs, signal, encryption |
| Monitor Mode | Yes | Beacon frames + probe requests from clients |
| Continuous | No | AP changes over time |
| Channel Map | No | Visual channel congestion |

## Probe Requests — Why They Matter

When your phone has WiFi on but not connected, it broadcasts
"probe requests" asking: "Is [home_wifi] nearby? Is [work_wifi] nearby?"

This reveals:
- What networks a device has connected to before
- Device MAC address (tracking)
- Movement patterns (if you know where those SSIDs are)

This is why modern phones use MAC randomization.

## Disclaimer

Educational use only. Passive scanning is legal in most jurisdictions,
but active attacks (deauth, evil twin) against networks you don't own
its Illegal use.
