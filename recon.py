#!/usr/bin/env python3
"""
WiFi Recon Scanner — Passive WiFi Reconnaissance Tool
Author:  Bangkit Eldhianpranata (0xnhsec)
License: Educational use only

Requires: root privileges, aircrack-ng suite
Usage:    sudo python3 recon.py -i wlp3s0f4u1
"""

import subprocess
import sys
import os
import signal
import time
import argparse
import re
import select
from datetime import datetime
from collections import defaultdict

# ============================================
#  Colors
# ============================================
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ============================================
#  Globals
# ============================================
IFACE = None
MON_IFACE = None
original_mode = "managed"
running = True

def signal_handler(sig, frame):
    global running
    running = False
    print(f"\n{C.YELLOW}[!] Interrupt received, cleaning up...{C.RESET}")

signal.signal(signal.SIGINT, signal_handler)

# ============================================
#  Helper Functions
# ============================================
def run(cmd, check=False):
    """Run shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=30
        )
        if check and result.returncode != 0:
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return None

def check_root():
    if os.geteuid() != 0:
        print(f"{C.RED}[!] This tool requires root privileges.")
        print(f"    Run: sudo python3 recon.py -i <interface>{C.RESET}")
        sys.exit(1)

def check_deps():
    """Check if required tools are installed."""
    missing = []
    for tool in ["iw", "ip", "tcpdump"]:
        if not run(f"which {tool}"):
            missing.append(tool)
    if missing:
        print(f"{C.RED}[!] Missing tools: {', '.join(missing)}")
        print(f"    Install: sudo pacman -S iw tcpdump{C.RESET}")
        sys.exit(1)

def banner():
    # RGB Colors
    c1 = "\033[38;2;0;255;255m"   # Cyan
    c2 = "\033[38;2;85;170;255m"  # Sky Blue
    c3 = "\033[38;2;170;85;255m"  # Purple
    c4 = "\033[38;2;255;0;255m"   # Magenta

    print(f"""
{c1}▗▖    ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▄▖ ▗▄▄▄▖▗▖  ▗▖
{c2}▐▌   ▐▌ ▐▌▐▌ ▐▌  █  ▐▌ ▐▌  █   ▝▚▞▘ 
{c3}▐▌   ▐▌ ▐▌▐▌ ▐▌  █  ▐▛▀▚▖  █    ▐▌  
{c4}▐▙▄▄▖▝▚▄▞▘▐▙█▟▌  █  ▐▌ ▐▌▗▄█▄▖▗▞▘▝▚▖
{C.RESET}
     Author: Bangkit (0xnhsec)
     >> Basic Scanner with (Matrix - wlp3s0f4u1) <<
""")

# ============================================
#  Monitor Mode Management
# ============================================
def enable_monitor(iface):
    """Put interface into monitor mode."""
    global MON_IFACE

    print(f"{C.BLUE}[*] Enabling monitor mode on {iface}...{C.RESET}")

    # Pure manual — no airmon-ng
    run(f"ip link set {iface} down")
    time.sleep(0.5)
    run(f"iw dev {iface} set type monitor")
    time.sleep(0.5)
    run(f"ip link set {iface} up")
    time.sleep(1)

    # Verify
    mode_check = run(f"iw dev {iface} info | grep type")
    if mode_check and "monitor" in mode_check:
        MON_IFACE = iface
        print(f"{C.GREEN}[+] Monitor mode: {MON_IFACE}{C.RESET}")
        return True

    print(f"{C.RED}[!] Failed to enable monitor mode{C.RESET}")
    return False

def disable_monitor():
    """Restore interface to managed mode."""
    iface = MON_IFACE or IFACE
    if not iface:
        return

    print(f"\n{C.BLUE}[*] Restoring {iface} to managed mode...{C.RESET}")

    run(f"ip link set {iface} down")
    time.sleep(0.5)
    run(f"iw dev {iface} set type managed")
    time.sleep(0.5)
    run(f"ip link set {iface} up")
    time.sleep(1)

    print(f"{C.GREEN}[+] Interface restored{C.RESET}")

# ============================================
#  Channel Hopper
# ============================================
def hop_channel(iface, channel):
    """Switch to specific channel."""
    run(f"iw dev {iface} set channel {channel} 2>/dev/null")

# ============================================
#  Scan Mode 1: Quick AP Scan (iw based)
# ============================================
def scan_aps_managed(iface):
    """Scan APs using iw scan (managed mode, no monitor needed)."""
    print(f"{C.BLUE}[*] Scanning APs on {iface} (managed mode)...{C.RESET}")
    print(f"{C.DIM}    This takes a few seconds...{C.RESET}")

    raw = run(f"iw dev {iface} scan 2>/dev/null")
    if not raw:
        print(f"{C.RED}[!] Scan failed. Interface might be busy.{C.RESET}")
        return []

    aps = []
    current = {}

    for line in raw.split('\n'):
        line = line.strip()

        if line.startswith("BSS "):
            if current:
                aps.append(current)
            bssid = line.split('(')[0].replace("BSS ", "").strip()
            current = {
                "bssid": bssid,
                "ssid": "",
                "signal": 0,
                "freq": 0,
                "channel": 0,
                "encryption": "OPEN"
            }

        elif line.startswith("SSID:"):
            current["ssid"] = line.replace("SSID:", "").strip()

        elif line.startswith("signal:"):
            try:
                current["signal"] = float(line.split(":")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass

        elif line.startswith("freq:"):
            try:
                current["freq"] = int(float(line.split(":")[1].strip()))
                # Convert freq to channel
                freq = current["freq"]
                if 2412 <= freq <= 2484:
                    current["channel"] = (freq - 2407) // 5
                elif freq == 2484:
                    current["channel"] = 14
            except (ValueError, IndexError):
                pass

        elif "WPA" in line:
            current["encryption"] = "WPA"
        elif "RSN" in line or "WPA2" in line:
            current["encryption"] = "WPA2"
        elif "WEP" in line:
            current["encryption"] = "WEP"

    if current:
        aps.append(current)

    return aps

# ============================================
#  Scan Mode 2: Monitor Mode Packet Capture
# ============================================
def capture_packets(iface, duration=15):
    """Capture beacon frames and probe requests using tcpdump."""
    print(f"{C.BLUE}[*] Capturing packets on {iface} for {duration}s...{C.RESET}")
    print(f"{C.DIM}    Channel hopping active — Ctrl+C to stop early{C.RESET}\n")

    aps = {}
    clients = {}
    channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    ch_idx = 0

    # Capture all 802.11 management frames; stderr saved for diagnosis
    tcpdump_cmd = (
        f"tcpdump -i {iface} -e -l -n type mgt 2>/tmp/tcpdump_err.txt"
    )

    try:
        proc = subprocess.Popen(
            tcpdump_cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1
        )

        # Give tcpdump a moment to initialise
        time.sleep(0.8)

        if proc.poll() is not None:
            try:
                with open("/tmp/tcpdump_err.txt") as f:
                    err = f.read().strip()
            except OSError:
                err = "unknown error"
            print(f"{C.RED}[!] tcpdump failed to start: {err}{C.RESET}")
            return {}, {}

        start_time = time.time()
        last_hop   = start_time

        while running and (time.time() - start_time) < duration:
            now     = time.time()
            elapsed = int(now - start_time)

            # Channel hop every 0.5s
            if now - last_hop >= 0.5:
                ch_idx = (ch_idx + 1) % len(channels)
                hop_channel(iface, channels[ch_idx])
                last_hop = now
                print(
                    f"\r{C.DIM}  [{elapsed:>3}s/{duration}s] "
                    f"CH:{channels[ch_idx]:>2} | "
                    f"APs:{len(aps):>3} | "
                    f"Clients:{len(clients):>3}{C.RESET}  ",
                    end="", flush=True
                )

            # Non-blocking read — 0.1s timeout so channel hop stays on schedule
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if not ready:
                continue

            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            # Current channel (best estimate)
            ch = channels[ch_idx]
            freq_match = re.search(r'(\d{4})\s*MHz', line)
            if freq_match:
                freq = int(freq_match.group(1))
                if 2412 <= freq <= 2484:
                    ch = (freq - 2407) // 5

            # Signal strength (radiotap annotation)
            signal = 0
            sig_match = re.search(r'(-\d+)dBm', line)
            if sig_match:
                signal = int(sig_match.group(1))

            # Beacon frames
            if "Beacon" in line:
                bssid_match = re.search(r'BSSID:([\da-f]{2}(?::[\da-f]{2}){5})', line, re.I)
                ssid_match  = re.search(r'Beacon \((.+?)\)', line)

                if bssid_match:
                    bssid = bssid_match.group(1).lower()
                    ssid  = ssid_match.group(1) if ssid_match else "<hidden>"

                    if bssid not in aps:
                        aps[bssid] = {"ssid": ssid, "signal": signal, "channel": ch, "count": 0}
                    aps[bssid]["count"] += 1
                    if signal and (signal > aps[bssid]["signal"] or aps[bssid]["signal"] == 0):
                        aps[bssid]["signal"] = signal

            # Probe requests
            elif "Probe Request" in line:
                mac_match  = re.search(r'SA:([\da-f]{2}(?::[\da-f]{2}){5})', line, re.I)
                ssid_match = re.search(r'Probe Request \((.+?)\)', line)

                if mac_match:
                    client_mac = mac_match.group(1).lower()
                    probe_ssid = ssid_match.group(1) if ssid_match else "broadcast"

                    if client_mac not in clients:
                        clients[client_mac] = {"probes": set()}
                    clients[client_mac]["probes"].add(probe_ssid)

        print()  # newline after progress line

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

        if not aps and not clients:
            try:
                with open("/tmp/tcpdump_err.txt") as f:
                    err = f.read().strip()
                if err:
                    print(f"{C.YELLOW}[!] tcpdump stderr: {err[:300]}{C.RESET}")
            except OSError:
                pass
            print(f"{C.YELLOW}[!] No packets captured. Possible causes:{C.RESET}")
            print(f"{C.DIM}    • Interface not fully in monitor mode")
            print(f"    • Driver does not support monitor mode")
            print(f"    • Run: iw dev {iface} info   (verify 'type monitor'){C.RESET}")

    except Exception as e:
        print(f"{C.RED}[!] Capture error: {e}{C.RESET}")

    return aps, clients

# ============================================
#  Display Functions
# ============================================
def display_aps(aps_list):
    """Display Access Points in a table."""
    if not aps_list:
        print(f"{C.YELLOW}[!] No APs found{C.RESET}")
        return

    # Sort by signal strength (strongest first)
    aps_list.sort(key=lambda x: x.get("signal", -100), reverse=True)

    print()
    print(f"{C.BOLD}{C.CYAN}{'═' * 85}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ACCESS POINTS DETECTED: {len(aps_list)}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 85}{C.RESET}")
    print(f"{C.BOLD}  {'BSSID':<20} {'SSID':<25} {'SIG':>5} {'CH':>4} {'FREQ':>6} {'ENC':<8}{C.RESET}")
    print(f"  {'─' * 78}")

    for ap in aps_list:
        ssid = ap.get("ssid", "") or "<hidden>"
        signal = ap.get("signal", 0)
        bssid = ap.get("bssid", "??:??:??:??:??:??")
        ch = ap.get("channel", 0)
        freq = ap.get("freq", 0)
        enc = ap.get("encryption", "???")

        # Color signal strength
        if signal > -50:
            sig_color = C.GREEN
            sig_bar = "████"
        elif signal > -65:
            sig_color = C.GREEN
            sig_bar = "███░"
        elif signal > -75:
            sig_color = C.YELLOW
            sig_bar = "██░░"
        elif signal > -85:
            sig_color = C.RED
            sig_bar = "█░░░"
        else:
            sig_color = C.RED
            sig_bar = "░░░░"

        # Color encryption
        if enc == "OPEN":
            enc_color = C.RED
        elif enc == "WEP":
            enc_color = C.YELLOW
        else:
            enc_color = C.GREEN

        print(f"  {C.DIM}{bssid:<20}{C.RESET} "
              f"{C.WHITE}{ssid:<25}{C.RESET} "
              f"{sig_color}{signal:>5.0f}{C.RESET} "
              f"{C.WHITE}{ch:>4}{C.RESET} "
              f"{C.DIM}{freq:>6}{C.RESET} "
              f"{enc_color}{enc:<8}{C.RESET} "
              f"{sig_color}{sig_bar}{C.RESET}")

    print(f"  {'─' * 78}")
    print()

def display_monitor_results(aps, clients):
    """Display results from monitor mode capture."""
    if not aps and not clients:
        print(f"{C.YELLOW}[!] No results to display{C.RESET}")
        return

    if aps:
        print()
        print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  BEACONS CAPTURED: {len(aps)} APs{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}  {'BSSID':<20} {'SSID':<25} {'SIG':>5} {'CH':>4} {'BEACONS':>8}{C.RESET}")
        print(f"  {'─' * 65}")

        for bssid, info in sorted(aps.items(), key=lambda x: x[1]["count"], reverse=True):
            sig = info.get('signal', 0)
            sig_str = f"{sig}" if sig != 0 else "?"
            print(f"  {C.DIM}{bssid:<20}{C.RESET} "
                  f"{C.WHITE}{info['ssid']:<25}{C.RESET} "
                  f"{C.YELLOW}{sig_str:>5}{C.RESET} "
                  f"{C.CYAN}{info['channel']:>4}{C.RESET} "
                  f"{C.GREEN}{info['count']:>8}{C.RESET}")

        print(f"  {'─' * 65}")

    if clients:
        print()
        print(f"{C.BOLD}{C.MAGENTA}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}{C.MAGENTA}  PROBE REQUESTS: {len(clients)} Clients{C.RESET}")
        print(f"{C.BOLD}{C.MAGENTA}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}  {'CLIENT MAC':<20} {'PROBING FOR':<48}{C.RESET}")
        print(f"  {'─' * 65}")

        for mac, info in clients.items():
            probes = ", ".join(info["probes"])
            print(f"  {C.DIM}{mac:<20}{C.RESET} "
                  f"{C.YELLOW}{probes:<48}{C.RESET}")

        print(f"  {'─' * 65}")
        print()

def display_channel_map(aps_list):
    """Show channel usage visualization."""
    if not aps_list:
        return

    channels = defaultdict(list)
    for ap in aps_list:
        ch = ap.get("channel", 0)
        if ch > 0:
            channels[ch].append(ap)

    print(f"{C.BOLD}{C.CYAN}{'═' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  CHANNEL MAP (2.4GHz){C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 60}{C.RESET}")

    max_count = max(len(v) for v in channels.values()) if channels else 1

    # Bar chart
    for row in range(max_count, 0, -1):
        line = "  "
        for ch in range(1, 14):
            if ch in channels and len(channels[ch]) >= row:
                line += f" {C.GREEN}██{C.RESET}"
            else:
                line += f" {C.DIM}░░{C.RESET}"
        print(line)

    # Channel labels
    print(f"  {C.BOLD}", end="")
    for ch in range(1, 14):
        print(f" {ch:>2}", end="")
    print(f"{C.RESET}")
    print(f"  {C.DIM}  Channel numbers (2.4GHz band){C.RESET}")

    # List APs per channel
    print()
    for ch in sorted(channels.keys()):
        ssids = [ap.get("ssid", "?") or "<hidden>" for ap in channels[ch]]
        print(f"  {C.CYAN}CH {ch:>2}:{C.RESET} {', '.join(ssids)}")

    print()

# ============================================
#  Main Menu
# ============================================
def main():
    global IFACE, running

    parser = argparse.ArgumentParser(
        description="WiFi Recon Scanner — Passive WiFi Reconnaissance"
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="WiFi interface (e.g., wlp3s0f4u1)")
    args = parser.parse_args()

    IFACE = args.interface
    check_root()
    check_deps()
    banner()

    print(f"{C.GREEN}[+] Interface: {IFACE}{C.RESET}")
    print(f"{C.GREEN}[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print()

    while running:
        print(f"{C.BOLD}Select scan mode:{C.RESET}")
        print(f"  {C.CYAN}[1]{C.RESET} Quick AP Scan       — List all nearby APs (no monitor mode)")
        print(f"  {C.CYAN}[2]{C.RESET} Monitor Mode Scan   — Capture beacons + probe requests")
        print(f"  {C.CYAN}[3]{C.RESET} Continuous Scan     — Repeat quick scan every 10s")
        print(f"  {C.CYAN}[4]{C.RESET} Channel Map         — Visualize channel usage")
        print(f"  {C.CYAN}[q]{C.RESET} Quit")
        print()

        try:
            choice = input(f"{C.BOLD}> {C.RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            aps = scan_aps_managed(IFACE)
            display_aps(aps)

        elif choice == "2":
            if enable_monitor(IFACE):
                try:
                    aps, clients = capture_packets(MON_IFACE)
                    display_monitor_results(aps, clients)
                finally:
                    disable_monitor()
            else:
                print(f"{C.RED}[!] Could not enable monitor mode{C.RESET}")
                print(f"{C.YELLOW}    Try: sudo airmon-ng start {IFACE}{C.RESET}")

        elif choice == "3":
            print(f"{C.BLUE}[*] Continuous scan (Ctrl+C to stop)...{C.RESET}")
            scan_num = 0
            while running:
                scan_num += 1
                print(f"\n{C.DIM}── Scan #{scan_num} @ "
                      f"{datetime.now().strftime('%H:%M:%S')} ──{C.RESET}")
                aps = scan_aps_managed(IFACE)
                display_aps(aps)
                for _ in range(100):  # 10s sleep, interruptible
                    if not running:
                        break
                    time.sleep(0.1)
            running = True  # reset for menu

        elif choice == "4":
            aps = scan_aps_managed(IFACE)
            display_aps(aps)
            display_channel_map(aps)

        elif choice in ("q", "quit", "exit"):
            break

        else:
            print(f"{C.YELLOW}[!] Invalid choice{C.RESET}")

    print(f"\n{C.GREEN}[+] Done. Stay curious.{C.RESET}")

if __name__ == "__main__":
    main()
