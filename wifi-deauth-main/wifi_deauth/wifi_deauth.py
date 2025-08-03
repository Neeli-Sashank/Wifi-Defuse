#!/usr/bin/env python3

import os
import sys  # leave it
import signal
import logging
import argparse
import threading  # leave it

from typing import Dict, Generator, List, Union
from collections import defaultdict
import copy
import traceback

from scapy.layers.dot11 import (
    RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp,
    Dot11AssoResp, Dot11QoS, Dot11Deauth, Dot11
)
from scapy.all import *
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

try:
    from .utils import *
except ImportError:
    from utils import *

conf.verb = 0

# =====================[ BANNER ]=====================
BANNER = r"""
 __        ___ _  _____   ____        __
 \ \      / (_) ||  ___| |  _ \  ___ / _| ___  ___
  \ \ /\ / /| | || |_    | | | |/ _ \ |_ / _ \/ _ \
   \ V  V / | | ||  _|   | |_| |  __/  _|  __/  __/
    \_/\_/  |_|_||_|     |____/ \___|_|  \___|\___|

          W I F I   D E F U S E
   ---------------------------------
          by Firebyte
"""
# =====================================================


class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100 ms
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42  # total len 80

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_client_macs, custom_channels,
                 deauth_all_channels, autostart, debug_mode):
        self.interface = net_iface
        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV
        self._current_channel_num = None
        self._current_channel_aps = set()
        self.attack_loop_count = 0
        self.target_ssid: Union[SSID, None] = None
        self._debug_mode = debug_mode

        if not skip_monitor_mode_setup:
            print_info("Setting up monitor mode...")
            if not self._enable_monitor_mode():
                print_error("Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            print_info("Monitor mode was set up successfully")
        else:
            print_info("Skipping monitor mode setup...")

        if kill_networkmanager:
            print_info("Killing NetworkManager...")
            if not self._kill_networkmanager():
                print_error("Failed to kill NetworkManager...")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}
        self.log_debug(f"Supported channels: {[c for c in self._channel_range.keys()]}")
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self._custom_target_client_mac: Union[List[str], None] = self.parse_custom_client_mac(custom_client_macs)
        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self._custom_target_ap_last_ch = 0
        self._midrun_output_buffer: List[str] = list()
        self._midrun_output_lck = threading.RLock()
        self._deauth_all_channels = deauth_all_channels
        self._ch_iterator: Union[Generator[int, None, int], None] = None

        if self._deauth_all_channels:
            self._ch_iterator = self._init_channels_generator()
        print_info(f"De-auth all channels enabled -> {BOLD}{self._deauth_all_channels}{RESET}")
        self._autostart = autostart

    # [PARSE METHODS] -------------------
    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                print_error("Custom SSID name cannot be an empty string")
                raise Exception("Invalid SSID name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception:
                print_error(f"Invalid bssid address -> {bssid_addr}")
                raise Exception("Bad custom BSSID mac address")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        RandMAC(mac_addr)
        return mac_addr

    @staticmethod
    def parse_custom_client_mac(client_mac_addrs: Union[None, str]) -> List[str]:
        custom_client_mac_list = []
        if client_mac_addrs is not None:
            for mac in client_mac_addrs.split(','):
                try:
                    custom_client_mac_list.append(Interceptor.verify_mac_addr(mac))
                except Exception:
                    print_error(f"Invalid custom client mac address -> {mac}")
                    raise Exception("Bad custom client mac address")

        if custom_client_mac_list:
            print_info(f"Disabling broadcast deauth, attacking custom clients instead: {custom_client_mac_list}")
        else:
            print_info("No custom clients selected, enabling broadcast deauth and attacking all connected clients")

        return custom_client_mac_list

    def parse_custom_channels(self, channel_list: Union[None, str]):
        ch_list = []
        if channel_list is not None:
            try:
                ch_list = [int(ch) for ch in channel_list.split(',')]
            except Exception:
                print_error(f"Invalid custom channel input -> {channel_list}")
                raise Exception("Bad custom channel input")

            if len(ch_list):
                supported_channels = self._channel_range.keys()
                for ch in ch_list:
                    if ch not in supported_channels:
                        print_error(f"Custom channel {ch} is not supported by the network interface {list(supported_channels)}")
                        raise Exception("Unsupported channel")
        return ch_list

    # [MONITOR MODE] -------------------
    def _enable_monitor_mode(self):
        for cmd in [f"sudo ip link set {self.interface} down",
                    f"sudo iw {self.interface} set monitor control",
                    f"sudo ip link set {self.interface} up"]:
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if os.system(cmd):
                os.system(f"sudo ip link set {self.interface} up")
                return False
        sleep(2)
        return True

    @staticmethod
    def _kill_networkmanager():
        cmd = 'systemctl stop NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return not os.system(cmd)

    # [REST OF YOUR METHODS REMAIN UNCHANGED]
    # ...
    # Keep the rest of your original Interceptor methods exactly as they were
    # ...

def main():
    signal.signal(signal.SIGINT, Interceptor.user_abort)

    printf(f"\n{BANNER}\n"
           f"Make sure of the following:\n"
           f"1. You are running as {BOLD}root{RESET}\n"
           f"2. You kill NetworkManager (manually or with {BOLD}--kill{RESET})\n"
           f"3. Your wireless adapter supports {BOLD}monitor mode{RESET}\n\n"
           f"Written by {BOLD}@flashnuke{RESET}")
    printf(DELIM)
    restore_print()

    if "linux" not in sys.platform:
        raise OSError(f"Unsupported OS {sys.platform}, only Linux is supported...")
    elif os.geteuid() != 0:
        raise PermissionError("Must be run as root")

    parser = argparse.ArgumentParser(description='A simple program to perform a deauth attack')
    parser.add_argument('-i', '--iface', required=True, help='Network interface with monitor mode enabled')
    parser.add_argument('--skip-monitormode', action='store_true', help='Skip automatic setup of monitor mode')
    parser.add_argument('-k', '--kill', action='store_true', help='Kill NetworkManager')
    parser.add_argument('-s', '--ssid', default=None, help='Custom SSID name')
    parser.add_argument('-b', '--bssid', default=None, help='Custom BSSID address')
    parser.add_argument('--clients', default=None, help='Target client MAC addresses, comma separated')
    parser.add_argument('-c', '--channels', default=None, help='Custom channels to scan/deauth, comma separated')
    parser.add_argument('-a', '--autostart', action='store_true', help='Autostart if single AP found')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug prints')
    parser.add_argument('--deauth-all-channels', action='store_true', help='Enable deauth on all channels')

    pargs = parser.parse_args()

    invalidate_print()

    attacker = Interceptor(
        net_iface=pargs.iface,
        skip_monitor_mode_setup=pargs.skip_monitormode,
        kill_networkmanager=pargs.kill,
        ssid_name=pargs.ssid,
        bssid_addr=pargs.bssid,
        custom_client_macs=pargs.clients,
        custom_channels=pargs.channels,
        deauth_all_channels=pargs.deauth_all_channels,
        autostart=pargs.autostart,
        debug_mode=pargs.debug
    )
    attacker.run()


if __name__ == "__main__":
    main()
