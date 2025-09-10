#!/usr/bin/env python3
import argparse
import subprocess
import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "/ram/iptables.log"

def parse_duration_to_seconds(duration_str):
    """Converts a duration string like '1d', '3h', '30m' to seconds."""
    duration_str = duration_str.lower()
    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    
    if not duration_str or not duration_str[-1] in multipliers:
        raise ValueError(f"Invalid duration format: '{duration_str}'. Use s, m, h, or d.")
        
    unit = duration_str[-1]
    try:
        value = int(duration_str[:-1])
    except ValueError:
        raise ValueError(f"Invalid duration value in '{duration_str}'.")
        
    return value * multipliers[unit]

def add_to_ipset(ipset_name, ip, timeout_seconds, dryrun=False):
    """Adds an IP to a specified ipset with a timeout."""
    log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if dryrun:
        print(f"  -> [DRYRUN] Would add IP '{ip}' to ipset '{ipset_name}' with a timeout of {timeout_seconds} seconds.")
        return

    command = ['ipset', 'add', ipset_name, ip, 'timeout', str(timeout_seconds), '-exist']
    
    try:
        print(f"  -> [ACTION] Adding IP '{ip}' to ipset '{ipset_name}' with a timeout of {timeout_seconds} seconds.")
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"  -> [ERROR] Failed to add '{ip}' to '{ipset_name}'. Stderr: {e.stderr.strip()}")
    except FileNotFoundError:
        print(f"  -> [ERROR] 'ipset' command not found. Is it installed and in your PATH?")

def setup_arg_parser():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Scan iptables/ip6tables logs for traffic patterns and add violating IPs to the correct ipset.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Arguments remain the same, the script handles the _v6 logic internally
    parser.add_argument('--rule', required=True, choices=['blocked', 'allowed'], help="Log rule to match (e.g., 'blocked').")
    parser.add_argument('--type', required=True, choices=['tcp', 'udp', 'icmp'], help="Protocol type to match (e.g., 'tcp').")
    parser.add_argument('--howmany', required=True, type=int, help="Number of log entries to trigger the rule (e.g., 1000).")
    parser.add_argument('--within', required=True, type=str, help="Time window for the count (e.g., '1h', '30m', '1d').")
    parser.add_argument('--ipset', required=True, type=str, help="The base name of the ipset (e.g., 'blacklist'). '_v6' will be appended for IPv6.")
    parser.add_argument('--removeafter', required=True, type=str, help="How long the IP should remain in the ipset (e.g., '3h').")
    parser.add_argument('--dryrun', action='store_true', help="If set, print what would happen but don't execute ipset commands.")
    return parser.parse_args()

def main():
    args = setup_arg_parser()
    
    try:
        within_delta = timedelta(seconds=parse_duration_to_seconds(args.within))
        removeafter_seconds = parse_duration_to_seconds(args.removeafter)
    except ValueError as e:
        print(f"[ERROR] Error parsing time arguments: {e}")
        return

    # UPDATED REGEX: Now captures both IPv4 and IPv6 addresses.
    log_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+).*(?:IPTABLES|IP6TABLES)-(?P<rule>\w+):.*SRC=(?P<ip>[\d\.:a-fA-F]+).*PROTO=(?P<proto>\w+)"
    )

    ip_timestamps = defaultdict(list)
    total_lines = 0
    matched_lines = 0

    print("--- Log Scanner Initialized (Dual-Stack Mode) ---")
    if args.dryrun:
        print("Mode: DRY RUN (no changes will be made)\n")
    print(f"Reading log file: {LOG_FILE}")
    print(f"Trigger Rule: > {args.howmany} '{args.type.upper()}' packets from a single IP where rule is '{args.rule.upper()}' within any '{args.within}' window.")
    print(f"Action: Add IP to ipset '{args.ipset}' (or '{args.ipset}_v6' for IPv6) for {args.removeafter}.\n")
    print("--- Phase 1: Reading and Filtering Log ---")

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                total_lines += 1
                match = log_pattern.search(line)
                if not match:
                    continue
                
                data = match.groupdict()
                
                if data['rule'].lower() != args.rule or data['proto'].lower() != args.type:
                    continue
                
                matched_lines += 1
                
                try:
                    log_time = datetime.strptime(data['timestamp'], "%b %d %H:%M:%S").replace(year=datetime.now().year)
                    ip_timestamps[data['ip']].append(log_time)
                except ValueError:
                    continue

    except FileNotFoundError:
        print(f"[ERROR] Log file not found at '{LOG_FILE}'. Exiting.")
        return

    print(f"Finished reading. Found {matched_lines} log entries matching criteria.")
    print("\n--- Phase 2: Analyzing Traffic Patterns ---")
    
    triggered_ips = set()

    for ip, timestamps in ip_timestamps.items():
        if len(timestamps) < args.howmany:
            continue
        
        timestamps.sort()
        
        for i in range(len(timestamps) - args.howmany + 1):
            window_start_time = timestamps[i]
            window_end_time = window_start_time + within_delta
            hits_in_window = 1 + sum(1 for j in range(i + 1, len(timestamps)) if timestamps[j] <= window_end_time)
            
            if hits_in_window >= args.howmany:
                # --- NEW LOGIC TO DETERMINE IPSET NAME ---
                target_ipset = args.ipset
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.version == 6:
                        target_ipset += "_v6"
                except ValueError:
                    print(f"[WARNING] Could not parse '{ip}' as a valid IP address. Skipping.")
                    continue # Skip this invalid IP
                
                print(f"[VIOLATION] IP: {ip} (v{ip_obj.version})")
                print(f"  -> Details: Found {hits_in_window} hits between {window_start_time.strftime('%H:%M:%S')} and {window_end_time.strftime('%H:%M:%S')}")
                add_to_ipset(target_ipset, ip, removeafter_seconds, args.dryrun)
                triggered_ips.add(ip)
                break 

    print("\n--- Phase 3: Summary ---")
    print(f"Total lines scanned in file: {total_lines}")
    print(f"Lines matching filter criteria: {matched_lines}")
    print(f"Unique IPs matching criteria: {len(ip_timestamps)}")
    print(f"IPs that triggered the rule: {len(triggered_ips)}")
    if triggered_ips:
        print(f"Actioned IPs: {', '.join(sorted(list(triggered_ips)))}")
    print("\n--- Scan Complete ---")

if __name__ == "__main__":
    main()
