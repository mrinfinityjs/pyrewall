# Dynamic IPTables Firewall with IPset and Automated Log Scanning

This document outlines a robust, dual-stack (IPv4/IPv6) firewall system for Linux. It uses `iptables`, `ip6tables`, and `ipset` for efficient, dynamic filtering, and includes a powerful Python script for automatically banning malicious IPs based on real-time log analysis.

The entire system is designed for high performance by logging to a RAM disk, preventing disk I/O bottlenecks and wear on physical drives.

## Table of Contents
1.  [Core Components](#core-components)
2.  [Features](#features)
3.  [Installation and Setup](#installation-and-setup)
4.  [How It Works](#how-it-works)
    - [Firewall Logic](#firewall-logic)
    - [IPset Management](#ipset-management)
    - [Automated Log Scanner](#automated-log-scanner)
5.  [Usage](#usage)
    - [Managing IPsets Manually](#managing-ipsets-manually)
    - [Using the Log Scanner Script](#using-the-log-scanner-script)
    - [Practical Examples](#practical-examples)
6.  [Configuration and Customization](#configuration-and-customization)
7.  [Troubleshooting](#troubleshooting)

## Core Components

1.  **Unified Firewall Script (`firewall.sh`)**: A single bash script that configures `iptables` (IPv4) and `ip6tables` (IPv6).
2.  **IPsets**: A series of dynamic lists used by the firewall to efficiently manage groups of IP addresses without reloading rules.
    - `whitelist` / `whitelist_v6`
    - `blacklist` / `blacklist_v6`
    - `throttle-soft` / `throttle-soft_v6`
    - `throttle-hard` / `throttle-hard_v6`
3.  **Log Scanner Script (`log_scanner_dualstack.py`)**: A Python tool that runs on-demand (e.g., via cron) to analyze firewall logs and add offending IPs to the appropriate ipset.
4.  **RAM Disk Logging**: All logs are written to a `tmpfs` (RAM) filesystem at `/ram/iptables.log` for maximum performance and to avoid disk wear.
5.  **System Services**:
    - **Rsyslog**: Configured to filter and direct firewall logs to the RAM disk.
    - **Logrotate**: Configured to truncate the log file when it reaches a specific size limit.

## Features

- **Dual-Stack Ready**: Fully supports both IPv4 and IPv6 with parallel rules and ipsets.
- **High Performance**: Logs to RAM, and `ipset` provides highly efficient lookups for large lists of IPs.
- **Dynamic & Automated**: The Python script automatically bans IPs based on customizable rules, reducing the need for manual intervention.
- **Comprehensive Logging**: Logs all allowed and blocked connection attempts for complete visibility.
- **Resilient**: Firewall rules and IPsets can be made persistent across reboots.
- **Flexible**: The scanner script is highly configurable via command-line arguments.

## Installation and Setup

Follow these steps to deploy the entire system.

### Step 1: Create the RAM Disk

This creates a 1GB RAM disk at `/ram` that will persist across reboots.

```bash
# Create the mount point
sudo mkdir /ram

# Mount it for the current session
sudo mount -t tmpfs -o size=1G tmpfs /ram

# Add it to fstab to make it permanent
echo "tmpfs   /ram   tmpfs   defaults,size=1G   0   0" | sudo tee -a /etc/fstab
```

### Step 2: Configure Logging (Rsyslog)

Create a rule to tell `rsyslog` where to send the firewall logs.

```bash
# Create the rsyslog configuration file
sudo nano /etc/rsyslog.d/10-iptables.conf
```

Paste the following content into the file:
```
# Catches logs from iptables and ip6tables, both allowed and blocked
if ($msg contains "IPTABLES-") or ($msg contains "IP6TABLES-") then {
    action(type="omfile" file="/ram/iptables.log")
    stop
}
```
Save the file and restart `rsyslog`:
```bash
sudo systemctl restart rsyslog
```

### Step 3: Configure Log Rotation (Logrotate)

Create a rule to manage the log file, truncating it at 10MB.

```bash
sudo nano /etc/logrotate.d/iptables
```
Paste the following content into the file:
```
/ram/iptables.log
{
    size 100M
    rotate 0
    copytruncate
    missingok
    notifempty
    create 0640 syslog adm
}
```
Save the file. No restart is needed.

### Step 4: Deploy the Firewall Script

Save the firewall script from the previous response as `firewall.sh`.

```bash
# Make it executable
chmod +x furewall.sh

# Run the script to apply the firewall rules
sudo ./firewall.sh
```

### Step 5: Save Firewall Rules (Persistence)

To ensure your firewall rules and ipsets survive a reboot:

**For Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install iptables-persistent ipset-persistent
# During installation, say YES to saving current IPv4 and IPv6 rules.
```

**For CentOS/RHEL/Fedora:**
```bash
sudo dnf install iptables-services ipset-service
sudo systemctl enable iptables ip6tables ipset

# Save the current rules and sets
sudo iptables-save > /etc/sysconfig/iptables
sudo ip6tables-save > /etc/sysconfig/ip6tables
sudo ipset save > /etc/sysconfig/ipset
```

### Step 6: Deploy the Python Scanner

Save the Python script as `log_scanner_dualstack.py` (e.g., in `/usr/local/sbin/`).

```bash
# Make it executable
chmod +x /usr/local/sbin/log_scanner_dualstack.py
```

### Step 7: Automate the Scanner (Cron Job)

Set up a cron job to run the scanner periodically.

```bash
# Open the crontab for editing
crontab -e
```
Add one or more lines to define your scanning rules. For example, to run a scan every 5 minutes:
```
*/5 * * * * /usr/local/sbin/log_scanner_dualstack.py --rule blocked --type tcp --howmany 500 --within 30m --ipset throttle-hard --removeafter 1h >> /var/log/log_scanner.log 2>&1
```

## How It Works

### Firewall Logic

The firewall operates with a "default drop" policy. The logic for an incoming packet is as follows:
1.  Is the connection related to an already established session? If yes, **ACCEPT**.
2.  Is the source IP in the `whitelist`? If yes, **LOG and ACCEPT**.
3.  Is the source IP in the `blacklist`? If yes, **LOG and DROP**.
4.  Is the source IP in a `throttle` set? If yes, check against its specific rate limits. If allowed, **LOG and ACCEPT**.
5.  Does the packet match a general rule (e.g., for SSH/HTTPS)? If yes, check against its rate limits. If allowed, **LOG and ACCEPT**.
6.  If none of the above match, **LOG and DROP**.

### IPset Management

IPsets are the core of the dynamic system. Instead of adding/removing individual `iptables` rules (which is slow), we just add/remove IPs from these sets.

### Automated Log Scanner

The `log_scanner_dualstack.py` script is a stateless, one-shot tool. When run, it:
1.  Reads the entire `/ram/iptables.log` file.
2.  Filters lines based on the criteria provided via command-line arguments (e.g., `--rule blocked`, `--type tcp`).
3.  For each IP, it analyzes its timestamps to see if it has violated the threshold (e.g., more than `--howmany 1000` hits `--within 1h`).
4.  If a violation is found, it determines if the IP is IPv4 or IPv6.
5.  It adds the IP to the correct ipset (`blacklist` for IPv4, `blacklist_v6` for IPv6) with the specified timeout.
6.  It prints a detailed summary of its findings and actions, then exits.

## Usage

### Managing IPsets Manually

You can interact with the firewall in real-time by managing the ipsets.

| Action                   | IPv4 Command                                            | IPv6 Command                                                       |
| ------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------ |
| **Whitelist an IP**      | `sudo ipset add whitelist 1.2.3.4`                      | `sudo ipset add whitelist_v6 2001:db8::1`                            |
| **Blacklist for 1 day**  | `sudo ipset add blacklist 4.3.2.1 timeout 86400`        | `sudo ipset add blacklist_v6 2001:db8::2 timeout 86400`            |
| **Remove from a list**   | `sudo ipset del blacklist 4.3.2.1`                      | `sudo ipset del blacklist_v6 2001:db8::2`                            |
| **List IPs in a set**    | `sudo ipset list blacklist`                             | `sudo ipset list blacklist_v6`                                     |
| **Flush all IPs**        | `sudo ipset flush blacklist`                            | `sudo ipset flush blacklist_v6`                                    |

### Using the Log Scanner Script

The script is controlled entirely by command-line arguments.

`./log_scanner_dualstack.py [OPTIONS]`

| Argument        | Description                                                               | Example         |
| --------------- | ------------------------------------------------------------------------- | --------------- |
| `--rule`        | Log rule to match.                                                        | `blocked`       |
| `--type`        | Protocol to match.                                                        | `tcp`           |
| `--howmany`     | Number of hits to trigger the action.                                     | `1000`          |
| `--within`      | Time window for the count (s, m, h, d).                                   | `1h`, `30m`     |
| `--ipset`       | Base name of the ipset to use. `_v6` is added automatically.              | `blacklist`     |
| `--removeafter` | How long the IP should stay in the ipset.                                 | `3h`, `1d`      |
| `--dryrun`      | Report actions that would be taken without actually modifying the ipset.  |                 |

### Practical Examples

**Dry Run:** Test a rule to see who would be blacklisted for >100 blocked TCP hits in 5 minutes.
```bash
./log_scanner_dualstack.py --rule blocked --type tcp --howmany 100 --within 5m --ipset blacklist --removeafter 1d --dryrun
```

**Hard Throttling:** Add any IP with >500 blocked TCP hits in 30 minutes to the `throttle-hard` list for 2 hours.
```bash
./log_scanner_dualstack.py --rule blocked --type tcp --howmany 500 --within 30m --ipset throttle-hard --removeafter 2h
```

**ICMP Flood Protection:** Blacklist any IP sending >200 blocked ICMP packets in 1 minute for 6 hours.
```bash
./log_scanner_dualstack.py --rule blocked --type icmp --howmany 200 --within 1m --ipset blacklist --removeafter 6h
```

## Configuration and Customization

- **Firewall Rules**: To open new ports, edit `firewall.sh` and add new `-j LOG_AND_ACCEPT` rules.
- **RAM Disk Size**: Change the `size=1G` parameter in `/etc/fstab` to resize the RAM disk.
- **Log Truncation Size**: Change the `size 10M` parameter in `/etc/logrotate.d/iptables`.
- **Log File Path**: To change the log path, you must update it in `/etc/fstab`, `/etc/rsyslog.d/10-iptables.conf`, `/etc/logrotate.d/iptables`, and the `LOG_FILE` variable in the Python script.

## Troubleshooting

- **Logs not appearing in `/ram/iptables.log`**:
    1.  Check that packets are hitting your log rules: `sudo iptables -vL LOG_AND_DROP`. If the packet count is 0, nothing is being blocked.
    2.  Check the kernel's raw log buffer: `sudo dmesg | grep "IPTABLES-"`. If you see logs here, `iptables` is working, but `rsyslog` is misconfigured.
    3.  Check for `rsyslog` syntax errors: `sudo rsyslogd -N1`.
    4.  Ensure you restarted `rsyslog` after changing its configuration.
- **IPs not being added to ipset**:
    1.  Run the Python script with `--dryrun` to see if it's detecting violations correctly.
    2.  Check the script's output (e.g., in `/var/log/log_scanner.log`) for any `[ERROR]` messages.
    3.  Ensure the ipset names in the script's `--ipset` argument match the names created by the firewall script.
