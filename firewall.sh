#!/bin/bash
# =================================================================
# Unified IPv4 & IPv6 Firewall Setup Script (Legacy Compatible)
# Configures iptables and ip6tables with ipset integration
# to log ALL allowed and blocked traffic.
# =================================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- 1. SYSTEM CHECKS ---
echo "[+] Checking for required commands (iptables, ip6tables, ipset)..."
for cmd in iptables ip6tables ipset; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[!] Critical Error: '$cmd' command not found. Please install it."
        exit 1
    fi
done
echo "[+] All commands found."

# --- 2. IPSET CREATION ---
echo "[+] Creating all required ipsets for IPv4 and IPv6..."
ipset create whitelist hash:ip timeout 0 -exist
ipset create blacklist hash:ip timeout 0 -exist
ipset create throttle-soft hash:ip timeout 0 -exist
ipset create throttle-hard hash:ip timeout 0 -exist
ipset create whitelist_v6 hash:ip family inet6 timeout 0 -exist
ipset create blacklist_v6 hash:ip family inet6 timeout 0 -exist
ipset create throttle-soft_v6 hash:ip family inet6 timeout 0 -exist
ipset create throttle-hard_v6 hash:ip family inet6 timeout 0 -exist
echo "[+] IPsets are ready."

# =================================================================
# --- 3. IPV4 FIREWALL CONFIGURATION (iptables) ---
# =================================================================
echo "[+] Configuring IPv4 Firewall (iptables)..."

# --- FLUSH IPv4 ---
iptables -F
iptables -X
iptables -Z

# --- SET IPv4 DEFAULTS ---
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# --- CREATE IPv4 ACTION CHAINS ---
iptables -N LOG_AND_ACCEPT
# --log-timestamps removed for legacy compatibility
iptables -A LOG_AND_ACCEPT -j LOG --log-prefix "IPTABLES-ALLOWED: " --log-level 6
iptables -A LOG_AND_ACCEPT -j ACCEPT

iptables -N LOG_AND_DROP
# --log-timestamps removed for legacy compatibility
iptables -A LOG_AND_DROP -j LOG --log-prefix "IPTABLES-BLOCKED: " --log-level 4
iptables -A LOG_AND_DROP -j DROP

# --- ALLOW IPv4 ESSENTIALS (UNLOGGED) ---
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# --- IPv4 IPSET RULES ---
iptables -A INPUT -m set --match-set whitelist src -j LOG_AND_ACCEPT
iptables -A INPUT -m set --match-set blacklist src -j LOG_AND_DROP
iptables -A INPUT -p tcp -m set --match-set throttle-soft src -m conntrack --ctstate NEW -m limit --limit 100/minute -j LOG_AND_ACCEPT
iptables -A INPUT -p icmp -m set --match-set throttle-soft src -m limit --limit 100/hour -j LOG_AND_ACCEPT
iptables -A INPUT -p tcp -m set --match-set throttle-hard src -m conntrack --ctstate NEW -m limit --limit 100/hour -j LOG_AND_ACCEPT
iptables -A INPUT -p icmp -m set --match-set throttle-hard src -m limit --limit 1/minute -j LOG_AND_ACCEPT

# --- IPv4 GENERAL RULES ---
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name ssh_limit --hashlimit-mode srcip --hashlimit-upto 10/minute -j LOG_AND_ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name https_limit --hashlimit-mode srcip --hashlimit-upto 60/minute -j LOG_AND_ACCEPT

# --- IPv4 CATCH-ALL ---
iptables -A INPUT -j LOG_AND_DROP
echo "[+] IPv4 Firewall configured."

# =================================================================
# --- 4. IPV6 FIREWALL CONFIGURATION (ip6tables) ---
# =================================================================
echo "[+] Configuring IPv6 Firewall (ip6tables)..."

# --- FLUSH IPv6 ---
ip6tables -F
ip6tables -X
ip6tables -Z

# --- SET IPv6 DEFAULTS ---
ip6tables -P INPUT   DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT  ACCEPT

# --- CREATE IPv6 ACTION CHAINS ---
ip6tables -N LOG_AND_ACCEPT_V6
# --log-timestamps removed for legacy compatibility
ip6tables -A LOG_AND_ACCEPT_V6 -j LOG --log-prefix "IP6TABLES-ALLOWED: " --log-level 6
ip6tables -A LOG_AND_ACCEPT_V6 -j ACCEPT

ip6tables -N LOG_AND_DROP_V6
# --log-timestamps removed for legacy compatibility
ip6tables -A LOG_AND_DROP_V6 -j LOG --log-prefix "IP6TABLES-BLOCKED: " --log-level 4
ip6tables -A LOG_AND_DROP_V6 -j DROP

# --- ALLOW IPv6 ESSENTIALS (UNLOGGED) ---
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# --- IPv6 IPSET RULES ---
ip6tables -A INPUT -m set --match-set whitelist_v6 src -j LOG_AND_ACCEPT_V6
ip6tables -A INPUT -m set --match-set blacklist_v6 src -j LOG_AND_DROP_V6
ip6tables -A INPUT -p tcp -m set --match-set throttle-soft_v6 src -m conntrack --ctstate NEW -m limit --limit 100/minute -j LOG_AND_ACCEPT_V6
ip6tables -A INPUT -p icmpv6 -m set --match-set throttle-soft_v6 src -m limit --limit 100/hour -j LOG_AND_ACCEPT_V6
ip6tables -A INPUT -p tcp -m set --match-set throttle-hard_v6 src -m conntrack --ctstate NEW -m limit --limit 100/hour -j LOG_AND_ACCEPT_V6
ip6tables -A INPUT -p icmpv6 -m set --match-set throttle-hard_v6 src -m limit --limit 1/minute -j LOG_AND_ACCEPT_V6

# --- IPv6 GENERAL RULES ---
ip6tables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name ssh_limit_v6 --hashlimit-mode srcip --hashlimit-upto 10/minute -j LOG_AND_ACCEPT_V6
ip6tables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m hashlimit --hashlimit-name https_limit_v6 --hashlimit-mode srcip --hashlimit-upto 60/minute -j LOG_AND_ACCEPT_V6

# --- IPv6 CATCH-ALL ---
ip6tables -A INPUT -j LOG_AND_DROP_V6
echo "[+] IPv6 Firewall configured."

echo ""
echo "[*] Unified firewall setup is complete!"
echo "[!] IMPORTANT: Ensure your rsyslog and logrotate configurations are set up."
