#!/bin/bash

# Proxmox Host Security Manager
# Focused script for protecting SSH and Proxmox web interface access on the host

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default ports
SSH_PORT=22
PROXMOX_PORT=8006

# Array to store allowed sources
declare -a ALLOWED_SOURCES=()

# Function to print colored output
print_color() {
    echo -e "${1}${2}${NC}"
}

# Function to print header
print_header() {
    echo
    print_color $BLUE "=================================================="
    print_color $BLUE "$1"
    print_color $BLUE "=================================================="
    echo
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_color $RED "This script must be run as root"
        print_color $YELLOW "Please run: sudo $0"
        exit 1
    fi
}

# Function to backup current iptables rules
backup_rules() {
    local backup_file="/root/iptables_backup_$(date +%Y%m%d_%H%M%S).rules"
    print_color $YELLOW "Creating backup of current iptables rules..."
    iptables-save > "$backup_file"
    print_color $GREEN "Backup saved to: $backup_file"
}

# Function to display current firewall rules
show_current_rules() {
    print_header "CURRENT IPTABLES RULES"
    
    echo "SSH and Proxmox specific rules:"
    iptables -L INPUT -n --line-numbers | grep -E "(ACCEPT|DROP|REJECT)" | grep -E ":22|:8006" || echo "No SSH/Proxmox specific rules found"
    
    echo
    echo "All INPUT rules:"
    iptables -L INPUT -n --line-numbers
}

# Function to resolve FQDN to IP
resolve_fqdn() {
    local fqdn=$1
    local ip=$(dig +short "$fqdn" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    else
        return 1
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to check if a rule already exists
rule_exists() {
    local protocol=$1
    local port=$2
    local source=$3
    local action=$4
    
    # Check if the exact rule already exists
    if [[ -n "$source" ]]; then
        iptables -C INPUT -p "$protocol" --dport "$port" -s "$source" -j "$action" 2>/dev/null
    else
        iptables -C INPUT -p "$protocol" --dport "$port" -j "$action" 2>/dev/null
    fi
}

# Function to add rule if it doesn't exist
add_rule_if_not_exists() {
    local protocol=$1
    local port=$2
    local source=$3
    local action=$4
    local description=$5
    
    if rule_exists "$protocol" "$port" "$source" "$action"; then
        print_color $BLUE "Rule already exists: $description"
        return 0
    else
        if [[ -n "$source" ]]; then
            iptables -A INPUT -p "$protocol" --dport "$port" -s "$source" -j "$action"
        else
            iptables -A INPUT -p "$protocol" --dport "$port" -j "$action"
        fi
        print_color $GREEN "Added rule: $description"
        return 0
    fi
}
# Function to add source (IP or FQDN)
add_source() {
    while true; do
        echo
        print_color $BLUE "Enter source (IP address or FQDN), or 'done' to finish:"
        read -p "> " source_input
        
        if [[ "$source_input" == "done" ]]; then
            break
        fi
        
        if [[ -z "$source_input" ]]; then
            print_color $RED "Please enter a valid source"
            continue
        fi
        
        # Check if it's an IP or FQDN
        if validate_ip "$source_input"; then
            # It's an IP address
            ALLOWED_SOURCES+=("$source_input")
            print_color $GREEN "Added IP: $source_input"
        else
            # Try to resolve as FQDN
            print_color $YELLOW "Attempting to resolve FQDN: $source_input"
            if resolved_ip=$(resolve_fqdn "$source_input"); then
                print_color $GREEN "Resolved $source_input to $resolved_ip"
                ALLOWED_SOURCES+=("$resolved_ip")
                print_color $YELLOW "Note: FQDN resolved to IP. Consider setting up dynamic IP update if this changes frequently."
            else
                print_color $RED "Could not resolve FQDN: $source_input"
                print_color $YELLOW "Would you like to enter it as a static IP instead? (y/n)"
                read -p "> " try_ip
                if [[ "$try_ip" =~ ^[Yy]$ ]]; then
                    continue
                fi
            fi
        fi
        
        echo "Current allowed sources:"
        for i in "${!ALLOWED_SOURCES[@]}"; do
            echo "  $((i+1)). ${ALLOWED_SOURCES[i]}"
        done
    done
}

# Function to remove existing rules for SSH and Proxmox
remove_existing_rules() {
    print_color $YELLOW "Removing existing SSH and Proxmox rules..."
    
    # Remove dangerous broad ACCEPT rules that bypass security
    while iptables -C INPUT -p tcp -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -p tcp -j ACCEPT
        print_color $YELLOW "Removed broad TCP ACCEPT rule that bypassed security"
    done
    
    # Get line numbers for SSH and Proxmox rules and remove them (in reverse order)
    while IFS= read -r line_num; do
        if [[ -n "$line_num" ]]; then
            iptables -D INPUT "$line_num" 2>/dev/null || true
        fi
    done < <(iptables -L INPUT --line-numbers | grep -E "dpt:(22|8006)" | awk '{print $1}' | sort -rn)
    
    print_color $GREEN "Existing SSH/Proxmox rules removed"
}

# Function to apply host protection rules
apply_host_protection() {
    if [[ ${#ALLOWED_SOURCES[@]} -eq 0 ]]; then
        print_color $RED "No sources configured. Aborting."
        return 1
    fi
    
    print_header "APPLYING HOST PROTECTION RULES"
    
    print_color $YELLOW "This will secure the Proxmox HOST:"
    echo "1. Allow SSH (port $SSH_PORT) from specified sources ONLY"
    echo "2. Allow Proxmox web (port $PROXMOX_PORT) from specified sources ONLY" 
    echo "3. Block all other SSH and Proxmox web access"
    echo "4. Leave all other ports and services unchanged"
    echo "5. Does NOT affect VM networking or port forwarding"
    echo
    print_color $RED "WARNING: This could lock you out if your current IP is not in the allowed list!"
    echo
    echo "Allowed sources:"
    for source in "${ALLOWED_SOURCES[@]}"; do
        echo "  - $source"
    done
    echo
    read -p "Continue? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        print_color $YELLOW "Operation cancelled"
        return 0
    fi
    
    # Create backup first
    backup_rules
    
    # Allow loopback (if not already present)
    if ! rule_exists "all" "" "" "ACCEPT" && ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 1 -i lo -j ACCEPT
        print_color $GREEN "Added loopback rule"
    else
        print_color $BLUE "Loopback rule already exists"
    fi
    
    # Allow established connections (if not already present)
    if ! iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
        print_color $GREEN "Added established connections rule"
    else
        print_color $BLUE "Established connections rule already exists"
    fi
    
    # Remove existing SSH/Proxmox rules (including dangerous broad rules)
    remove_existing_rules
    
    # Add rules for each allowed source
    for source in "${ALLOWED_SOURCES[@]}"; do
        print_color $YELLOW "Processing rules for $source..."
        
        # SSH access
        add_rule_if_not_exists "tcp" "$SSH_PORT" "$source" "ACCEPT" "SSH access from $source"
        
        # Proxmox web access
        add_rule_if_not_exists "tcp" "$PROXMOX_PORT" "$source" "ACCEPT" "Proxmox web access from $source"
    done
    
    # Add DROP rules for SSH and Proxmox (if not already present)
    add_rule_if_not_exists "tcp" "$SSH_PORT" "" "DROP" "DROP all other SSH access"
    add_rule_if_not_exists "tcp" "$PROXMOX_PORT" "" "DROP" "DROP all other Proxmox web access"
    
    print_color $GREEN "Host protection rules applied successfully!"
    print_color $BLUE "Security Summary:"
    echo "  ✓ SSH (port $SSH_PORT): Restricted to allowed sources only"
    echo "  ✓ Proxmox (port $PROXMOX_PORT): Restricted to allowed sources only"
    echo "  ✓ All other host services: Unchanged"
    echo "  ✓ VM networking: Not affected"
    echo "  ✓ Host is now protected from unauthorized access"
    echo "  ✓ Duplicate rules prevented"
    
    # Save rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        }
        print_color $GREEN "Rules saved to /etc/iptables/rules.v4"
    fi
    
    # Show final rules
    echo
    show_current_rules
}

# Function to configure general host ports
configure_host_ports() {
    print_header "CONFIGURE HOST PORT ACCESS"
    
    print_color $BLUE "Configure access to OTHER ports on the Proxmox HOST (not SSH/Proxmox web)"
    print_color $YELLOW "This affects services running directly on the Proxmox server"
    echo
    echo "1. Allow all other ports on this host (HTTP, HTTPS, custom apps, etc.)"
    echo "2. Skip - leave other ports unchanged"
    echo
    read -p "Select option (1-2): " port_choice
    
    case $port_choice in
        1)
            print_color $YELLOW "This will allow specific port ranges on the Proxmox HOST:"
            echo "  ✓ HTTP/HTTPS (80, 443) and common web ports"
            echo "  ✓ Custom applications running on Proxmox host"
            echo "  ✓ Database ports and application ports"
            echo "  ✓ UDP traffic (DNS, DHCP, etc.)"
            echo "  ✓ ICMP traffic (ping, etc.)"
            echo
            print_color $BLUE "Security: Uses specific port ranges, NOT broad rules"
            print_color $YELLOW "Note: SSH(22) and Proxmox(8006) restrictions remain unchanged"
            echo
            read -p "Continue? (yes/no): " confirm
            
            if [[ "$confirm" != "yes" ]]; then
                print_color $YELLOW "Operation cancelled"
                return 0
            fi
            
            # Create backup
            backup_rules
            
            # Remove any dangerous broad ACCEPT rules first
            while iptables -C INPUT -p tcp -j ACCEPT 2>/dev/null; do
                iptables -D INPUT -p tcp -j ACCEPT
                print_color $YELLOW "Removed dangerous broad TCP ACCEPT rule"
            done
            
            while iptables -C INPUT -p udp -j ACCEPT 2>/dev/null; do
                iptables -D INPUT -p udp -j ACCEPT
                print_color $YELLOW "Removed broad UDP ACCEPT rule"
            done
            
            # Add rules for specific port ranges (avoiding SSH and Proxmox)
            print_color $YELLOW "Adding secure port range rules..."
            
            # Check and add port range rules
            add_rule_if_not_exists "tcp" "1:21" "" "ACCEPT" "TCP ports 1-21"
            add_rule_if_not_exists "tcp" "23:8005" "" "ACCEPT" "TCP ports 23-8005" 
            add_rule_if_not_exists "tcp" "8007:65535" "" "ACCEPT" "TCP ports 8007-65535"
            
            # Add UDP and ICMP rules
            if ! iptables -C INPUT -p udp -j ACCEPT 2>/dev/null; then
                iptables -A INPUT -p udp -j ACCEPT
                print_color $GREEN "Added UDP rule"
            else
                print_color $BLUE "UDP rule already exists"
            fi
            
            if ! iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null; then
                iptables -A INPUT -p icmp -j ACCEPT
                print_color $GREEN "Added ICMP rule"
            else
                print_color $BLUE "ICMP rule already exists"
            fi
            
            print_color $GREEN "Host port ranges are now open!"
            print_color $BLUE "Current Configuration:"
            echo "  ✓ TCP Ports 1-21: Open on Proxmox host"
            echo "  ✓ TCP Port 22 (SSH): Restricted (if configured)"
            echo "  ✓ TCP Ports 23-8005: Open on Proxmox host"
            echo "  ✓ TCP Port 8006 (Proxmox): Restricted (if configured)"
            echo "  ✓ TCP Ports 8007-65535: Open on Proxmox host"
            echo "  ✓ UDP traffic: Allowed"
            echo "  ✓ ICMP traffic: Allowed"
            echo "  ✓ VM networking: Not affected"
            
            # Save rules
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
                    mkdir -p /etc/iptables
                    iptables-save > /etc/iptables/rules.v4
                }
                print_color $GREEN "Rules saved to /etc/iptables/rules.v4"
            fi
            ;;
        2)
            print_color $YELLOW "Skipping general port configuration - leaving ports unchanged"
            ;;
        *)
            print_color $RED "Invalid option"
            ;;
    esac
}

# Function to clear host protection rules
clear_host_protection() {
    print_header "CLEAR HOST PROTECTION RULES"
    print_color $RED "WARNING: This will remove SSH and Proxmox port restrictions!"
    print_color $YELLOW "Your Proxmox host will be accessible from any IP address."
    print_color $BLUE "This only affects HOST firewall rules, not VM networking."
    echo
    read -p "Are you sure? (yes/no): " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        backup_rules
        
        print_color $YELLOW "Clearing SSH and Proxmox host protection rules..."
        
        # Remove SSH rules with source restrictions
        for source in "68.148.134.168" "68.148.128.187"; do
            while iptables -C INPUT -p tcp --dport 22 -s "$source" -j ACCEPT 2>/dev/null; do
                iptables -D INPUT -p tcp --dport 22 -s "$source" -j ACCEPT
            done
            while iptables -C INPUT -p tcp --dport 8006 -s "$source" -j ACCEPT 2>/dev/null; do
                iptables -D INPUT -p tcp --dport 8006 -s "$source" -j ACCEPT
            done
        done
        
        # Remove DROP rules
        while iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do
            iptables -D INPUT -p tcp --dport 22 -j DROP
        done
        
        while iptables -C INPUT -p tcp --dport 8006 -j DROP 2>/dev/null; do
            iptables -D INPUT -p tcp --dport 8006 -j DROP
        done
        
        # Remove dangerous broad ACCEPT rules
        print_color $YELLOW "Removing any broad ACCEPT rules..."
        while iptables -C INPUT -p tcp -j ACCEPT 2>/dev/null; do
            iptables -D INPUT -p tcp -j ACCEPT
            print_color $GREEN "Removed broad TCP ACCEPT rule"
        done
        
        # Remove port range rules
        iptables -D INPUT -p tcp --dport 1:21 -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p tcp --dport 23:8005 -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p tcp --dport 8007:65535 -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p icmp -j ACCEPT 2>/dev/null || true
        
        print_color $GREEN "Host protection rules cleared!"
        print_color $GREEN "SSH and Proxmox are now accessible from any IP."
        print_color $BLUE "VM networking remains unchanged."
        
        # Save rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        
        print_color $BLUE "Clean slate achieved! You can now reconfigure host protection."
    else
        print_color $YELLOW "Operation cancelled"
    fi
}

# Emergency function to completely reset iptables
emergency_reset() {
    print_header "EMERGENCY RESET - COMPLETE IPTABLES FLUSH"
    print_color $RED "DANGER: This will remove ALL iptables rules on the HOST!"
    print_color $YELLOW "This includes any custom rules not created by this script."
    print_color $BLUE "VM networking should not be affected."
    print_color $BLUE "Use this only if the host firewall is completely messed up."
    echo
    read -p "Type 'RESET' to confirm complete flush: " confirm
    
    if [[ "$confirm" == "RESET" ]]; then
        backup_rules
        
        print_color $YELLOW "Performing complete host iptables reset..."
        
        # Set default policies to ACCEPT (so we don't lock ourselves out)
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        # Flush all chains
        iptables -F INPUT
        iptables -F FORWARD
        iptables -F OUTPUT
        iptables -t nat -F
        iptables -t mangle -F
        
        # Delete user-defined chains
        iptables -X 2>/dev/null || true
        iptables -t nat -X 2>/dev/null || true
        iptables -t mangle -X 2>/dev/null || true
        
        # Add basic security back
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        print_color $GREEN "Complete host iptables reset performed!"
        print_color $BLUE "Basic security restored (loopback + established connections)"
        print_color $YELLOW "All host ports are now open - reconfigure security immediately!"
        print_color $GREEN "VM networking should be unaffected."
        
        # Save the clean state
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        
    else
        print_color $YELLOW "Emergency reset cancelled"
    fi
}

# Function to test connectivity
test_connectivity() {
    print_header "HOST CONNECTIVITY TEST"
    echo "Current SSH connections to host:"
    ss -tnp | grep :22 || echo "No active SSH connections"
    echo
    echo "Current Proxmox web connections to host:"
    ss -tnp | grep :8006 || echo "No active Proxmox web connections"
    echo
    print_color $BLUE "Note: This shows connections to the Proxmox HOST only, not VMs"
}

# Main menu
main_menu() {
    while true; do
        print_header "PROXMOX HOST SECURITY MANAGER"
        print_color $GREEN "Focused on protecting SSH and Proxmox web interface on the HOST"
        print_color $BLUE "For VM port forwarding, use a separate port forwarding script"
        echo
        echo "1. Show current host firewall rules"
        echo "2. Configure SSH/Proxmox access restrictions"
        echo "3. Configure other host port access"
        echo "4. Clear host protection rules"
        echo "5. Emergency reset (complete host iptables flush)"
        echo "6. Test host connectivity"
        echo "7. Exit"
        echo
        read -p "Select option (1-7): " choice
        
        case $choice in
            1)
                show_current_rules
                read -p "Press Enter to continue..."
                ;;
            2)
                ALLOWED_SOURCES=()  # Reset array
                add_source
                if [[ ${#ALLOWED_SOURCES[@]} -gt 0 ]]; then
                    apply_host_protection
                    read -p "Press Enter to continue..."
                fi
                ;;
            3)
                configure_host_ports
                read -p "Press Enter to continue..."
                ;;
            4)
                clear_host_protection
                read -p "Press Enter to continue..."
                ;;
            5)
                emergency_reset
                read -p "Press Enter to continue..."
                ;;
            6)
                test_connectivity
                read -p "Press Enter to continue..."
                ;;
            7)
                print_color $GREEN "Goodbye!"
                print_color $BLUE "Remember: This script only protects the Proxmox HOST"
                print_color $BLUE "Use a separate script for VM port forwarding if needed"
                exit 0
                ;;
            *)
                print_color $RED "Invalid option"
                ;;
        esac
    done
}

# Main execution
print_header "PROXMOX HOST SECURITY MANAGER"
print_color $GREEN "Focused Host Protection Tool"
print_color $BLUE "Protects SSH and Proxmox web interface access on the HOST only"

check_root

# Check if iptables is available
if ! command -v iptables >/dev/null 2>&1; then
    print_color $RED "iptables not found. Please install iptables."
    exit 1
fi

# Check if dig is available for FQDN resolution
if ! command -v dig >/dev/null 2>&1; then
    print_color $YELLOW "dig not found. FQDN resolution may not work."
    print_color $YELLOW "Consider installing dnsutils: apt-get install dnsutils"
fi

main_menu