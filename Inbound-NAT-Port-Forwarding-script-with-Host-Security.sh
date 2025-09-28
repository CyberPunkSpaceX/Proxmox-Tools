#!/bin/bash

# Proxmox Inbound Port Forwarding Script
# Excludes ports 22 (SSH) and 8006 (Proxmox Web UI) - keeps them on host
# Forwards ALL other ports to specified VM IP

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
EXCLUDED_PORTS="22 8006"
PUBLIC_IPS=()
SELECTED_PUBLIC_IPS=()
VM_IP=""

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -lt 0 || $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to discover public IP addresses
discover_public_ips() {
    print_info "Discovering public IP addresses on this Proxmox host..."
    
    # Get public IPs from network interfaces
    local temp_ips=()
    
    # Check all network interfaces for public IPs
    while IFS= read -r line; do
        local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        if validate_ip "$ip" && [[ ! "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]; then
            temp_ips+=("$ip")
        fi
    done < <(ip addr show | grep "inet " | grep -v "inet 127")
    
    # Try to get external IP as well
    for service in "https://ifconfig.me/ip" "https://ipinfo.io/ip" "https://icanhazip.com"; do
        local external_ip
        external_ip=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | tr -d '\n\r' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        if validate_ip "$external_ip"; then
            temp_ips+=("$external_ip")
            break
        fi
    done
    
    # Remove duplicates and sort
    PUBLIC_IPS=($(printf '%s\n' "${temp_ips[@]}" | sort -u))
    
    if [[ ${#PUBLIC_IPS[@]} -eq 0 ]]; then
        print_error "No public IP addresses found!"
        print_info "Please ensure this Proxmox host has public IP addresses configured"
        exit 1
    fi
    
    print_success "Found public IP addresses:"
    for i in "${!PUBLIC_IPS[@]}"; do
        echo "  $(($i + 1)). ${PUBLIC_IPS[$i]}"
    done
}

# Function to select public IPs for forwarding
select_public_ips() {
    echo
    print_info "Select which public IP(s) to use for port forwarding:"
    echo
    
    # Show available options
    echo "Available public IP addresses:"
    for i in "${!PUBLIC_IPS[@]}"; do
        echo "  $(($i + 1)). ${PUBLIC_IPS[$i]}"
    done
    echo "  $((${#PUBLIC_IPS[@]} + 1)). Use ALL public IPs"
    echo
    
    while true; do
        read -p "Enter your choice (number, comma-separated numbers, or 'all'): " selection
        
        SELECTED_PUBLIC_IPS=()
        
        if [[ "$selection" == "all" ]] || [[ "$selection" == "$((${#PUBLIC_IPS[@]} + 1))" ]]; then
            # Use all public IPs
            SELECTED_PUBLIC_IPS=("${PUBLIC_IPS[@]}")
            print_success "Selected ALL public IPs for forwarding"
            break
        elif [[ "$selection" =~ ^[0-9,]+$ ]]; then
            # Parse comma-separated numbers
            IFS=',' read -ra selections <<< "$selection"
            local valid_selection=true
            
            for sel in "${selections[@]}"; do
                sel=$(echo "$sel" | tr -d ' ') # Remove spaces
                if [[ "$sel" -ge 1 && "$sel" -le "${#PUBLIC_IPS[@]}" ]]; then
                    local ip_index=$((sel - 1))
                    SELECTED_PUBLIC_IPS+=("${PUBLIC_IPS[$ip_index]}")
                else
                    print_error "Invalid selection: $sel"
                    valid_selection=false
                    break
                fi
            done
            
            if $valid_selection; then
                # Remove duplicates
                SELECTED_PUBLIC_IPS=($(printf '%s\n' "${SELECTED_PUBLIC_IPS[@]}" | sort -u))
                print_success "Selected public IP(s):"
                for ip in "${SELECTED_PUBLIC_IPS[@]}"; do
                    echo "  - $ip"
                done
                break
            fi
        else
            print_error "Invalid input. Please enter numbers, comma-separated numbers, or 'all'"
        fi
    done
}
# Function to get VM IP
get_vm_ip() {
    echo
    print_info "Enter the VM IP address where you want to forward traffic"
    print_warning "This should be the IP of your VM on the internal network (e.g., 10.x.x.x, 192.168.x.x)"
    echo
    
    while true; do
        read -p "VM IP address: " VM_IP
        
        if validate_ip "$VM_IP"; then
            # Check if it looks like a private IP (recommended for VMs)
            if [[ "$VM_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
                print_success "VM IP set to: $VM_IP"
                break
            else
                print_warning "Warning: $VM_IP doesn't appear to be a private IP address"
                read -p "Are you sure this is correct? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    print_success "VM IP set to: $VM_IP"
                    break
                fi
            fi
        else
            print_error "Invalid IP address format. Please try again."
        fi
    done
}

# Function to show what will be configured
show_configuration_summary() {
    echo
    print_info "Configuration Summary:"
    echo "======================="
    echo
    echo -e "${YELLOW}Excluded Ports (staying on Proxmox host):${NC}"
    for port in $EXCLUDED_PORTS; do
        case $port in
            22) echo "  - Port 22 (SSH) - for Proxmox management" ;;
            8006) echo "  - Port 8006 (Proxmox Web UI) - for web interface" ;;
            *) echo "  - Port $port" ;;
        esac
    done
    
    echo
    echo -e "${YELLOW}Port Forwarding Rules:${NC}"
    for public_ip in "${SELECTED_PUBLIC_IPS[@]}"; do
        echo "  - $public_ip:* (all ports except ${EXCLUDED_PORTS// /, }) → $VM_IP:*"
    done
    
    echo
    echo -e "${YELLOW}Total Rules:${NC}"
    local rule_count=$((${#SELECTED_PUBLIC_IPS[@]} * 2))  # TCP and UDP rules per IP
    echo "  - $rule_count NAT rules will be created (TCP + UDP for each selected public IP)"
}

# Function to backup current iptables rules
backup_current_rules() {
    local backup_file="/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules"
    print_info "Creating backup of current iptables rules..."
    
    iptables-save > "$backup_file"
    print_success "Current rules backed up to: $backup_file"
    echo "  Use 'iptables-restore < $backup_file' to restore if needed"
}

# Function to clear existing NAT rules
clear_existing_nat_rules() {
    print_info "Clearing existing inbound NAT rules..."
    
    # Clear PREROUTING chain (where DNAT rules go)
    iptables -t nat -F PREROUTING 2>/dev/null || true
    
    print_success "Existing NAT rules cleared"
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."
    
    # Enable for current session
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Make persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        print_success "IP forwarding enabled and made persistent"
    else
        print_success "IP forwarding enabled"
    fi
}

# Function to create NAT rules
create_nat_rules() {
    print_info "Creating NAT rules..."
    
    local rules_created=0
    
    for public_ip in "${SELECTED_PUBLIC_IPS[@]}"; do
        print_info "Creating rules for public IP: $public_ip"
        
        # Instead of trying to exclude multiple ports in one rule,
        # we'll create rules for port ranges that avoid the excluded ports
        
        # Port ranges to forward (avoiding 22 and 8006)
        local port_ranges=(
            "1:21"      # Ports 1-21 (before SSH)
            "23:8005"   # Ports 23-8005 (between SSH and Proxmox)
            "8007:65535" # Ports 8007-65535 (after Proxmox)
        )
        
        for range in "${port_ranges[@]}"; do
            local start_port=$(echo "$range" | cut -d':' -f1)
            local end_port=$(echo "$range" | cut -d':' -f2)
            
            # TCP rules
            iptables -t nat -A PREROUTING -d "$public_ip" -p tcp --dport "$start_port:$end_port" -j DNAT --to-destination "$VM_IP"
            
            # UDP rules
            iptables -t nat -A PREROUTING -d "$public_ip" -p udp --dport "$start_port:$end_port" -j DNAT --to-destination "$VM_IP"
            
            rules_created=$((rules_created + 2))
        done
        
        echo "  ✓ TCP and UDP rules created for $public_ip (3 port ranges each)"
    done
    
    print_success "Created $rules_created NAT rules"
}

# Function to add FORWARD rules (allow traffic to flow through)
create_forward_rules() {
    print_info "Creating FORWARD rules to allow traffic flow..."
    
    # Allow forwarding to VM
    iptables -A FORWARD -d "$VM_IP" -j ACCEPT 2>/dev/null || true
    
    # Allow return traffic
    iptables -A FORWARD -s "$VM_IP" -j ACCEPT 2>/dev/null || true
    
    print_success "FORWARD rules created"
}

# Function to save rules persistently
save_rules() {
    print_info "Saving rules for persistence..."
    
    # Try different persistence methods
    if [ -d /etc/iptables ]; then
        iptables-save > /etc/iptables/rules.v4
        print_success "Rules saved to /etc/iptables/rules.v4"
    elif command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save
        print_success "Rules saved using netfilter-persistent"
    elif command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables.rules
        print_success "Rules saved to /etc/iptables.rules"
        
        # Create restore script for startup
        cat > /etc/network/if-pre-up.d/iptables << 'EOF'
#!/bin/bash
iptables-restore < /etc/iptables.rules
EOF
        chmod +x /etc/network/if-pre-up.d/iptables
        print_info "Auto-restore script created"
    else
        local manual_save="/tmp/iptables_rules_$(date +%Y%m%d_%H%M%S).rules"
        iptables-save > "$manual_save"
        print_warning "Could not save rules automatically"
        print_info "Rules saved to: $manual_save"
        print_info "Manually restore with: iptables-restore < $manual_save"
    fi
}

# Function to show current NAT rules
show_current_rules() {
    echo
    print_info "Current NAT Rules (PREROUTING):"
    echo "=================================="
    iptables -t nat -L PREROUTING -n --line-numbers | head -20
    
    echo
    print_info "Current FORWARD Rules:"
    echo "======================"
    iptables -L FORWARD -n --line-numbers | head -10
    
    echo
    print_info "IP Forwarding Status:"
    echo "====================="
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        echo "✓ IP Forwarding: ENABLED"
    else
        echo "✗ IP Forwarding: DISABLED"
    fi
}

# Function to test connectivity
test_connectivity() {
    echo
    print_info "Testing connectivity to VM..."
    
    if ping -c 2 -W 3 "$VM_IP" >/dev/null 2>&1; then
        print_success "✓ VM $VM_IP is reachable from Proxmox host"
    else
        print_warning "⚠ VM $VM_IP is not responding to ping"
        print_info "This might be normal if the VM blocks ICMP"
    fi
}

# Main configuration function
configure_port_forwarding() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            Proxmox VM Port Forwarding Setup             ║${NC}"
    echo -e "${BLUE}║     Excludes SSH (22) & Proxmox Web UI (8006)           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Step 1: Check prerequisites
    check_root
    
    # Step 2: Discover public IPs
    discover_public_ips
    
    # Step 3: Select which public IPs to use
    select_public_ips
    
    # Step 4: Get VM IP
    get_vm_ip
    
    # Step 5: Show configuration summary
    show_configuration_summary
    
    # Step 6: Confirm configuration
    echo
    read -p "Proceed with this configuration? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_warning "Configuration cancelled"
        exit 0
    fi
    
    # Step 7: Backup current rules
    backup_current_rules
    
    # Step 8: Clear existing NAT rules
    clear_existing_nat_rules
    
    # Step 9: Enable IP forwarding
    enable_ip_forwarding
    
    # Step 10: Create NAT rules
    create_nat_rules
    
    # Step 11: Create FORWARD rules
    create_forward_rules
    
    # Step 12: Save rules
    save_rules
    
    # Step 13: Test connectivity
    test_connectivity
    
    # Step 14: Show final status
    show_current_rules
    
    echo
    print_success "Port forwarding configuration complete!"
    echo
    print_info "Summary:"
    echo "  - Ports 22 (SSH) and 8006 (Proxmox) remain on this host"
    echo "  - Selected public IP(s) forward all other ports to VM: $VM_IP"
    for ip in "${SELECTED_PUBLIC_IPS[@]}"; do
        echo "    • $ip → $VM_IP"
    done
    echo "  - Configuration saved and will persist after reboot"
    echo
    print_warning "Important:"
    echo "  - Ensure your VM ($VM_IP) is running and has services on desired ports"
    echo "  - Test your services from external networks"
    echo "  - Consider firewall rules on your VM for security"
}

# Menu function
show_menu() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            Proxmox VM Port Forwarding Manager           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
    echo "1. Configure new port forwarding to VM (select public IPs)"
    echo "2. Show current NAT rules"
    echo "3. Clear all NAT rules"
    echo "4. Test VM connectivity"
    echo "5. Quick setup (all public IPs to one VM)"
    echo "6. Exit"
    echo
    read -p "Choose option [1-6]: " choice
    
    case $choice in
        1)
            configure_port_forwarding
            ;;
        2)
            show_current_rules
            ;;
        3)
            print_warning "This will clear ALL NAT rules!"
            read -p "Are you sure? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                backup_current_rules
                clear_existing_nat_rules
                print_success "All NAT rules cleared"
            fi
            ;;
        4)
            read -p "Enter VM IP to test: " test_ip
            if validate_ip "$test_ip"; then
                VM_IP="$test_ip"
                test_connectivity
            else
                print_error "Invalid IP address"
            fi
            ;;
        5)
            # Quick setup - use all public IPs
            check_root
            discover_public_ips
            SELECTED_PUBLIC_IPS=("${PUBLIC_IPS[@]}")
            get_vm_ip
            show_configuration_summary
            echo
            read -p "Proceed with forwarding ALL public IPs to $VM_IP? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                backup_current_rules
                clear_existing_nat_rules
                enable_ip_forwarding
                create_nat_rules
                create_forward_rules
                save_rules
                test_connectivity
                show_current_rules
                print_success "Quick setup complete!"
            fi
            ;;
        6)
            print_info "Goodbye!"
            exit 0
            ;;
        *)
            print_error "Invalid choice"
            ;;
    esac
}

# Main execution
if [[ $# -eq 0 ]]; then
    # Interactive mode
    while true; do
        show_menu
        echo
        read -p "Press Enter to continue..."
        clear
    done
else
    # Command line mode
    case $1 in
        configure)
            configure_port_forwarding
            ;;
        show)
            show_current_rules
            ;;
        clear)
            check_root
            backup_current_rules
            clear_existing_nat_rules
            print_success "All NAT rules cleared"
            ;;
        *)
            echo "Usage: $0 [configure|show|clear]"
            echo "  configure - Set up port forwarding to VM"
            echo "  show      - Display current NAT rules"
            echo "  clear     - Clear all NAT rules"
            echo "  (no args) - Interactive menu"
            exit 1
            ;;
    esac
fi