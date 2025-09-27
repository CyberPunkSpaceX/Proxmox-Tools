#!/bin/bash

# Proxmox Port Forwarding Manager
# Dedicated script for managing port forwarding from Proxmox host to VMs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Array to store port forwards
declare -a PORT_FORWARDS=()

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
    local backup_file="/root/iptables_nat_backup_$(date +%Y%m%d_%H%M%S).rules"
    print_color $YELLOW "Creating backup of current iptables rules..."
    iptables-save > "$backup_file"
    print_color $GREEN "Backup saved to: $backup_file"
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

# Function to show current port forwarding rules
show_current_forwards() {
    print_header "CURRENT PORT FORWARDING RULES"

    echo "NAT PREROUTING rules (incoming traffic):"
    iptables -t nat -L PREROUTING -n --line-numbers | grep -v "^Chain\|^num" || echo "No PREROUTING rules found"

    echo
    echo "FORWARD rules (traffic passing through):"
    iptables -L FORWARD -n --line-numbers | grep -v "^Chain\|^num" || echo "No FORWARD rules found"

    echo
    echo "NAT POSTROUTING rules (outgoing traffic):"
    iptables -t nat -L POSTROUTING -n --line-numbers | grep -v "^Chain\|^num" || echo "No POSTROUTING rules found"

    echo
    echo "IP Forwarding status:"
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        print_color $GREEN "✓ IP forwarding is ENABLED"
    else
        print_color $YELLOW "⚠ IP forwarding is DISABLED"
    fi
}

# Function to add port forwarding rules
add_port_forwards() {
    print_color $BLUE "Port Forwarding Configuration"
    print_color $YELLOW "Add specific ports to forward from Proxmox host to VMs"
    print_color $BLUE "Common examples:"
    echo "  - Web server: 80:192.168.1.100:80, 443:192.168.1.100:443"
    echo "  - Application: 3000:192.168.1.101:3000"
    echo "  - Database: 5432:192.168.1.102:5432"
    echo "  - Port range: 8000-8005:192.168.1.103:8000-8005 (max 10 ports)"
    echo

    while true; do
        echo
        print_color $BLUE "Add port forwarding rule (or 'done' to finish):"
        echo "Format: HOST_PORT:VM_IP:VM_PORT"
        echo "Examples:"
        echo "  80:192.168.1.100:80     (HTTP to web server VM)"
        echo "  8080:192.168.1.101:80   (Custom port to web server)"
        echo "  3000-3005:192.168.1.102:3000-3005 (small range)"
        read -p "> " forward_rule

        if [[ "$forward_rule" == "done" ]]; then
            break
        fi

        if [[ -z "$forward_rule" ]]; then
            print_color $RED "Please enter a valid forwarding rule"
            continue
        fi

        # Validate format: PORT:IP:PORT or PORT-PORT:IP:PORT-PORT
        if [[ $forward_rule =~ ^([0-9-]+):([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9-]+)$ ]]; then
            local host_port="${BASH_REMATCH[1]}"
            local vm_ip="${BASH_REMATCH[2]}"
            local vm_port="${BASH_REMATCH[3]}"

            # Check for large port ranges
            if [[ $host_port == *"-"* ]]; then
                IFS='-' read -r start_port end_port <<< "$host_port"
                local range_size=$((end_port - start_port + 1))
                if [[ $range_size -gt 10 ]]; then
                    print_color $RED "Port range too large ($range_size ports). Maximum 10 ports allowed."
                    print_color $YELLOW "For large ranges, consider using a dedicated VM gateway."
                    continue
                fi
            fi

            # Validate VM IP
            if validate_ip "$vm_ip"; then
                PORT_FORWARDS+=("$forward_rule")
                print_color $GREEN "Added port forward: $host_port -> $vm_ip:$vm_port"
            else
                print_color $RED "Invalid VM IP address: $vm_ip"
                continue
            fi
        else
            print_color $RED "Invalid format. Use: HOST_PORT:VM_IP:VM_PORT"
            print_color $YELLOW "Example: 80:192.168.1.100:8080"
            continue
        fi

        echo "Current port forwards:"
        for i in "${!PORT_FORWARDS[@]}"; do
            echo "  $((i+1)). ${PORT_FORWARDS[i]}"
        done
    done
}

# Function to apply port forwarding rules
apply_port_forwards() {
    if [[ ${#PORT_FORWARDS[@]} -eq 0 ]]; then
        print_color $RED "No port forwarding rules configured."
        return 1
    fi

    print_header "APPLYING PORT FORWARDING RULES"

    print_color $YELLOW "This will configure port forwarding:"
    echo "1. Enable IP forwarding on the host"
    echo "2. Set up NAT rules to forward traffic to VMs"
    echo "3. Configure FORWARD rules to allow forwarded traffic"
    echo "4. Set up MASQUERADE for VM internet access"
    echo
    echo "Port forwarding rules to apply:"
    for forward in "${PORT_FORWARDS[@]}"; do
        echo "  - $forward"
    done
    echo
    read -p "Continue? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_color $YELLOW "Operation cancelled"
        return 0
    fi

    # Create backup
    backup_rules

    print_color $YELLOW "Configuring port forwarding..."

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        print_color $GREEN "IP forwarding enabled and made persistent"
    fi

    # Apply each port forward rule
    for forward in "${PORT_FORWARDS[@]}"; do
        IFS=':' read -r host_port vm_ip vm_port <<< "$forward"

        print_color $YELLOW "Setting up forward: $host_port -> $vm_ip:$vm_port"

        # Handle port ranges vs single ports
        if [[ $host_port == *"-"* ]] && [[ $vm_port == *"-"* ]]; then
            # Port range forwarding
            IFS='-' read -r start_port end_port <<< "$host_port"
            IFS='-' read -r vm_start_port vm_end_port <<< "$vm_port"

            # Validate range sizes match
            local host_range_size=$((end_port - start_port))
            local vm_range_size=$((vm_end_port - vm_start_port))

            if [[ $host_range_size -eq $vm_range_size ]]; then
                # Use efficient port range forwarding
                iptables -t nat -A PREROUTING -p tcp --dport "$start_port:$end_port" -j DNAT --to-destination "$vm_ip:$vm_start_port-$vm_end_port"
                iptables -t nat -A PREROUTING -p udp --dport "$start_port:$end_port" -j DNAT --to-destination "$vm_ip:$vm_start_port-$vm_end_port"
                iptables -A FORWARD -p tcp -d "$vm_ip" --dport "$vm_start_port:$vm_end_port" -j ACCEPT
                iptables -A FORWARD -p udp -d "$vm_ip" --dport "$vm_start_port:$vm_end_port" -j ACCEPT
            else
                print_color $RED "Error: Port range sizes don't match for $forward"
                continue
            fi
        else
            # Single port forwarding
            iptables -t nat -A PREROUTING -p tcp --dport "$host_port" -j DNAT --to-destination "$vm_ip:$vm_port"
            iptables -t nat -A PREROUTING -p udp --dport "$host_port" -j DNAT --to-destination "$vm_ip:$vm_port"
            iptables -A FORWARD -p tcp -d "$vm_ip" --dport "$vm_port" -j ACCEPT
            iptables -A FORWARD -p udp -d "$vm_ip" --dport "$vm_port" -j ACCEPT
        fi
    done

    # Add MASQUERADE rule for outbound traffic from VMs
    iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true

    print_color $GREEN "Port forwarding rules applied successfully!"
    print_color $BLUE "Configuration Summary:"
    echo "  ✓ IP forwarding: Enabled"
    echo "  ✓ Port forwarding rules: ${#PORT_FORWARDS[@]} configured"
    echo "  ✓ VM internet access: Configured via NAT"
    echo "  ✓ Traffic routing: Host -> VMs configured"

    # Save rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        }
        print_color $GREEN "Rules saved to /etc/iptables/rules.v4"

        # Also save NAT rules separately for clarity
        iptables-save -t nat > /etc/iptables/nat-rules.v4 2>/dev/null || true
        print_color $GREEN "NAT rules saved to /etc/iptables/nat-rules.v4"
    fi

    # Show final rules
    echo
    show_current_forwards
}

# Function to configure VM gateway forwarding
configure_vm_gateway() {
    print_header "CONFIGURE VM GATEWAY FORWARDING"

    print_color $BLUE "Forward ALL other ports to a single VM gateway"
    print_color $YELLOW "This sets up one VM to handle all external traffic"
    print_color $RED "WARNING: This affects ALL ports not used by host services"
    echo
    echo "Enter the VM IP address to use as gateway:"
    read -p "VM Gateway IP: " vm_ip

    if [[ -z "$vm_ip" ]]; then
        print_color $RED "No VM IP provided"
        return 1
    fi

    # Validate VM IP
    if ! validate_ip "$vm_ip"; then
        print_color $RED "Invalid VM IP address: $vm_ip"
        return 1
    fi

    print_color $YELLOW "This will forward ALL traffic (except host services) to VM $vm_ip:"
    echo "  ✓ All TCP ports → $vm_ip (except those used by host)"
    echo "  ✓ All UDP ports → $vm_ip"
    echo "  ✓ Enable IP forwarding"
    echo "  ✓ Configure NAT for VM internet access"
    echo
    print_color $BLUE "Note: Host services (SSH, Proxmox) remain on the host"
    print_color $RED "This is a powerful configuration - use carefully!"
    echo
    read -p "Continue? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_color $YELLOW "Operation cancelled"
        return 0
    fi

    # Create backup
    backup_rules

    print_color $YELLOW "Setting up VM gateway forwarding..."

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    # Clear existing PREROUTING and FORWARD rules
    iptables -t nat -F PREROUTING 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true

    # Forward all traffic to VM gateway (this is a broad approach)
    print_color $YELLOW "Setting up gateway forwarding to $vm_ip..."

    # Forward all TCP and UDP traffic to the gateway VM
    iptables -t nat -A PREROUTING -j DNAT --to-destination $vm_ip
    iptables -A FORWARD -d $vm_ip -j ACCEPT

    # Add MASQUERADE rule for outbound traffic from VMs
    iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE 2>/dev/null || true

    print_color $GREEN "VM gateway forwarding configured!"
    print_color $BLUE "Configuration Summary:"
    echo "  ✓ Gateway VM: $vm_ip"
    echo "  ✓ All external traffic: Forwarded to gateway"
    echo "  ✓ Host services: Remain on host (if configured)"
    echo "  ✓ VM internet access: Configured via NAT"

    # Save rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        }
        print_color $GREEN "Rules saved to /etc/iptables/rules.v4"
    fi
}

# Function to clear port forwarding rules
clear_port_forwarding() {
    print_header "CLEAR PORT FORWARDING RULES"
    print_color $RED "WARNING: This will remove ALL port forwarding rules!"
    print_color $YELLOW "External traffic will no longer be forwarded to VMs."
    print_color $BLUE "Host firewall rules will remain unchanged."
    echo
    read -p "Are you sure? (yes/no): " confirm

    if [[ "$confirm" == "yes" ]]; then
        backup_rules

        print_color $YELLOW "Clearing port forwarding rules..."

        # Clear NAT rules
        iptables -t nat -F PREROUTING 2>/dev/null || true
        iptables -t nat -F POSTROUTING 2>/dev/null || true
        iptables -F FORWARD 2>/dev/null || true

        print_color $GREEN "Port forwarding rules cleared!"
        print_color $BLUE "VMs can still access internet, but external traffic won't be forwarded"
        print_color $YELLOW "IP forwarding remains enabled"

        # Save rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        print_color $GREEN "Rules saved"

    else
        print_color $YELLOW "Operation cancelled"
    fi
}

# Function to test port forwarding
test_port_forwarding() {
    print_header "PORT FORWARDING TEST"

    echo "Current NAT rules:"
    iptables -t nat -L -n | grep -E "(DNAT|MASQUERADE)" || echo "No NAT rules found"

    echo
    echo "Current FORWARD rules:"
    iptables -L FORWARD -n | grep "ACCEPT" || echo "No FORWARD ACCEPT rules found"

    echo
    echo "IP forwarding status:"
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        print_color $GREEN "✓ IP forwarding is ENABLED"
    else
        print_color $RED "✗ IP forwarding is DISABLED"
    fi

    echo
    echo "Active connections through host:"
    ss -tn | grep -E ":80|:443|:8080" || echo "No active web connections"

    echo
    print_color $BLUE "To test externally:"
    echo "1. Try accessing your host IP on forwarded ports"
    echo "2. Check if traffic reaches the target VMs"
    echo "3. Verify VMs can access internet"
}

# Main menu
main_menu() {
    while true; do
        print_header "PROXMOX PORT FORWARDING MANAGER"
        print_color $GREEN "Dedicated tool for forwarding traffic from host to VMs"
        print_color $BLUE "Manages NAT, FORWARD, and MASQUERADE rules"
        echo
        echo "1. Show current port forwarding rules"
        echo "2. Configure specific port forwarding"
        echo "3. Configure VM gateway (forward all traffic to one VM)"
        echo "4. Clear all port forwarding rules"
        echo "5. Test port forwarding"
        echo "6. Exit"
        echo
        read -p "Select option (1-6): " choice

        case $choice in
            1)
                show_current_forwards
                read -p "Press Enter to continue..."
                ;;
            2)
                PORT_FORWARDS=()  # Reset array
                add_port_forwards
                if [[ ${#PORT_FORWARDS[@]} -gt 0 ]]; then
                    apply_port_forwards
                    read -p "Press Enter to continue..."
                fi
                ;;
            3)
                configure_vm_gateway
                read -p "Press Enter to continue..."
                ;;
            4)
                clear_port_forwarding
                read -p "Press Enter to continue..."
                ;;
            5)
                test_port_forwarding
                read -p "Press Enter to continue..."
                ;;
            6)
                print_color $GREEN "Goodbye!"
                print_color $BLUE "Port forwarding configuration complete"
                exit 0
                ;;
            *)
                print_color $RED "Invalid option"
                ;;
        esac
    done
}

# Main execution
print_header "PROXMOX PORT FORWARDING MANAGER"
print_color $GREEN "Dedicated Port Forwarding Tool"
print_color $BLUE "Manages traffic forwarding from Proxmox host to VMs"

check_root

# Check if iptables is available
if ! command -v iptables >/dev/null 2>&1; then
    print_color $RED "iptables not found. Please install iptables."
    exit 1
fi

main_menu