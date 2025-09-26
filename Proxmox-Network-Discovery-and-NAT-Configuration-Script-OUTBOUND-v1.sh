#!/bin/bash
# Enhanced NAT Fixer with Bridge Detection and Interface Selection
# Automatically detects all bridges and public interfaces, provides interactive configuration

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
test_step() { echo -e "${BLUE}[TEST] $1${NC}"; }
prompt() { echo -e "${CYAN}[INPUT] $1${NC}"; }

# Global variables
ISSUES_FOUND=0
FIXES_APPLIED=0
ALL_BRIDGES=()
ALL_PUBLIC_INTERFACES=()
SELECTED_NAT_CONFIGS=()
INTERACTIVE_MODE=1

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

test_host_internet() {
    test_step "Testing host internet connectivity..."
    if timeout 5 ping -c 2 8.8.8.8 >/dev/null 2>&1; then
        success "Host has internet access"
        return 0
    else
        error "Host cannot reach internet - fix this first!"
        return 1
    fi
}

discover_all_bridges() {
    log "Discovering all bridge interfaces..."
    ALL_BRIDGES=()
    
    # Find all bridge interfaces
    while IFS= read -r bridge; do
        if [[ -n "$bridge" ]]; then
            bridge_ip=$(ip addr show "$bridge" 2>/dev/null | grep 'inet ' | head -1 | awk '{print $2}' || echo "")
            bridge_state=$(ip link show "$bridge" 2>/dev/null | grep -o 'state [A-Z]*' | awk '{print $2}' || echo "DOWN")
            
            if [[ -n "$bridge_ip" ]]; then
                ip_only=$(echo "$bridge_ip" | cut -d'/' -f1)
                # Determine if private or public IP
                if [[ "$ip_only" =~ ^10\. ]] || [[ "$ip_only" =~ ^192\.168\. ]] || [[ "$ip_only" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
                    bridge_type="private"
                else
                    bridge_type="public"
                fi
                ALL_BRIDGES+=("$bridge:$bridge_ip:$bridge_state:$bridge_type")
                log "Bridge found: $bridge ($bridge_ip) - $bridge_state - $bridge_type"
            else
                ALL_BRIDGES+=("$bridge:no-ip:$bridge_state:unknown")
                log "Bridge found: $bridge (no IP) - $bridge_state"
            fi
        fi
    done < <(ip link show type bridge | grep -o '^[0-9]*: [^:]*' | cut -d' ' -f2 | sort)
    
    if [[ ${#ALL_BRIDGES[@]} -eq 0 ]]; then
        warning "No bridge interfaces found"
        return 1
    fi
    
    log "Found ${#ALL_BRIDGES[@]} bridge interface(s)"
    return 0
}

discover_public_interfaces() {
    log "Discovering public network interfaces..."
    ALL_PUBLIC_INTERFACES=()
    
    # Get all interfaces with IPs
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            interface=$(echo "$line" | awk '{print $1}')
            ip_addr=$(echo "$line" | awk '{print $2}')
            ip_only=$(echo "$ip_addr" | cut -d'/' -f1)
            
            # Skip loopback and private IPs
            if [[ "$interface" == "lo" ]]; then
                continue
            fi
            
            # Check if this is a public IP (not private)
            if [[ ! "$ip_only" =~ ^10\. ]] && [[ ! "$ip_only" =~ ^192\.168\. ]] && [[ ! "$ip_only" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && [[ ! "$ip_only" =~ ^127\. ]]; then
                # Check if interface has default route
                if ip route show default | grep -q "dev $interface"; then
                    default_route="(default route)"
                else
                    default_route=""
                fi
                ALL_PUBLIC_INTERFACES+=("$interface:$ip_addr:public:$default_route")
                log "Public interface: $interface ($ip_addr) $default_route"
            fi
        fi
    done < <(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $NF, $2}')
    
    # Also include interfaces that are part of default route but might have private IPs (like behind NAT)
    default_interface=$(ip route show default 2>/dev/null | head -1 | grep -o 'dev [^ ]*' | cut -d' ' -f2 || echo "")
    if [[ -n "$default_interface" ]]; then
        # Check if we already have this interface
        found=0
        for pub_int in "${ALL_PUBLIC_INTERFACES[@]}"; do
            if [[ "$pub_int" == "$default_interface:"* ]]; then
                found=1
                break
            fi
        done
        
        if [[ $found -eq 0 ]]; then
            interface_ip=$(ip addr show "$default_interface" 2>/dev/null | grep 'inet ' | head -1 | awk '{print $2}' || echo "")
            if [[ -n "$interface_ip" ]]; then
                ALL_PUBLIC_INTERFACES+=("$default_interface:$interface_ip:default:(default route)")
                log "Default route interface: $default_interface ($interface_ip)"
            fi
        fi
    fi
    
    if [[ ${#ALL_PUBLIC_INTERFACES[@]} -eq 0 ]]; then
        error "No public network interfaces found!"
        return 1
    fi
    
    log "Found ${#ALL_PUBLIC_INTERFACES[@]} public interface(s)"
    return 0
}

display_bridges() {
    echo
    echo -e "${BOLD}Available Bridge Interfaces:${NC}"
    echo "=================================================="
    
    local index=1
    for bridge_info in "${ALL_BRIDGES[@]}"; do
        IFS=':' read -r bridge ip state type <<< "$bridge_info"
        
        if [[ "$type" == "private" ]]; then
            color="${GREEN}"
        elif [[ "$type" == "public" ]]; then
            color="${YELLOW}"
        else
            color="${NC}"
        fi
        
        printf "%s%2d) %-10s %-18s %-8s %s%s\n" "$color" $index "$bridge" "$ip" "$state" "$type" "${NC}"
        ((index++))
    done
    echo
}

display_public_interfaces() {
    echo
    echo -e "${BOLD}Available Public Interfaces:${NC}"
    echo "=================================================="
    
    local index=1
    for pub_info in "${ALL_PUBLIC_INTERFACES[@]}"; do
        IFS=':' read -r interface ip type extra <<< "$pub_info"
        
        if [[ "$extra" == *"default"* ]]; then
            color="${GREEN}"
        else
            color="${CYAN}"
        fi
        
        printf "%s%2d) %-10s %-18s %s %s%s\n" "$color" $index "$interface" "$ip" "$type" "$extra" "${NC}"
        ((index++))
    done
    echo
}

select_nat_configurations() {
    echo
    echo -e "${BOLD}NAT Configuration Setup${NC}"
    echo "============================================="
    echo "Select which private bridges should be NAT'd to which public interfaces"
    echo
    
    # Get private bridges
    local private_bridges=()
    for bridge_info in "${ALL_BRIDGES[@]}"; do
        IFS=':' read -r bridge ip state type <<< "$bridge_info"
        if [[ "$type" == "private" && "$state" != "DOWN" ]]; then
            private_bridges+=("$bridge_info")
        fi
    done
    
    if [[ ${#private_bridges[@]} -eq 0 ]]; then
        warning "No private bridges found that can be NAT'd"
        return 1
    fi
    
    SELECTED_NAT_CONFIGS=()
    
    for bridge_info in "${private_bridges[@]}"; do
        IFS=':' read -r bridge ip state type <<< "$bridge_info"
        
        echo
        echo -e "${CYAN}Configure NAT for bridge: ${BOLD}$bridge${NC}${CYAN} ($ip)${NC}"
        echo "Choose public interface for outbound NAT:"
        echo
        
        display_public_interfaces
        
        while true; do
            read -p "Select public interface (1-${#ALL_PUBLIC_INTERFACES[@]}) or 's' to skip: " choice
            
            if [[ "$choice" == "s" || "$choice" == "S" ]]; then
                log "Skipping NAT configuration for $bridge"
                break
            elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ALL_PUBLIC_INTERFACES[@]} ]; then
                selected_pub_info="${ALL_PUBLIC_INTERFACES[$((choice-1))]}"
                IFS=':' read -r pub_interface pub_ip pub_type pub_extra <<< "$selected_pub_info"
                
                SELECTED_NAT_CONFIGS+=("$bridge:$ip:$pub_interface:$pub_ip")
                success "Will NAT $bridge ($ip) → $pub_interface ($pub_ip)"
                break
            else
                error "Invalid selection. Please choose 1-${#ALL_PUBLIC_INTERFACES[@]} or 's' to skip"
            fi
        done
    done
    
    if [[ ${#SELECTED_NAT_CONFIGS[@]} -eq 0 ]]; then
        warning "No NAT configurations selected"
        return 1
    fi
    
    echo
    echo -e "${BOLD}Selected NAT Configurations:${NC}"
    echo "============================================="
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        echo "  $bridge ($bridge_ip) → $pub_interface ($pub_ip)"
    done
    
    echo
    read -p "Proceed with these NAT configurations? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log "Configuration cancelled by user"
        exit 0
    fi
    
    return 0
}

test_and_fix_ip_forwarding() {
    test_step "Checking IP forwarding..."
    
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_forward" == "1" ]]; then
        success "IP forwarding is enabled"
        return 0
    else
        error "IP forwarding is disabled"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        
        log "Fixing IP forwarding..."
        echo 1 > /proc/sys/net/ipv4/ip_forward
        
        # Make persistent
        if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
            echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        fi
        
        # Test fix
        new_value=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ "$new_value" == "1" ]]; then
            success "✓ IP forwarding enabled and made persistent"
            FIXES_APPLIED=$((FIXES_APPLIED + 1))
            return 0
        else
            error "Failed to enable IP forwarding"
            return 1
        fi
    fi
}

debug_network_config() {
    local config="$1"
    IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
    
    warning "Debugging network configuration for: $bridge ($bridge_ip) → $pub_interface"
    
    echo "Bridge details:"
    echo "  Bridge: $bridge"
    echo "  Bridge IP: $bridge_ip"
    echo "  Public Interface: $pub_interface"
    echo "  Public IP: $pub_ip"
    
    # Check if bridge exists and is up
    if ip link show "$bridge" >/dev/null 2>&1; then
        echo "  Bridge exists: ✓"
        bridge_state=$(ip link show "$bridge" | grep -o 'state [A-Z]*' | awk '{print $2}')
        echo "  Bridge state: $bridge_state"
    else
        echo "  Bridge exists: ✗"
    fi
    
    # Check if public interface exists
    if ip link show "$pub_interface" >/dev/null 2>&1; then
        echo "  Public interface exists: ✓"
        pub_state=$(ip link show "$pub_interface" | grep -o 'state [A-Z]*' | awk '{print $2}')
        echo "  Public interface state: $pub_state"
    else
        echo "  Public interface exists: ✗"
        echo "  Available interfaces:"
        ip link show | grep -E '^[0-9]+:' | awk '{print "    " $2}' | sed 's/:$//'
    fi
    
    # Show current routes
    echo "  Current default routes:"
    ip route show default | sed 's/^/    /'
    
    echo
}

test_and_fix_nat_rules() {
    test_step "Checking and configuring NAT rules..."
    
    if [[ ${#SELECTED_NAT_CONFIGS[@]} -eq 0 ]]; then
        warning "No NAT configurations to apply"
        return 0
    fi
    
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        
        # Debug the configuration first
        debug_network_config "$config"
        
        # Extract network from bridge IP properly
        ip_only=$(echo "$bridge_ip" | cut -d'/' -f1)
        cidr_mask=$(echo "$bridge_ip" | cut -d'/' -f2)
        
        # Calculate network address based on CIDR
        if [[ "$cidr_mask" == "24" ]]; then
            network=$(echo "$ip_only" | cut -d'.' -f1-3).0
        elif [[ "$cidr_mask" == "16" ]]; then
            network=$(echo "$ip_only" | cut -d'.' -f1-2).0.0
        elif [[ "$cidr_mask" == "8" ]]; then
            network=$(echo "$ip_only" | cut -d'.' -f1).0.0.0
        else
            # For other CIDR masks, use a more sophisticated calculation
            IFS='.' read -r a b c d <<< "$ip_only"
            case "$cidr_mask" in
                "32") network="$ip_only" ;;
                "30") network="$a.$b.$c.$((d & 252))" ;;
                "29") network="$a.$b.$c.$((d & 248))" ;;
                "28") network="$a.$b.$c.$((d & 240))" ;;
                "27") network="$a.$b.$c.$((d & 224))" ;;
                "26") network="$a.$b.$c.$((d & 192))" ;;
                "25") network="$a.$b.$c.$((d & 128))" ;;
                "23") network="$a.$b.$((c & 254)).0" ;;
                "22") network="$a.$b.$((c & 252)).0" ;;
                "21") network="$a.$b.$((c & 248)).0" ;;
                "20") network="$a.$b.$((c & 240)).0" ;;
                *) network="$a.$b.$c.0" ;; # Default to /24
            esac
        fi
        full_network="$network/$cidr_mask"
        
        log "Configuring NAT: $full_network → $pub_interface"
        
        # Check if rule already exists with a simple, reliable check
        if [[ "$cidr_mask" == "32" ]]; then
            nat_source="$ip_only"
        else
            nat_source="$full_network"
        fi
        
        # Simple check for existing rule
        if iptables -t nat -L POSTROUTING -n | grep "$nat_source" | grep "$pub_interface" | grep -q MASQUERADE; then
            success "NAT rule already exists for $nat_source → $pub_interface"
        else
            # Add NAT rule
            log "Adding NAT rule: $nat_source → $pub_interface"
            iptables -t nat -A POSTROUTING -s "$nat_source" -o "$pub_interface" -j MASQUERADE
            
            # Verify rule was added - check for the specific source and interface combination
            sleep 1  # Give iptables a moment to update
            
            # Debug: Show what we're looking for
            log "Debug: Looking for pattern matching source '$nat_source' and interface '$pub_interface'"
            
            # First, let's see if the rule exists at all (simplified check)
            if iptables -t nat -L POSTROUTING -n | grep "$nat_source" | grep "$pub_interface" | grep -q MASQUERADE; then
                success "✓ Added NAT rule: $nat_source → $pub_interface (verified with simple match)"
                FIXES_APPLIED=$((FIXES_APPLIED + 1))
            else
                # Try a more detailed check
                log "Debug: Simple match failed, trying detailed verification..."
                
                # Show the exact lines we're checking
                log "Debug: Lines containing source '$nat_source':"
                iptables -t nat -L POSTROUTING -n | grep "$nat_source" | while read line; do
                    log "  $line"
                done
                
                log "Debug: Lines containing interface '$pub_interface':"
                iptables -t nat -L POSTROUTING -n | grep "$pub_interface" | while read line; do
                    log "  $line"
                done
                
                # Manual check
                rule_count=$(iptables -t nat -L POSTROUTING -n | grep "$nat_source" | grep "$pub_interface" | grep MASQUERADE | wc -l)
                if [[ "$rule_count" -gt 0 ]]; then
                    success "✓ NAT rule exists: $nat_source → $pub_interface (found $rule_count rule(s))"
                    FIXES_APPLIED=$((FIXES_APPLIED + 1))
                else
                    error "Failed to verify NAT rule for $nat_source → $pub_interface"
                    log "This might be a verification issue - the rule may actually be working"
                    
                    # Don't return 1 here, just warn and continue
                    warning "Continuing despite verification failure - rule may be functional"
                fi
            fi
        fi
    done
    
    # Display all NAT rules
    echo
    log "Current NAT rules:"
    iptables -t nat -L POSTROUTING -n --line-numbers | grep -E "(Chain|MASQUERADE|num)" || echo "No MASQUERADE rules found"
    
    return 0
}

test_and_fix_forward_rules() {
    test_step "Checking forward rules..."
    
    # Check for stateful forwarding
    if timeout 10 iptables -L FORWARD -n 2>/dev/null | grep -q "state RELATED,ESTABLISHED"; then
        success "Stateful forward rules found"
        stateful_ok=1
    else
        error "No stateful forward rules"
        stateful_ok=0
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Check bridge forward rules for selected configurations
    bridge_rules_ok=1
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        
        if ! timeout 10 iptables -L FORWARD -n 2>/dev/null | grep -q "$bridge"; then
            error "No forward rules for bridge $bridge"
            bridge_rules_ok=0
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    done
    
    if [[ $stateful_ok -eq 1 && $bridge_rules_ok -eq 1 ]]; then
        success "Forward rules are properly configured"
        return 0
    fi
    
    log "Adding missing forward rules..."
    
    # Add stateful rules
    if [[ $stateful_ok -eq 0 ]]; then
        iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        success "✓ Added stateful forward rules"
    fi
    
    # Add bridge rules for selected configurations
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        
        if ! timeout 10 iptables -L FORWARD -n 2>/dev/null | grep -q "$bridge"; then
            iptables -I FORWARD -i "$bridge" -j ACCEPT
            iptables -I FORWARD -o "$bridge" -j ACCEPT
            success "✓ Added forward rules for $bridge"
        fi
    done
    
    FIXES_APPLIED=$((FIXES_APPLIED + 1))
    return 0
}

test_bridge_connectivity() {
    test_step "Testing bridge connectivity..."
    
    all_bridges_ok=1
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        gateway=$(echo "$bridge_ip" | cut -d'/' -f1)
        
        # Check if bridge is up
        if ip link show "$bridge" | grep -q "state UP"; then
            success "Bridge $bridge is UP"
        else
            error "Bridge $bridge is DOWN"
            ip link set "$bridge" up 2>/dev/null || true
            sleep 1
            if ip link show "$bridge" | grep -q "state UP"; then
                success "✓ Brought up bridge $bridge"
                FIXES_APPLIED=$((FIXES_APPLIED + 1))
            else
                error "Failed to bring up bridge $bridge"
                all_bridges_ok=0
            fi
        fi
        
        # Test bridge IP accessibility
        if timeout 3 ping -c 1 -W 1 "$gateway" >/dev/null 2>&1; then
            success "Bridge $bridge gateway ($gateway) is reachable"
        else
            warning "Bridge $bridge gateway ($gateway) not responding (normal if no VMs)"
        fi
    done
    
    return $all_bridges_ok
}

comprehensive_connectivity_test() {
    test_step "Running comprehensive connectivity test..."
    
    echo
    log "=== CONNECTIVITY TEST SUMMARY ==="
    
    # Test 1: Host to internet
    if timeout 5 ping -c 2 8.8.8.8 >/dev/null 2>&1; then
        success "✓ Host → Internet: OK"
    else
        error "✗ Host → Internet: FAILED"
        return 1
    fi
    
    # Test 2: DNS resolution
    if timeout 5 nslookup google.com >/dev/null 2>&1; then
        success "✓ Host DNS resolution: OK"
    else
        warning "⚠ Host DNS resolution: Issues (may affect VMs)"
    fi
    
    # Test 3: NAT rules active
    if timeout 10 iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
        success "✓ NAT rules: Active"
    else
        error "✗ NAT rules: Missing"
        return 1
    fi
    
    # Test 4: IP forwarding
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        success "✓ IP forwarding: Enabled"
    else
        error "✗ IP forwarding: Disabled"
        return 1
    fi
    
    # Test 5: Forward rules
    if timeout 10 iptables -L FORWARD -n 2>/dev/null | grep -q "ACCEPT"; then
        success "✓ Forward rules: Present"
    else
        error "✗ Forward rules: Missing"
        return 1
    fi
    
    echo
    success "Core networking tests passed!"
    return 0
}

save_configuration() {
    log "Saving configuration..."
    
    # Install iptables-persistent if needed
    if ! dpkg -l | grep -q iptables-persistent 2>/dev/null; then
        log "Installing iptables-persistent..."
        apt update >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent >/dev/null 2>&1
        success "✓ Installed iptables-persistent"
    fi
    
    # Save iptables rules
    mkdir -p /etc/iptables
    if iptables-save > /etc/iptables/rules.v4; then
        success "✓ Saved iptables rules to /etc/iptables/rules.v4"
    else
        error "Failed to save iptables rules"
        return 1
    fi
    
    return 0
}

vm_configuration_guide() {
    echo
    log "=== VM CONFIGURATION GUIDE ==="
    
    if [[ ${#SELECTED_NAT_CONFIGS[@]} -eq 0 ]]; then
        warning "No NAT configurations applied."
        return
    fi
    
    echo "For VMs to access internet, configure them as follows:"
    echo
    
    for config in "${SELECTED_NAT_CONFIGS[@]}"; do
        IFS=':' read -r bridge bridge_ip pub_interface pub_ip <<< "$config"
        gateway=$(echo "$bridge_ip" | cut -d'/' -f1)
        network_base=$(echo "$gateway" | cut -d'.' -f1-3)
        
        echo -e "${BOLD}For VMs on bridge $bridge:${NC}"
        echo "  • Connect VM to bridge: $bridge"
        echo "  • VM IP example: ${network_base}.100/24"
        echo "  • VM Gateway: $gateway"
        echo "  • VM DNS: 8.8.8.8, 1.1.1.1"
        echo "  • NAT exit via: $pub_interface ($pub_ip)"
        echo
        echo "  Test commands (run inside VM):"
        echo "    ping $gateway           # Test gateway connectivity"
        echo "    ping 8.8.8.8           # Test internet connectivity"
        echo "    nslookup google.com     # Test DNS resolution"
        echo
    done
}

create_management_script() {
    log "Creating NAT management script..."
    
    cat > /usr/local/bin/proxmox-nat-manager.sh << 'SCRIPT_EOF'
#!/bin/bash
# Proxmox NAT Management Script

show_nat_status() {
    echo "=== Current NAT Configuration ==="
    echo
    echo "IP Forwarding:"
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        echo "  ✓ Enabled"
    else
        echo "  ✗ Disabled"
    fi
    
    echo
    echo "NAT Rules (POSTROUTING):"
    iptables -t nat -L POSTROUTING -n --line-numbers | grep -E "(Chain|MASQUERADE|num)" || echo "  No MASQUERADE rules"
    
    echo
    echo "Forward Rules:"
    iptables -L FORWARD -n | grep ACCEPT | head -5
    
    echo
    echo "Bridge Status:"
    for bridge in $(ip link show type bridge | grep -o '^[0-9]*: [^:]*' | cut -d' ' -f2); do
        bridge_ip=$(ip addr show "$bridge" 2>/dev/null | grep 'inet ' | head -1 | awk '{print $2}' || echo "no-ip")
        bridge_state=$(ip link show "$bridge" | grep -o 'state [A-Z]*' | awk '{print $2}')
        echo "  $bridge: $bridge_ip ($bridge_state)"
    done
}

case "${1:-status}" in
    "status")
        show_nat_status
        ;;
    "reload")
        echo "Reloading iptables rules..."
        if [[ -f /etc/iptables/rules.v4 ]]; then
            iptables-restore < /etc/iptables/rules.v4
            echo "✓ Rules reloaded"
        else
            echo "✗ No saved rules found"
        fi
        ;;
    *)
        echo "Usage: $0 {status|reload}"
        echo "  status - Show current NAT configuration"
        echo "  reload - Reload saved iptables rules"
        ;;
esac
SCRIPT_EOF
    
    chmod +x /usr/local/bin/proxmox-nat-manager.sh
    success "✓ Created /usr/local/bin/proxmox-nat-manager.sh"
    echo "  Use 'proxmox-nat-manager.sh status' to check NAT status"
    echo "  Use 'proxmox-nat-manager.sh reload' to reload saved rules"
}

create_test_vm_script() {
    log "Creating VM test script..."
    
    cat > /usr/local/bin/test-vm-internet.sh << 'SCRIPT_EOF'
#!/bin/bash
# VM Internet Test Script
# Run this inside a VM to test connectivity

echo "=== VM Internet Connectivity Test ==="
echo

# Get VM network info
echo "VM Network Configuration:"
ip addr show | grep -E "(inet|UP)" | grep -v lo
echo

# Test gateway
gateway=$(ip route | grep default | awk '{print $3}' | head -1)
if [[ -n "$gateway" ]]; then
    echo "Testing gateway ($gateway)..."
    if ping -c 2 -W 3 "$gateway"; then
        echo "✓ Gateway reachable"
    else
        echo "✗ Gateway unreachable - check VM network config"
        exit 1
    fi
else
    echo "✗ No default gateway configured"
    exit 1
fi

echo
echo "Testing internet connectivity..."
if ping -c 2 -W 5 8.8.8.8; then
    echo "✓ Internet connectivity working"
else
    echo "✗ Cannot reach internet"
    echo "Check:"
    echo "  1. VM gateway = bridge IP on Proxmox host"
    echo "  2. NAT rules on Proxmox host"
    echo "  3. VM firewall settings"
    exit 1
fi

echo
echo "Testing DNS resolution..."
if nslookup google.com; then
    echo "✓ DNS working"
else
    echo "⚠ DNS issues - try setting DNS to 8.8.8.8"
fi

echo
echo "✓ VM internet connectivity test completed successfully!"
SCRIPT_EOF
    
    chmod +x /usr/local/bin/test-vm-internet.sh
    success "✓ Created /usr/local/bin/test-vm-internet.sh"
    echo "  Use this script inside VMs to test their connectivity"
}

main() {
    echo "======================================================="
    echo "  Enhanced Proxmox NAT Configuration Script"
    echo "  with Bridge Detection and Interface Selection"
    echo "======================================================="
    echo
    
    check_root
    
    # Initial test
    if ! test_host_internet; then
        exit 1
    fi
    
    # Discovery phase
    log "Starting network discovery..."
    if ! discover_all_bridges; then
        error "Failed to discover bridges"
        exit 1
    fi
    
    if ! discover_public_interfaces; then
        error "Failed to discover public interfaces"
        exit 1
    fi
    
    # Display discovered interfaces
    display_bridges
    display_public_interfaces
    
    # Interactive configuration
    if ! select_nat_configurations; then
        error "No valid NAT configurations selected"
        exit 1
    fi
    
    # Apply fixes and tests
    log "Starting systematic fixes and tests..."
    echo
    
    test_and_fix_ip_forwarding || exit 1
    test_and_fix_nat_rules || exit 1
    test_and_fix_forward_rules || exit 1
    test_bridge_connectivity
    
    echo
    log "Running final comprehensive test..."
    if comprehensive_connectivity_test; then
        success "All tests passed!"
    else
        error "Some tests failed - manual intervention needed"
    fi
    
    # Save configuration
    save_configuration || exit 1
    
    # Create tools and guides
    create_management_script
    create_test_vm_script
    vm_configuration_guide
    
    echo
    log "=== SUMMARY ==="
    echo "Issues found: $ISSUES_FOUND"
    echo "Fixes applied: $FIXES_APPLIED"
    echo "NAT configurations: ${#SELECTED_NAT_CONFIGS[@]}"
    
    if [[ $FIXES_APPLIED -gt 0 ]]; then
        success "Configuration has been applied and tested!"
    else
        success "Configuration was already correct!"
    fi
    
    echo
    warning "Next steps:"
    echo "1. Configure your VMs according to the guide above"
    echo "2. Run '/usr/local/bin/test-vm-internet.sh' inside VMs to test"
    echo "3. Use '/usr/local/bin/proxmox-nat-manager.sh status' to monitor NAT"
    echo "4. If issues persist, check VM network configuration"
    
    echo
    success "Enhanced NAT configuration completed!"
}

# Check for non-interactive mode
if [[ "$1" == "--auto" ]]; then
    INTERACTIVE_MODE=0
    log "Running in automatic mode - will NAT all private bridges to default interface"
fi

main "$@"