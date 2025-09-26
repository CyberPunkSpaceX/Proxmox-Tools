#!/bin/bash
# Debian 12 Proxmox VPS Installation Script - Complete with Hostname Fix
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

check_debian() {
    log "Checking Debian version..."
    local debian_version=$(lsb_release -rs 2>/dev/null || echo "unknown")
    local debian_codename=$(lsb_release -cs 2>/dev/null || echo "unknown")
    if [[ "$debian_codename" != "bookworm" && "$debian_version" != "12"* ]]; then
        warning "Detected: $debian_version ($debian_codename)"
        warning "Recommended: Debian 12 (Bookworm)"
        read -p "Continue anyway? [y/N]: " continue_other
        if [[ ! $continue_other =~ ^[Yy]$ ]]; then exit 1; fi
    fi
    log "Debian version OK: $debian_version ($debian_codename)"
}

validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -lt 0 || $i -gt 255 ]]; then return 1; fi
        done
        return 0
    fi
    return 1
}

get_ip_input() {
    local prompt=$1
    local ip
    while true; do
        read -p "$prompt: " ip
        if validate_ip "$ip"; then
            echo "$ip"
            break
        else
            error "Invalid IP format. Try again."
        fi
    done
}

get_cidr_input() {
    local prompt=$1
    local cidr
    while true; do
        read -p "$prompt (e.g., 192.168.1.10/24): " cidr
        if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            local ip_part=$(echo $cidr | cut -d'/' -f1)
            local subnet_part=$(echo $cidr | cut -d'/' -f2)
            if validate_ip "$ip_part" && [[ $subnet_part -ge 1 && $subnet_part -le 32 ]]; then
                echo "$cidr"
                break
            fi
        fi
        error "Invalid CIDR format. Use format like 192.168.1.10/24"
    done
}

detect_network() {
    log "Auto-detecting network configuration..."
    CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    CURRENT_GW=$(ip route | awk '/default/ {print $3; exit}')
    MAIN_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    
    # Get subnet mask
    SUBNET_MASK=$(ip addr show "$MAIN_INTERFACE" | grep "$CURRENT_IP/" | awk '{print $2}' | cut -d'/' -f2)
    if [[ -z "$SUBNET_MASK" ]]; then
        SUBNET_MASK="24"
        warning "Could not detect subnet mask, using /24"
    fi
    
    PUBLIC_IP="$CURRENT_IP/$SUBNET_MASK"
    GATEWAY_IP="$CURRENT_GW"
    
    info "Auto-detected network configuration:"
    info "  Interface: $MAIN_INTERFACE"
    info "  Main Public IP: $PUBLIC_IP"
    info "  Gateway: $GATEWAY_IP"
    echo
    read -p "Is this network configuration correct? [Y/n]: " network_correct
    if [[ $network_correct =~ ^[Nn]$ ]]; then
        warning "Auto-detection failed. Manual input required."
        PUBLIC_IP=$(get_cidr_input "Enter main public IP with CIDR")
        GATEWAY_IP=$(get_ip_input "Enter gateway IP")
    fi
}

get_additional_ips() {
    local additional_ips=()
    echo
    info "=== Additional Public IP Configuration ==="
    info "You can add additional public IPs for VMs/containers"
    read -p "Add additional public IP addresses? [y/N]: " add_ips
    
    if [[ ! $add_ips =~ ^[Yy]$ ]]; then
        info "No additional IPs configured"
        ADDITIONAL_PUBLIC_IPS=()
        return 0
    fi
    
    local count=1
    while true; do
        echo
        info "Additional IP #$count:"
        local additional_ip
        additional_ip=$(get_cidr_input "Enter additional public IP with CIDR")
        
        if [[ "$additional_ip" == "$PUBLIC_IP" ]]; then
            error "Cannot use same IP as main public IP"
            continue
        fi
        
        local already_added=false
        for existing_ip in "${additional_ips[@]}"; do
            if [[ "$existing_ip" == "$additional_ip" ]]; then
                error "IP already added"
                already_added=true
                break
            fi
        done
        if [[ "$already_added" == true ]]; then continue; fi
        
        additional_ips+=("$additional_ip")
        info "Added: $additional_ip"
        
        read -p "Add another IP? [y/N]: " add_more
        if [[ ! $add_more =~ ^[Yy]$ ]]; then break; fi
        
        count=$((count + 1))
        if [[ $count -gt 10 ]]; then
            warning "Maximum 10 IPs reached"
            break
        fi
    done
    
    ADDITIONAL_PUBLIC_IPS=("${additional_ips[@]}")
    
    if [[ ${#additional_ips[@]} -gt 0 ]]; then
        echo
        info "Additional public IPs configured:"
        for ip in "${additional_ips[@]}"; do
            info "  - $ip"
        done
    fi
}

get_bridge_config() {
    echo
    info "=== Bridge Network Configuration ==="
    info "Configure internal network bridges (vmbr1-vmbr5) for private VM networks"
    info "Default bridge configurations:"
    info "  vmbr1: 10.195.195.254/24"
    info "  vmbr2: 10.195.196.254/24" 
    info "  vmbr3: 10.195.197.254/24"
    info "  vmbr4: 10.195.198.254/24"
    info "  vmbr5: 10.195.199.254/24"
    echo
    read -p "Use default bridge configurations? [Y/n]: " use_defaults
    
    declare -g -A BRIDGE_IPS
    if [[ $use_defaults =~ ^[Nn]$ ]]; then
        info "Custom bridge configuration..."
        for i in {1..5}; do
            echo
            info "Bridge vmbr$i configuration:"
            read -p "Assign IP to vmbr$i? [y/N]: " assign_ip
            if [[ $assign_ip =~ ^[Yy]$ ]]; then
                BRIDGE_IPS["vmbr$i"]=$(get_cidr_input "Enter IP for vmbr$i")
            else
                BRIDGE_IPS["vmbr$i"]="none"
                info "vmbr$i will be created without IP (manual configuration)"
            fi
        done
    else
        info "Using default bridge configurations..."
        BRIDGE_IPS["vmbr1"]="10.195.195.254/24"
        BRIDGE_IPS["vmbr2"]="10.195.196.254/24"
        BRIDGE_IPS["vmbr3"]="10.195.197.254/24"
        BRIDGE_IPS["vmbr4"]="10.195.198.254/24"
        BRIDGE_IPS["vmbr5"]="10.195.199.254/24"
    fi
}

get_password() {
    local password
    local confirm_password
    echo
    info "=== Proxmox Root Password Configuration ==="
    while true; do
        read -s -p "Enter root password for Proxmox: " password
        echo
        read -s -p "Confirm password: " confirm_password
        echo
        if [[ "$password" == "$confirm_password" ]]; then
            if [[ ${#password} -ge 8 ]]; then
                ROOT_PASSWORD="$password"
                log "Password configured successfully"
                break
            else
                error "Password must be at least 8 characters"
            fi
        else
            error "Passwords don't match"
        fi
    done
}

show_configuration_summary() {
    echo
    info "=== Configuration Summary ==="
    info "Hostname: $(hostname)"
    info "Main Public IP: $PUBLIC_IP"
    info "Gateway: $GATEWAY_IP"
    info "Interface: $MAIN_INTERFACE"
    
    if [[ ${#ADDITIONAL_PUBLIC_IPS[@]} -gt 0 ]]; then
        info "Additional Public IPs:"
        for ip in "${ADDITIONAL_PUBLIC_IPS[@]}"; do
            info "  - $ip"
        done
    else
        info "Additional Public IPs: None"
    fi
    
    info "Bridge Networks:"
    info "  vmbr0: $PUBLIC_IP (Main bridge for VMs with internet)"
    for i in {1..5}; do
        if [[ "${BRIDGE_IPS["vmbr$i"]}" != "none" ]]; then
            info "  vmbr$i: ${BRIDGE_IPS["vmbr$i"]} (Private network)"
        else
            info "  vmbr$i: Manual configuration (no IP assigned)"
        fi
    done
    
    echo
    warning "This installs FREE Proxmox VE (no enterprise features)"
    warning "Network configuration will be modified!"
    echo
}

update_system() {
    log "Updating system packages..."
    apt update
    DEBIAN_FRONTEND=noninteractive apt upgrade -y
    DEBIAN_FRONTEND=noninteractive apt install -y curl wget gnupg2 apt-transport-https ca-certificates lsb-release bridge-utils ifupdown2
    log "System update completed"
}

fix_hostname_resolution() {
    log "Fixing hostname resolution for Proxmox..."
    
    local hostname=$(hostname)
    local current_ip=$(echo "$PUBLIC_IP" | cut -d'/' -f1)
    local fqdn="${hostname}.localdomain"
    
    info "Setting up hostname resolution:"
    info "  Hostname: $hostname"
    info "  IP: $current_ip"
    info "  FQDN: $fqdn"
    
    # Backup current /etc/hosts
    cp /etc/hosts /etc/hosts.backup
    
    # Create proper /etc/hosts file
    cat > /etc/hosts << EOF
127.0.0.1       localhost
127.0.1.1       ${fqdn} ${hostname}
${current_ip}   ${fqdn} ${hostname}

# The following lines are desirable for IPv6 capable hosts
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF
    
    log "Hostname resolution configured properly"
}

install_proxmox() {
    log "Installing Proxmox VE..."
    
    # Add Proxmox repository
    cat > /etc/apt/sources.list.d/pve-no-subscription.list << EOF
# Proxmox VE No-Subscription Repository (FREE)
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
EOF
    
    # Add Proxmox key
    wget -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg
    
    if [[ ! -f /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg ]]; then
        error "Failed to download Proxmox key"
        exit 1
    fi
    
    # Update and install
    apt update
    DEBIAN_FRONTEND=noninteractive apt install -y proxmox-ve postfix open-iscsi chrony
    
    # Configure postfix
    debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure postfix
    
    log "Proxmox installation completed"
}

configure_network() {
    log "Configuring Proxmox network..."
    
    # Backup current config
    cp /etc/network/interfaces /etc/network/interfaces.backup
    log "Backed up current network config"
    
    # Create new network config
    cat > /etc/network/interfaces << EOF
# Proxmox VE Network Configuration
source /etc/network/interfaces.d/*

# Loopback interface
auto lo
iface lo inet loopback

# Physical interface (bridged mode)
auto $MAIN_INTERFACE
iface $MAIN_INTERFACE inet manual

# Main Proxmox bridge (vmbr0) - for VMs with internet access
auto vmbr0
iface vmbr0 inet static
    address $PUBLIC_IP
    gateway $GATEWAY_IP
    bridge-ports $MAIN_INTERFACE
    bridge-stp off
    bridge-fd 0
    bridge-maxwait 0
    dns-nameservers 8.8.8.8 8.8.4.4 1.1.1.1
EOF

    # Add additional public IPs if configured
    if [[ ${#ADDITIONAL_PUBLIC_IPS[@]} -gt 0 ]]; then
        log "Adding ${#ADDITIONAL_PUBLIC_IPS[@]} additional public IPs"
        local count=1
        for ip in "${ADDITIONAL_PUBLIC_IPS[@]}"; do
            cat >> /etc/network/interfaces << EOF

# Additional public IP $count
auto vmbr0:$count
iface vmbr0:$count inet static
    address $ip
EOF
            count=$((count + 1))
        done
    fi

    # Add internal bridges (vmbr1-5) for private VM networks
    for i in {1..5}; do
        if [[ "${BRIDGE_IPS["vmbr$i"]}" != "none" ]]; then
            cat >> /etc/network/interfaces << EOF

# Internal bridge vmbr$i (private network)
auto vmbr$i
iface vmbr$i inet static
    address ${BRIDGE_IPS["vmbr$i"]}
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOF
        else
            cat >> /etc/network/interfaces << EOF

# Internal bridge vmbr$i (private network - manual)
auto vmbr$i
iface vmbr$i inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOF
        fi
    done

    log "Network configuration created successfully"
}

configure_proxmox() {
    log "Configuring Proxmox..."
    
    # Remove enterprise repositories
    rm -f /etc/apt/sources.list.d/pve-enterprise.list
    rm -f /etc/apt/sources.list.d/ceph.list
    
    # Ensure free repo is configured
    cat > /etc/apt/sources.list.d/pve-no-subscription.list << EOF
# Proxmox VE No-Subscription Repository (FREE)
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
EOF
    
    # Clean and update
    apt clean
    apt update
    
    # Remove old kernel
    apt remove -y linux-image-amd64 'linux-image-6.1.*' 2>/dev/null || true
    update-grub
    
    # Full upgrade
    DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
    
    # Enable services (they will start after reboot with proper hostname resolution)
    local services=("pve-cluster" "pve-guests" "pvestatd" "pvedaemon" "pveproxy" "pve-firewall")
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            log "Enabling: $service"
            systemctl enable "$service" 2>/dev/null || true
        fi
    done
    
    # Remove subscription nag (if file exists)
    if [[ -f /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js ]]; then
        sed -i.backup "s/data.status !== 'Active'/false/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js 2>/dev/null || true
    fi
    
    log "Proxmox configuration completed"
}

set_password() {
    log "Setting root password..."
    echo "root:$ROOT_PASSWORD" | chpasswd
    log "Password set successfully"
}

create_post_reboot_script() {
    log "Creating post-reboot service initialization script..."
    
    # Create script that will run after reboot to ensure services start properly
    cat > /usr/local/bin/proxmox-post-reboot.sh << 'EOF'
#!/bin/bash
# Proxmox Post-Reboot Service Initialization

LOG_FILE="/var/log/proxmox-post-reboot.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date)] Starting Proxmox post-reboot initialization..."

# Wait for network to be fully up
sleep 10

# Ensure hostname resolution is correct
hostname=$(hostname)
current_ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "")
fqdn="${hostname}.localdomain"

if [[ -n "$current_ip" ]]; then
    # Update /etc/hosts to ensure proper resolution
    if ! grep -q "^${current_ip}.*${hostname}" /etc/hosts; then
        echo "${current_ip}   ${fqdn} ${hostname}" >> /etc/hosts
        echo "Updated /etc/hosts with current IP: $current_ip"
    fi
fi

# Start services in proper order
echo "Starting Proxmox services..."

systemctl start pve-cluster
sleep 5

systemctl start pvedaemon
sleep 3

systemctl start pvestatd
sleep 3  

systemctl start pveproxy
sleep 2

# Check service status
echo "Service status:"
for service in pve-cluster pvedaemon pvestatd pveproxy; do
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service: Running"
    else
        echo "✗ $service: Failed"
        systemctl restart "$service" 2>/dev/null || true
    fi
done

echo "[$(date)] Proxmox post-reboot initialization completed"
EOF

    chmod +x /usr/local/bin/proxmox-post-reboot.sh
    
    # Create systemd service to run the script after boot
    cat > /etc/systemd/system/proxmox-post-reboot.service << EOF
[Unit]
Description=Proxmox Post-Reboot Service Initialization
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/proxmox-post-reboot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable proxmox-post-reboot.service
    log "Post-reboot service created and enabled"
}

create_recovery() {
    log "Creating recovery script..."
    cat > /root/network-recovery.sh << 'EOF'
#!/bin/bash
echo "=== Proxmox Network Recovery Script ==="
echo "This script will restore your network connectivity"
echo

# Method 1: Restore original config
echo "Method 1: Restoring original network configuration..."
if [[ -f /etc/network/interfaces.backup ]]; then
    cp /etc/network/interfaces.backup /etc/network/interfaces
    echo "Original configuration restored"
    
    # Restart networking
    echo "Restarting networking services..."
    systemctl restart networking 2>/dev/null || true
    systemctl restart systemd-networkd 2>/dev/null || true
    
    sleep 5
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "SUCCESS: Network connectivity restored!"
        exit 0
    fi
fi

# Method 2: Manual interface restart
echo "Method 2: Manual interface configuration..."
INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
if [[ -n "$INTERFACE" ]]; then
    echo "Bringing up interface $INTERFACE..."
    ip link set "$INTERFACE" up
    dhclient "$INTERFACE" 2>/dev/null || true
    sleep 5
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "SUCCESS: Network restored via DHCP!"
        exit 0
    fi
fi

echo "FAILED: Manual recovery needed"
echo "Try: systemctl reboot"
echo "Or contact your VPS provider for console access"
EOF
    chmod +x /root/network-recovery.sh
    log "Recovery script created: /root/network-recovery.sh"
}

show_final_summary() {
    log "Installation completed successfully!"
    echo
    info "=== Proxmox VE Installation Summary ==="
    info "Hostname: $(hostname)"
    info "Main IP: $PUBLIC_IP"
    info "Gateway: $GATEWAY_IP"
    info "Interface: $MAIN_INTERFACE"
    
    if [[ ${#ADDITIONAL_PUBLIC_IPS[@]} -gt 0 ]]; then
        info "Additional IPs configured: ${#ADDITIONAL_PUBLIC_IPS[@]}"
        for ip in "${ADDITIONAL_PUBLIC_IPS[@]}"; do
            info "  - $ip"
        done
    fi
    
    echo
    info "=== Access Information ==="
    info "Web Interface: https://$CURRENT_IP:8006"
    if [[ ${#ADDITIONAL_PUBLIC_IPS[@]} -gt 0 ]]; then
        info "Alternative URLs:"
        for ip in "${ADDITIONAL_PUBLIC_IPS[@]}"; do
            local ip_only=$(echo "$ip" | cut -d'/' -f1)
            info "  - https://$ip_only:8006"
        done
    fi
    info "Username: root"
    info "Password: [as configured]"
    echo
    info "=== Network Bridges ==="
    info "vmbr0: $PUBLIC_IP (Main - VMs with internet)"
    for i in {1..5}; do
        if [[ "${BRIDGE_IPS["vmbr$i"]}" != "none" ]]; then
            info "vmbr$i: ${BRIDGE_IPS["vmbr$i"]} (Private network)"
        else
            info "vmbr$i: Manual configuration (no IP)"
        fi
    done
    echo
    info "=== Important Notes ==="
    warning "REBOOT REQUIRED to activate network and service changes!"
    warning "Services will auto-start properly after reboot with hostname fix"
    warning "FREE version - no enterprise features available"
    info "Recovery script available: /root/network-recovery.sh"
    info "Post-reboot log: /var/log/proxmox-post-reboot.log"
    echo
    read -p "Reboot now? (strongly recommended) [Y/n]: " do_reboot
    if [[ ! $do_reboot =~ ^[Nn]$ ]]; then
        log "Rebooting..."
        sleep 3
        reboot
    else
        warning "Remember to reboot: systemctl reboot"
        warning "Services may not start properly until reboot!"
    fi
}

main() {
    log "Starting Debian 12 Proxmox VPS installation with hostname fix..."
    
    check_root
    check_debian
    
    echo
    info "========================================"
    info "  Debian 12 Proxmox VPS Installer"
    info "  WITH HOSTNAME RESOLUTION FIX"
    info "========================================"
    echo
    warning "CRITICAL SAFETY WARNINGS:"
    warning "- This modifies network configuration"
    warning "- Ensure console/KVM access is available"
    warning "- Wrong settings will break connectivity"
    warning "- Recovery script will be created"
    echo
    error "DO NOT PROCEED without console access!"
    read -p "I have console/KVM access [type 'YES']: " safety_confirm
    if [[ "$safety_confirm" != "YES" ]]; then
        error "Cancelled for safety"
        exit 1
    fi
    
    # Configuration gathering
    detect_network
    get_additional_ips
    get_bridge_config
    get_password
    show_configuration_summary
    
    read -p "Continue with installation? [y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        info "Installation cancelled"
        exit 0
    fi
    
    # Installation process with hostname fix
    update_system
    fix_hostname_resolution
    install_proxmox
    configure_network
    configure_proxmox
    set_password
    create_post_reboot_script
    create_recovery
    show_final_summary
}

main "$@"