# Auto Tunnel

Auto Tunnel is a PowerShell script that automatically manages VPN connections and SSH tunnels. It monitors your VPN connection and establishes an SSH tunnel when the VPN is active, ensuring secure and persistent access to remote resources.

## Features

- Automatic VPN connection detection
- SSH tunnel management
- Configurable settings via JSON file
- Robust logging system with log rotation and compression
- Credential management for secure password handling

## Prerequisites

- PowerShell 5.1 or later
- Windows Subsystem for Linux (WSL) with a compatible distribution
- SSH client installed in the WSL environment
- CredentialManager PowerShell module

## Installation

1. Clone this repository or download the `auto_tunnel.ps1` script.
2. Ensure you have WSL installed with a compatible Linux distribution.
3. Install the CredentialManager module by running:
   ```powershell
   Install-Module -Name CredentialManager -Force -Scope CurrentUser
   ```
4. Create a configuration file named `auto_tunnel_config.json` in the same directory as the script.

## Configuration

Create a `auto_tunnel_config.json` file with the following structure:
```json
{
    "vpnProcessName": "ivpnservice",
    "vpnRoutePrefix": "10.",
    "remoteHost": "your.ssh.tunnel.server",
    "sshUser": "your_ssh_username",
    "sshKeyPath": "/path/to/your/ssh/key_in_wsl",
    "localPort": 8080,
    "wslDistribution": "Ubuntu-24.04",
    "wslUser": "your_wsl_username",
    "credentialTarget": "YourCredentialTarget",
    "mainLoopSleepSeconds": 30,
    "logLevel": "INFO",
    "logCompressionInterval": "1d",
    "logCompressOlderThan": "7d",
    "sshTunnelCheckCommand": "ps aux | grep ssh | grep -v grep"
}
```

### Configuration Options

- `vpnProcessName`: The name of the VPN service process to check for.
- `vpnRoutePrefix`: The IP route prefix associated with your VPN connection.
- `remoteHost`: The hostname or IP address of your SSH server.
- `sshUser`: Your SSH username for the remote server.
- `sshKeyPath`: The path to your SSH private key file.
- `localPort`: The local port to use for the SOCKS proxy.
- `wslDistribution`: The name of your WSL distribution.
- `wslUser`: Your username in the WSL environment.
- `credentialTarget`: The name of the credential stored in Windows Credential Manager.
- `mainLoopSleepSeconds`: The interval (in seconds) between main loop iterations.
- `logLevel`: The minimum log level to record (DEBUG, INFO, WARNING, or ERROR).
- `logCompressionInterval`: How often to compress logs (e.g., "1d" for daily).
- `logCompressOlderThan`: Age threshold for compressing logs (e.g., "7d" for 7 days).
- `sshTunnelCheckCommand`: The command used to check if the SSH tunnel is active.

## Usage

1. Set up your configuration in `auto_tunnel_config.json`.
2. Store your SSH password in Windows Credential Manager with the target name specified in `credentialTarget`.
3. Run the script in PowerShell:
   ```powershell
   .\auto_tunnel.ps1
   ```

The script will run continuously, monitoring your VPN connection and managing the SSH tunnel.

## Logging

Logs are stored in the same directory as the script, with the naming convention `auto_tunnel-YYYY-MM-DD.log`. Logs are automatically compressed and rotated based on the configuration settings.

## Troubleshooting

- Ensure all paths in the configuration file are correct and accessible.
- Check the log files for detailed error messages and debugging information.
- Verify that the VPN process name and route prefix match your VPN configuration.
- Ensure the SSH key has the correct permissions and is accessible from the WSL environment.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.