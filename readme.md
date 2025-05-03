# VPNer - Simple sing-box configuration launcher with TUI

## Overview

VPNer is a terminal-based launcher for managing and switching between different proxy configurations for sing-box. It provides an interactive menu to select configurations and handles process management for the proxy connections.

## Features

- Interactive terminal menu with keyboard navigation

## Installation

### Prerequisites

- Linux system
- `sing-box` installed and in your PATH
- `cJSON` library for JSON parsing

### Build Instructions

1. Clone the repository
    ```bash
    git clone https://github.com/rmntgx/vpner.git
    ```
2. Download and install cJSON
3. Compile the program:
    ```bash
    make
    ```
4. Install the binary
    ```bash
    sudo make install
    ```
## Configuration

VPNer looks for its configuration file at:
- `$XDG_CONFIG_HOME/vpner/configs.json` or
- `~/.config/vpner/configs.json`

### Configuration File Format

Create a JSON file with your VPN configurations.
Example `configs.json` file:
```json
{
  "configs": [
    {
      "name": "Example server 1",
      "path": "/home/user/vpn_configs/example_config_1.json"
    },
    {
      "name": "Example server 2",
      "path": "/home/user/vpn_configs/example_config_2.json"
    }
  ]
}
```

### Controls

- **Up Arrow/k**: Move selection up
- **Down Arrow/j**: Move selection down
- **Enter**: Select configuration
- **q/Ctrl+C**: Quit without selection

