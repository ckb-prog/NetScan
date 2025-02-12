# NetScan
A network scanning tool
-----------------------
# NetScan - Advanced WiFi & Network Analysis Tool

## Overview

**NetScan** is an advanced Python-based tool for comprehensive WiFi and network analysis. It combines passive WiFi scanning using a monitor mode wireless interface with active ARP scanning on your local network via a standard managed interface. This tool gathers detailed information about available WiFi networks and connected devices, then saves the results in a user-specified output file.

> **Recommendation:**  
> For optimal results, it is highly recommended to use **two wireless devices**:
> - **One device in managed mode:**  
>   Used for your normal network connection and ARP scanning of connected devices.
> - **One device in monitor mode:**  
>   Dedicated solely to passive WiFi scanning.  
> This separation prevents interference and ensures both scanning methods work correctly.

## Disclaimer

This tool is intended for authorized network analysis and troubleshooting only. Unauthorized scanning or interference with networks without explicit permission is illegal. Use responsibly and at your own risk.

## Requirements

- **Operating System:** Linux (with appropriate wireless drivers)
- **Python Version:** Python 3.x
- **Dependencies:**
  - **Scapy:**  
    Install via pip:
    ```bash
    pip3 install scapy
    ```
    OR
    ```bash
    sudo apt install scapy
    ```
    
  - **Wireless Tools:**  
    Ensure utilities like `iwconfig` and `ip` are installed (typically available on most Linux distributions).
- **Privileges:**  
  Root privileges are required to perform packet sniffing and ARP scanning.

## Setup Instructions

### >- Two Wireless Devices (1 for ARP & 1 for Managed)

### 1. Preparing Your Wireless Devices

#### Standard (Managed) Device
- **Purpose:**  
  - Maintain your regular network connection (e.g., for Internet access).
  - Perform ARP scans to detect devices on your local network.
- **Configuration:**  
  - This device should remain in the default managed mode.
  - Verify its connectivity using:
    ```bash
    ip addr show
    ```

#### Monitor Mode Device
- **Purpose:**  
  - Dedicated to passive WiFi scanning.
- **Configuration:**
  - To enable monitor mode, use tools such as `airmon-ng`. For example:
    ```bash
    sudo airmon-ng start wlan1
    ```
    Replace `wlan1` with the name of your wireless device.
  - After enabling, the interface might be renamed (e.g., `wlan1mon`).  
    Confirm its mode with:
    ```bash
    iwconfig
    ```
    Look for an interface displaying `Mode:Monitor`.

### 2. Downloading and Preparing the Script

1. **Download the Script:**  
   Save the `NetScan.py` file to your preferred location.
2. **Make It Executable (Optional):**  
   To run the script directly, change its permissions:
   ```bash
   chmod +x NetScan.py
