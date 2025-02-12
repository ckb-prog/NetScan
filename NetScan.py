#!/usr/bin/env python3
"""
NetScan - Advanced WiFi & Network Analysis Tool

DISCLAIMER: This tool is intended for authorized network analysis only.
Unauthorized scanning of networks may be illegal.
Ensure that your wireless interface is in monitor mode and that you have the necessary privileges (typically root).
"""

import subprocess
import re
import sys
import socket
import ipaddress  # New import for proper network calculations
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, arping

# Data structures to store scan results
wifi_networks = {}  # WiFi networks from beacon frames (keyed by BSSID)
connected_devices = []  # Devices discovered via ARP scan

def find_monitor_interface():
    """
    Automatically detect a wireless interface in monitor mode using iwconfig.
    Returns the first interface found with "Mode:Monitor" in its iwconfig output.
    """
    try:
        output = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT).decode()
        interfaces = re.findall(r'^(\S+).*?Mode:Monitor', output, re.MULTILINE)
        if interfaces:
            return interfaces[0]
        else:
            return None
    except subprocess.CalledProcessError as e:
        print("Error executing iwconfig:", e)
        return None

def find_default_interface():
    """
    Automatically detect the default network interface using the 'ip route' command.
    Returns the interface name used for the default route.
    """
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"]).decode()
        match = re.search(r'dev (\S+)', output)
        if match:
            return match.group(1)
    except Exception as e:
        print("Error detecting default interface:", e)
    return None

def get_ip_network(iface):
    """
    Retrieves the local IP network (in CIDR format) for the given interface using 'ip -o -f inet addr show'.
    Converts the IP address with mask to the network address. For example, "192.168.1.100/24" becomes "192.168.1.0/24".
    """
    try:
        output = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show", iface]).decode()
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', output)
        if match:
            ip_interface = ipaddress.ip_interface(match.group(1))
            network = ip_interface.network
            return str(network)
    except Exception as e:
        print(f"Error getting IP network for interface {iface}: {e}")
    return None

def packet_handler(pkt):
    """
    Callback function for Scapy's sniff.
    Processes beacon frames and extracts WiFi network details.
    """
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", "N/A")
        if bssid not in wifi_networks:
            wifi_networks[bssid] = {
                "ssid": ssid,
                "channel": channel,
                "signal": signal,
                "encryption": crypto
            }
            print(f"Discovered WiFi -> BSSID: {bssid}, SSID: {ssid}, Channel: {channel}, Signal: {signal}, Encryption: {crypto}")

def get_hostname(ip):
    """
    Attempts to perform a reverse DNS lookup to resolve the hostname for a given IP address.
    Returns the hostname if found, otherwise returns "Unknown".
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def perform_arp_scan(ip_range):
    """
    Performs an ARP scan on the provided IP range using Scapy's arping.
    Returns a list of dictionaries for each discovered device with IP, MAC, and hostname.
    """
    print(f"Scanning for connected devices on network {ip_range} ...")
    devices = []
    try:
        answered, _ = arping(ip_range, verbose=0)
        for sent, received in answered:
            device_info = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": get_hostname(received.psrc)
            }
            devices.append(device_info)
            print(f"Device found -> IP: {device_info['ip']}, MAC: {device_info['mac']}, Hostname: {device_info['hostname']}")
    except Exception as e:
        print("Error during ARP scan:", e)
    return devices

def main():
    # 1. Detect monitor mode interface for WiFi scanning.
    monitor_iface = find_monitor_interface()
    if monitor_iface is None:
        print("No interface in monitor mode detected. Please enable monitor mode and try again.")
        sys.exit(1)
    print(f"Using monitor mode interface for WiFi scan: {monitor_iface}")

    # 2. Detect default (managed) network interface for ARP scanning.
    default_iface = find_default_interface()
    if default_iface is None:
        print("No default network interface detected. ARP scanning will be skipped.")
    else:
        print(f"Using default network interface for ARP scan: {default_iface}")
        ip_range = get_ip_network(default_iface)
        if ip_range:
            print(f"Detected IP network: {ip_range}")
        else:
            print("Could not determine IP network from the default interface. ARP scanning will be skipped.")
            default_iface = None

    # 3. Prompt the user for an output file name.
    output_file = input("Enter the output file name: ").strip()
    if not output_file:
        print("No file name provided. Exiting.")
        sys.exit(1)

    # 4. Start WiFi scanning via monitor mode.
    print("Starting WiFi scan. Press Ctrl+C to stop scanning or wait for the timeout (30 seconds).")
    try:
        sniff(prn=packet_handler, iface=monitor_iface, timeout=30)
    except KeyboardInterrupt:
        print("\nWiFi scan interrupted by user.")

    # 5. Perform ARP scan for connected devices if default interface is available.
    if default_iface and ip_range:
        global connected_devices
        connected_devices = perform_arp_scan(ip_range)
    else:
        print("Skipping ARP scan due to missing default interface or IP network info.")

    # 6. Write all collected data to the output file.
    try:
        with open(output_file, 'w') as f:
            f.write("========== WiFi Networks ==========\n")
            for bssid, info in wifi_networks.items():
                f.write(f"BSSID: {bssid}\n")
                f.write(f"SSID: {info['ssid']}\n")
                f.write(f"Channel: {info['channel']}\n")
                f.write(f"Signal: {info['signal']}\n")
                f.write(f"Encryption: {info['encryption']}\n")
                f.write("-" * 40 + "\n")

            f.write("\n========== Connected Devices (ARP Scan) ==========\n")
            if connected_devices:
                for device in connected_devices:
                    f.write(f"IP: {device['ip']}\n")
                    f.write(f"MAC: {device['mac']}\n")
                    f.write(f"Hostname: {device['hostname']}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("No connected devices detected via ARP scan.\n")
    except Exception as e:
        print(f"Error writing to file: {e}")
        sys.exit(1)

    print("DONE")

if __name__ == "__main__":
    main()
