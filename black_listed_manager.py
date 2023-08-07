from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def read_blacklist(filename):
    blacklist = []
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                if line:
                    ip, mac = line.split()
                    blacklist.append({"ip": ip, "mac": mac})
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    return blacklist


def deauthenticate(iface, bssid, target_mac):
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap() / dot11 / Dot11Deauth()
    sendp(frame, iface=iface, count=100, inter=0.1, verbose=True)

if __name__ == "__main__":
    iface = "WiFi"  # Replace with the actual network interface name
    bssid = "f4:92:bf:22:22:9a"  # Replace with the actual BSSID of your access point
    blacklist_file = "blacklist.txt"
    
    blacklist_devices = read_blacklist(blacklist_file)
    
    for device in blacklist_devices:
        print(f"Deauthenticating device with IP: {device['ip']} - MAC: {device['mac']}")
        deauthenticate(iface, bssid, device["mac"])
