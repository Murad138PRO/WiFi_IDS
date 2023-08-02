from scapy.all import ARP, Ether, srp

def scan_network(interface, ip_range):
    try:
        # Create ARP request packet
        arp_request = ARP(pdst=ip_range)

        # Create Ethernet frame to broadcast ARP request
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine ARP request and Ethernet frame
        packet = ether_frame / arp_request

        # Send the packet and get responses
        result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

        # Extract IP and MAC addresses from the responses
        devices = []
        for sent, received in result:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})

        return devices

    except Exception as e:
        print("Error:", e)
        return []

if __name__ == "__main__":
    # Replace "eth0" with your network interface (e.g., "en0" on macOS, "eth0" on Linux, or "Wi-Fi" on Windows)
    interface = "WiFi"
    # Replace "192.168.0.1/24" with your desired IP range (e.g., "192.168.1.0/24")
    ip_range = "192.168.0.1/24"

    devices = scan_network(interface, ip_range)

    print("Connected devices:")
    for device in devices:
        print(f"IP: {device['ip']} - MAC: {device['mac']}")
