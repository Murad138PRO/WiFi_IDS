import pyshark

# Load the PCAP file using pyshark
pcap_file_path = 'B:\captred files\capture.pcap'
cap = pyshark.FileCapture(pcap_file_path)

# Initialize lists to store IP and MAC addresses
ip_addresses = set()
mac_addresses = set()

# Iterate through packets and extract IP and MAC addresses
for packet in cap:
    if 'ip' in packet:
        ip_addresses.add(packet.ip.src)
        ip_addresses.add(packet.ip.dst)
    if 'eth' in packet:
        mac_addresses.add(packet.eth.src)
        mac_addresses.add(packet.eth.dst)

# Close the packet capture
cap.close()

# Display the extracted IP and MAC addresses
print("Extracted IP addresses:")
for idx, ip in enumerate(ip_addresses, start=1):
    print(f"{idx}. {ip}")

print("\nExtracted MAC addresses:")
for idx, mac in enumerate(mac_addresses, start=1):
    print(f"{idx}. {mac}")

# Ask the user if they want to add IP and MAC addresses to the blacklist
blacklist_entries = []

while True:
    choice = input("Do you want to add any of these addresses to the blacklist? (y/n): ")
    if choice.lower() == 'n':
        break
    elif choice.lower() != 'y':
        print("Invalid choice. Please enter 'y' or 'n'.")
        continue

    ip_num = input("Enter the number of the IP to add to the blacklist: ")
    try:
        ip_num = int(ip_num)
        ip_to_add = list(ip_addresses)[ip_num - 1]

        mac_num = input("Enter the number of the MAC to add to the blacklist: ")
        mac_to_add = list(mac_addresses)[int(mac_num) - 1]

        blacklist_entries.append(f"{ip_to_add} {mac_to_add}")
    except (ValueError, IndexError):
        print("Invalid input. Please enter valid numbers.")

# Print and save the blacklisted entries to blacklist.txt
with open('blacklist.txt', 'a') as file:
    for entry in blacklist_entries:
        file.write(f"{entry}\n")

print("\nBlacklisted entries added to the blacklist.txt file.")
