import pyshark

# Specify the network interface to capture packets from
interface = 'WiFi'  # Change this to your network interface name

# Specify the path to save the captured packets
output_pcap_file = 'B:/captred files/capture.pcap'

# Capture packets and write them to the output pcap file
capture = pyshark.LiveCapture(interface=interface, output_file=output_pcap_file)

# Start the packet capture process
try:
    capture.sniff(timeout=10)  # Capture packets for 10 seconds (you can adjust this)
except KeyboardInterrupt:
    print("Capture stopped by user.")

# Close the capture
capture.close()
