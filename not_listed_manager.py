import argparse

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

def log_not_listed_devices(not_listed_devices):
    # Your code here to write the not listed devices to the file
    with open("not_listed_devices.txt", "w") as file:
        for device in not_listed_devices:
            file.write(f"{device['ip']} {device['mac']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage devices that are not listed.")
    parser.add_argument("--devices-file", default="devices.txt", help="Path to the file containing all devices")
    parser.add_argument("--whitelist-file", default="whitelist.txt", help="Path to the file containing whitelisted devices")
    parser.add_argument("--blacklist-file", default="blacklist.txt", help="Path to the file containing blacklisted devices")
    args = parser.parse_args()

    devices = read_devices_from_file(args.devices_file)
    whitelist_devices = read_devices_from_file(args.whitelist_file)
    blacklist_devices = read_devices_from_file(args.blacklist_file)

    whitelist_macs = set(device["mac"] for device in whitelist_devices)
    blacklist_macs = set(device["mac"] for device in blacklist_devices)

    not_listed_devices = [device for device in devices if device["mac"] not in whitelist_macs and device["mac"] not in blacklist_macs]
    log_not_listed_devices(not_listed_devices)
