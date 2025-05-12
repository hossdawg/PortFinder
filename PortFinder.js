import subprocess
import sys

# Check and install required packages
required_packages = [
    ('netmiko', 'netmiko'),
    ('yaml', 'PyYAML'),
    ('cryptography', 'cryptography'),
    ('retry', 'retry'),
]

for import_name, package_name in required_packages:
    try:
        __import__(import_name)
    except ImportError:
        print(f"Installing required package: {package_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

# Now import the rest of the modules
from netmiko import ConnectHandler
from getpass import getpass
import ipaddress
import re
import yaml
import os
from cryptography.fernet import Fernet
from retry import retry

# Configuration
CONFIG_FILE = "config.yaml"
LOW_PORT_THRESHOLD = 5

# Generate or load encryption key
def get_encryption_key():
    key_file = ".encryption_key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    return open(key_file, "rb").read()

KEY = get_encryption_key()
cipher_suite = Fernet(KEY)

def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
            if config and 'password' in config:
                config['password'] = decrypt_password(config['password'])
            return config
    except (FileNotFoundError, yaml.YAMLError, KeyError):
        return None
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def save_config(host, username, password):
    config = {
        'host': host,
        'username': username,
        'password': encrypt_password(password)
    }
    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(config, f)

@retry(tries=3, delay=2, backoff=2, exceptions=(Exception))
def connect_with_retry(device):
    return ConnectHandler(**device)

def get_device_credentials():
    config = load_config()
    while True:
        try:
            # Always get fresh credentials on retry
            if not config:
                print("\nPlease enter new credentials:")
                host = input("Enter device IP address: ").strip()
                username = input("Enter username: ").strip()
                password = getpass("Enter password: ").strip()
            else:
                print("\nUsing saved credentials (press enter to keep current values):")
                host = input(f"Enter device IP address [{config['host']}]: ").strip() or config['host']
                username = input(f"Enter username [{config['username']}]: ").strip() or config['username']
                password = getpass("Enter new password (press enter to keep current): ").strip() or config['password']

            if not validate_ip_address(host):
                print("Invalid IP address format")
                config = None
                continue

            device = {
                'device_type': 'juniper_junos',
                'host': host,
                'username': username,
                'password': password,
            }

            print("Validating credentials...")
            net_connect = connect_with_retry(device)
            net_connect.disconnect()
            
            # Save credentials if new or changed
            save_config(host, username, password)
            print("Credentials validated and saved successfully!")
            return device
            
        except Exception as e:
            print(f"\nConnection failed: {e}")
            if config and input("Retry with new credentials? (y/n): ").lower() == 'y':
                config = None  # Force fresh credentials entry
                os.remove(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else None
            else:
                raise

def parse_hardware_output(output):
    fpc_pic_port_map = {}
    current_fpc = None
    current_pic = None

    for line in output.splitlines():
        line = line.strip()

        # Match FPC lines (e.g., "FPC 0")
        fpc_match = re.match(r"^FPC\s+(\d+)", line, re.IGNORECASE)
        if fpc_match:
            current_fpc = int(fpc_match.group(1))
            fpc_pic_port_map[current_fpc] = {}
            current_pic = None
            continue

        # Match PIC lines (e.g., "PIC 0")
        pic_match = re.match(r"^PIC\s+(\d+)", line, re.IGNORECASE)
        if pic_match and current_fpc is not None:
            current_pic = int(pic_match.group(1))
            port_groups_raw = re.findall(r"(\d+)x(\d+)[GT]", line, re.IGNORECASE)
            if port_groups_raw:
                port_groups = []
                current_start = 0
                for count_str, speed_str in port_groups_raw:
                    count = int(count_str)
                    speed = int(speed_str)
                    end = current_start + count - 1  # Inclusive range
                    port_groups.append({
                        "start": current_start,
                        "end": end,
                        "speed": speed
                    })
                    current_start += count  # Prepare for next group
                fpc_pic_port_map[current_fpc][current_pic] = {
                    "port_groups": port_groups,
                    "used_ports": set()
                }
            else:
                current_pic = None  # Skip PICs without valid port groups
            continue

        # Match Xcvr lines (e.g., "Xcvr 0")
        xcvr_match = re.match(r"^Xcvr\s+(\d+)", line, re.IGNORECASE)
        if xcvr_match and current_fpc is not None and current_pic is not None:
            used_port = int(xcvr_match.group(1))
            fpc_pic_port_map[current_fpc][current_pic]["used_ports"].add(used_port)

    return fpc_pic_port_map

def get_available_ports(fpc_pic_port_map):
    # Collect all ports as tuples for sorting
    port_entries = []
    for fpc, pic_map in sorted(fpc_pic_port_map.items()):
        for pic, pic_data in sorted(pic_map.items()):
            port_groups = pic_data["port_groups"]
            used_ports = pic_data["used_ports"]
            
            for group in port_groups:
                prefix = "et-" if group["speed"] >= 100 else "xe-"
                for port_num in range(group["start"], group["end"] + 1):
                    if port_num not in used_ports:
                        port_entries.append((fpc, pic, port_num, prefix))
    
    # Sort by FPC, PIC, and port number
    port_entries.sort(key=lambda x: (x[0], x[1], x[2]))
    
    # Format into interface names
    return [f"{prefix}{fpc}/{pic}/{port}" for fpc, pic, port, prefix in port_entries]

def get_described_interfaces(net_connect):
    described_interfaces = set()
    described_but_no_optic = {}  # Dictionary: {interface: description}
    
    output = net_connect.send_command("show interfaces descriptions")
    for line in output.splitlines():
        line = line.strip()
        parts = re.split(r'\s{2,}', line)  # Split on 2+ spaces
        
        if not parts or len(parts) < 2:
            continue
            
        interface = parts[0]
        # Match only main interfaces (no subinterfaces)
        if re.match(r"^(ge|xe|et)-\d+/\d+/\d+$", interface):
            # Check if status columns are present
            status_present = False
            description = ""
            
            if len(parts) >= 3 and parts[1] in ('up', 'down') and parts[2] in ('up', 'down'):
                # Format: Interface  Admin  Link  Description
                status_present = True
                description = ' '.join(parts[3:]) if len(parts) > 3 else ""
            else:
                # Format: Interface  Description (no status)
                description = ' '.join(parts[1:]) if len(parts) > 1 else ""
            
            described_interfaces.add(interface)
            
            if not status_present and description:
                described_but_no_optic[interface] = description
    
    return described_interfaces, described_but_no_optic

def interface_sort_key(interface):
    """Helper to sort interfaces numerically (FPC/PIC/port)"""
    match = re.match(r".*-(\d+)/(\d+)/(\d+)$", interface)
    if match:
        return tuple(map(int, match.groups()))
    return (9999, 9999, 9999)  # Fallback for invalid format

def main():
    try:
        device = get_device_credentials()
        net_connect = ConnectHandler(**device)
        
        hardware_output = net_connect.send_command("show chassis hardware")
        fpc_pic_port_map = parse_hardware_output(hardware_output)
        available_ports = get_available_ports(fpc_pic_port_map)
        
        # Get both described interfaces and no-optic ports in one call
        described_interfaces, no_optic_ports = get_described_interfaces(net_connect)

        # Filter available ports
        available_ports = [
            port for port in available_ports
            if (port not in described_interfaces) and 
               (port.replace("xe-", "ge-", 1) not in described_interfaces)
        ]

        # Print results
        print("\n" + "="*50)
        if available_ports:
            print("Available ports:")
            for port in available_ports:
                print(f"  {port}")
        else:
            print("No available ports found")

        if no_optic_ports:
            print("\nPorts with description but no optic:")
            sorted_ports = sorted(no_optic_ports.items(), 
                                key=lambda x: interface_sort_key(x[0]))
            for interface, desc in sorted_ports:
                print(f"  {interface}: {desc}")

        if len(available_ports) < LOW_PORT_THRESHOLD:
            print(f"\nALERT: Only {len(available_ports)} available ports remaining!")
        print("="*50)

        net_connect.disconnect()

    except Exception as e:
        print(f"\nCritical error: {e}")
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)

if __name__ == "__main__":
    main()
