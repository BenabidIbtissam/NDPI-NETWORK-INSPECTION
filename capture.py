import ctypes
import pyshark
import pandas as pd
import threading
from datetime import datetime
import os

ndpi = ctypes.CDLL('/home/ibtissam/Desktop/Internship/nDPI-dev/src/lib/libndpi.so')
data = []
stop_capture = threading.Event()

output_dir = 'captures'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Updated scoring function with even more protocols
def score_protocol(protocol):
    scoring = {
        'HTTP': 10, 'HTTPS': 9, 'FTP': 8, 'TLS': 7, 'TCP': 6, 'UDP': 5,
        'ARP': 3, 'SSDP': 4, 'MDNS': 4, 'DNS': 7, 'ICMP': 5, 'SMTP': 8, 'SNMP': 6,
        'QUIC': 9, 'DHCP': 4, 'NBNS': 3, 'DATA': 2, 'SSH': 9, 'RDP': 10,
        'POP3': 8, 'IMAP': 7, 'BGP': 6, 'LDAP': 7, 'NTP': 5, 'SMB': 9,
        'Telnet': 10, 'SIP': 8, 'TFTP': 7, 'SFTP': 9, 'DCCP': 5, 'SCTP': 5,
        'LLDP': 4, 'OpenVPN': 8, 'WireGuard': 9, 'IKEv2': 7, 'ESP': 6, 'PPTP': 8
    }
    return scoring.get(protocol, 5)

def classify_risk(protocol):
    risk_categories = {
        'HTTP': 'Medium', 'HTTPS': 'Low', 'FTP': 'High', 'TLS': 'Medium', 'TCP': 'Low', 'UDP': 'Low',
        'ARP': 'Low', 'SSDP': 'Medium', 'MDNS': 'Medium', 'DNS': 'Medium', 'ICMP': 'Low', 'SMTP': 'High', 'SNMP': 'Medium',
        'QUIC': 'Low', 'DHCP': 'Low', 'NBNS': 'Low', 'DATA': 'Low', 'SSH': 'Low', 'RDP': 'High',
        'POP3': 'High', 'IMAP': 'Medium', 'BGP': 'Medium', 'LDAP': 'Medium', 'NTP': 'Low', 'SMB': 'High',
        'Telnet': 'High', 'SIP': 'Medium', 'TFTP': 'High', 'SFTP': 'Low', 'DCCP': 'Low', 'SCTP': 'Low',
        'LLDP': 'Low', 'OpenVPN': 'Medium', 'WireGuard': 'Medium', 'IKEv2': 'Low', 'ESP': 'Low', 'PPTP': 'High'
    }
    return risk_categories.get(protocol, 'Unknown')


# Function to score ports based on security risks
def score_ports(src_port, dst_port):
    non_secure_ports = {21, 23, 80, 110, 143}
    score = 0
    if int(src_port) in non_secure_ports:
        score += 10
    if int(dst_port) in non_secure_ports:
        score += 10
    return score

# Process each packet and save data to the CSV file
def process_packet(packet, output_file):
    try:
        protocol = packet.highest_layer
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport

        protocol_score = score_protocol(protocol)
        port_score = score_ports(src_port, dst_port)
        total_score = protocol_score + port_score
        risk = classify_risk(protocol)

        data.append({
            "Protocol": protocol,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Protocol Score": protocol_score,
            "Port Score": port_score,
            "Total Score": total_score,
            "Risk": risk
        })

        # Save to CSV file
        pd.DataFrame(data).to_csv(output_file, index=False)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start capturing packets on the specified network interface
def start_capture_func(interface='wlp1s0'):
    stop_capture.clear()  # Clear the stop event in case it was set previously

    # Generate a unique filename with date and time
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(output_dir, f"network_data_{timestamp}.csv")

    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture.sniff_continuously():
            if stop_capture.is_set():
                print("Stopping capture...")
                break
            process_packet(packet, output_file)
    except Exception as e:
        print(f"Error during packet capture: {e}")
    finally:
        capture.close()
        print(f"Capture saved to {output_file}.")
        print("Capture stopped.")

# Stop capturing packets
def stop_capture_func():
    stop_capture.set()

# Function to run the capture in a separate thread
def start_capture_thread(interface='wlp1s0'):
    capture_thread = threading.Thread(target=start_capture_func, args=(interface,))
    capture_thread.start()  