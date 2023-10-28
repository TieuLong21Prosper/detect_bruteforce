import csv
import time
from scapy.all import *
from collections import defaultdict

# Dictionary to store counts of login attempts per source IP and destination port
login_attempts = defaultdict(int)

def capture_packets(interface, timeout=45):
    captured_packets = []

    def packet_handler(packet):
        captured_packets.append(packet)
        detect_bruteforce_attacks(packet)

    try:
        print(".---------------------------------------------------------------------.")
        print(f"| \tCapturing packets on {interface} for {timeout} seconds] \t\t      |")
        print(".---------------------------------------------------------------------.")

        print(f"| Starting packet capture on the {interface} interface. Press Ctrl+C to stop. |")
        print(".---------------------------------------------------------------------.")

        sniff(iface=interface, prn=packet_handler, timeout=timeout)

    except KeyboardInterrupt:
        print("Stopping packet capture.")

    return captured_packets

def save_to_pcap(file_name, packets):
    wrpcap(file_name, packets)
    print(".---------------------------------------------------------------------.")
    print(f"| \t Writing packets to {file_name} \t      |")
    print(".---------------------------------------------------------------------.")

def convert_to_csv(packets, csv_file):
    with open(csv_file, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Time", "SrcIP ", "DstIP ", "SrcPort ", "DstPort ", "Protocol ", "Data "])

        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "N/A"
                dst_ip = "N/A"

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                data = packet[TCP].payload
            else:
                continue

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            csvwriter.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, data])
    print(".---------------------------------------------------------------------.")
    print(f"| \t Converting data to {csv_file} \t      |")
    print(".---------------------------------------------------------------------.")

# This function is used to detect whether it is attacked by bruteForce methods using the comparison between src_ip and dst_ip
# If they are the same network layer (3 octets alike) and the dst_ip sent network packets more than 3 times to the same dst_port it means (more than 3 times tried to authenticate)
# Then print alert 
def detect_bruteforce_attacks(packet, threshold=3):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        return

    if TCP in packet:
        dst_port = packet[TCP].dport
        payload = bytes(packet[TCP].payload)

        # Check if the packet contains FTP USER or PASS commands
        if b"USER" in payload or b"PASS" in payload:
            # Split IP addresses into octets
            src_octets = src_ip.split(".")
            dst_octets = dst_ip.split(".")

            # Check if the first three octets match (same network)
            if src_octets[:3] == dst_octets[:3]:
                key = (src_ip, dst_port)
                login_attempts[key] += 1

                # Check if the login attempts exceed the threshold
                if login_attempts[key] >= threshold:
                    print(f"ALERT: {src_ip} attempted {login_attempts[key]} logins to port {dst_port}!")



if __name__ == "__main__":
    pcap_file = "results_folder/net_packet.pcap"
    csv_file = "results_folder/net_packet.csv"
    interface = "en0"
    captured_packets = capture_packets(interface)
    save_to_pcap(pcap_file, captured_packets)
    convert_to_csv(captured_packets, csv_file)
