from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    """Callback function to process each captured packet"""
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        # Protocol mapping
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(proto, "Other")

        print(f"\n[+] New Packet:")
        print(f"    Source IP      : {src}")
        print(f"    Destination IP : {dst}")
        print(f"    Protocol       : {proto_name}")

        # Handle TCP/UDP packet details
        if proto_name == "TCP" and TCP in packet:
            tcp_layer = packet[TCP]
            print(f"    Source Port    : {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
        elif proto_name == "UDP" and UDP in packet:
            udp_layer = packet[UDP]
            print(f"    Source Port    : {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")
        elif proto_name == "ICMP" and ICMP in packet:
            print("    Type           : ICMP Packet")

        print("-" * 50)

def main():
    print("🔍 Starting Network Packet Sniffer...")
    print("Press Ctrl+C to stop.\n")

    # Capture packets on the default interface
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
