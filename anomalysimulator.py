from scapy.all import IP, UDP, ICMP, send, Raw
import time

def send_packet(packet, description):
    """Send a packet and print its description."""
    try:
        send(packet, verbose=False)
        print(f"Sent: {description}")
    except Exception as e:
        print(f"Error sending {description}: {e}")

def invalid_ips():
    """Send packets with invalid source or destination IPs."""
    print("Sending packets with invalid IPs...")
    try:
        # Using non-routable but valid-looking IPs
        packet = IP(src="0.0.0.0", dst="127.0.0.1") / UDP(sport=12345, dport=80)
        send_packet(packet, "Non-routable Source IP")

        packet = IP(src="127.0.0.1", dst="0.0.0.0") / UDP(sport=12345, dport=80)
        send_packet(packet, "Non-routable Destination IP")

        # Directly modify the raw bytes for a truly invalid IP
        raw_packet = bytes(IP(src="192.0.2.1", dst="127.0.0.1") / UDP(sport=12345, dport=80))
        modified_packet = raw_packet[:12] + b'\xFF\xFF\xFF\xFF' + raw_packet[16:]
        send(Raw(load=modified_packet), verbose=False)
        print("Sent packet with raw invalid IP bytes")
    except Exception as e:
        print(f"Error in invalid_ips: {e}")

def unusual_protocols():
    """Send packets with unusual protocol numbers."""
    print("Sending packets with unusual protocols...")
    try:
        for proto in [255, 254, 99]:  # Reserved or unusual protocols
            packet = IP(src="10.0.0.99", dst="127.0.0.1", proto=proto) / Raw(load="Unusual Protocol")
            send_packet(packet, f"Protocol {proto}")
    except Exception as e:
        print(f"Error in unusual_protocols: {e}")

def abnormal_packet_sizes():
    """Send packets with abnormally large and small sizes."""
    print("Sending abnormally large and small packets...")
    try:
        # Large packet
        large_packet = IP(src="10.0.0.99", dst="127.0.0.1") / UDP(sport=12345, dport=80) / ("X" * 65000)
        send_packet(large_packet, "Large Packet (65000 bytes)")

        # Small packet
        small_packet = IP(src="10.0.0.99", dst="127.0.0.1") / UDP(sport=12345, dport=80)
        send_packet(small_packet, "Small Packet")
    except Exception as e:
        print(f"Error in abnormal_packet_sizes: {e}")

def malformed_packets():
    """Send malformed packets with incomplete headers."""
    print("Sending malformed packets...")
    try:
        for _ in range(5):
            packet = IP() / Raw(load="Malformed Packet")  # No src/dst IPs
            send_packet(packet, "Malformed Packet")
    except Exception as e:
        print(f"Error in malformed_packets: {e}")

def high_frequency_packets():
    """Send a flood of packets in quick succession."""
    print("Sending high-frequency packet flood...")
    try:
        for i in range(100):  # Adjust number for more or less flooding
            packet = IP(src="10.0.0.99", dst="127.0.0.1") / ICMP()
            send_packet(packet, f"Flood Packet {i+1}")
    except Exception as e:
        print(f"Error in high_frequency_packets: {e}")

if __name__ == "__main__":
    print("Starting anomaly simulation...")

    invalid_ips()
    time.sleep(1)

    unusual_protocols()
    time.sleep(1)

    abnormal_packet_sizes()
    time.sleep(1)

    malformed_packets()
    time.sleep(1)

    high_frequency_packets()

    print("Anomaly simulation completed.")