import pyshark
from scapy.all import *


def capture_packets(interface, filter_option):
    print(f"Capturing packets on interface {interface}...\n")

    capture = pyshark.LiveCapture(
        interface=interface, display_filter=filter_option)

    try:
        for packet in capture.sniff_continuously(packet_count=5):
            print("Packet Details:")
            print(packet)
            print("\n" + "=" * 50 + "\n")

    except KeyboardInterrupt:
        print("Capture interrupted by user.")


def main():
    interface = input("Enter the network interface (e.g., eth0): ")

    filter_option = input(
        "Enter a filter option (e.g., 'tcp', 'udp', 'icmp', or a keyword): ")

    capture_packets(interface, filter_option)


if __name__ == "__main__":
    main()
