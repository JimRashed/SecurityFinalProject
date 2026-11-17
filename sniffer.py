# This is a sample Python script.
import sys

from scapy.all import *
import socket


def show_usage_and_exit():
    print("Usage: python sniffer.py <interface> [count=100]")
    print("Example: python sniffer.py Ethernet 50")
    print("Example: python sniffer.py Ethernet")
    sys.exit(1)


def ResolveDestinationHostNames(packets):
     for packet in packets:
             destination = ""
             error = None
             try:        
                 destination = socket.gethostbyaddr(packet[IP].dst);
             except socket.herror as e:
                      error = (e)
             finally:
                   if (error):
                         print(f"Error: {error} (probably private)")
                   else:
                         print(f"Destination IP: {destination[2]} - DNS Lookup result: {destination[0]}");


if __name__ == '__main__':
    # Check for correct argument count
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        show_usage_and_exit()


    # Parse given arguments
    interface = sys.argv[1].strip()
    if (len(sys.argv) == 3):
        count = int(sys.argv[2])
        try:
            if (count):
                print(f"Beginning packet sniff for {interface}...")
                packets = sniff(iface =interface, prn=lambda packets: ResolveDestinationHostNames(packets))
            else:
                print(f"Beginning packet sniff for {interface}...")
                packets = sniff(iface =interface, count=count, prn=lambda packets: ResolveDestinationHostNames(packets))
        except:
            print("Error occurred while resolving destination host names.")

