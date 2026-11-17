# This is a sample Python script.
from scapy.all import *
import socket


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press F9 to toggle the breakpoint.

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
    print_hi('PyCharm')
    packets = sniff(filter="tcp", count = 100, iface = "Ethernet")

    ResolveDestinationHostNames(packets)