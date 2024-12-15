from scapy import sniff, ARP


class Arponder():
    def __init__(self, net_interface: str, poison=False):
        self.net_interface = net_interface
        self.poison = poison

    def start_listener(self):
        """
        Starts sniffing ARP packets on the specified network interface.
        Will run until manually stopped (e.g., Ctrl+C).
        """
        sniff(iface=self.net_interface, filter="arp", prn=self.__arp_callback, store=0)

    def __arp_callback(self, packet):
        """Private method to handle each ARP packet as it's captured."""
        if ARP in packet and packet[ARP].op in (1, 2):
            # ARP operation: 1 = request (who-has), 2 = reply (is-at)
            arp_type = "request" if packet[ARP].op == 1 else "reply"
            source_mac = packet.src

            # Print in the requested format
            print(f"  [+] ARP {arp_type} from {source_mac}")

            # Store the packet for future processing if needed
            self.captured_packets.append(packet)