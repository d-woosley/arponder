from scapy.all import sniff, ARP, srp, Ether

from arponder.packet_process import PacketProcessor

class Arponder():
    def __init__(self, main_iface: str, analyze_only=False, debug=False):
        self.main_iface = main_iface
        self.debug = debug
        self.analyze_only = analyze_only
        self.processor = None
        self.start_queue()

        # Add given interface to active hosts
        self.processor.active_hosts[self.main_iface.main_ip] = self.main_iface.main_interface_mac

    def start_listener(self):
        """
        ARP Scan the local network and starts sniffing ARP
        packets on the specified network interface.

        Will run until manually stopped (e.g., Ctrl+C).
        """
        self.__scan_local_subnet()

        print(f"[-] Starting ARP listener on {self.main_iface.main_iface}")
        sniff(iface=self.main_iface.main_iface, filter="", prn=self.__capture_callback, store=0)

    def start_queue(self):
        self.processor = PacketProcessor(self.main_iface, self.debug, self.analyze_only)
    
    def stop_queue(self):
        self.processor.stop()
            
    def __capture_callback(self, packet):
        self.processor.enqueue_packet(packet)

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

            if responding_ip not in self.processor.active_hosts:
                self.processor.active_hosts[responding_ip] = responding_mac

            if self.debug:
                print(f"  [+] Host {responding_ip} is alive at {responding_mac}")

        print(f"  [+] Found {len(self.processor.active_hosts)} hosts online in {self.main_iface.main_network}")
        return