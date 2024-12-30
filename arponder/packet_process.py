import logging
import queue
import threading
from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, sendp

# Get the logger for this module
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, iface, analyze_only: bool):
        self.main_iface = iface
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.worker = threading.Thread(target=self.__process_packets, daemon=True)
        self.worker.start()
        self.analyze_only = analyze_only
        self.active_hosts = {}

    def enqueue_packet(self, packet):
        self.packet_queue.put(packet)

    def __process_packets(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if ARP in packet:
                self.__handle_arp(packet)
            else:
                self.__handle_non_arp(packet)
            self.packet_queue.task_done()

    def __handle_arp(self, packet):
        """Private method to handle each ARP packet as it's captured."""
        if packet[ARP].op in (1, 2):
            if packet[ARP].op == 1 and packet[ARP].hwsrc != self.main_iface.main_interface_mac:
                # ARP Request (who-has)
                source_mac = packet[ARP].hwsrc
                requested_ip = packet[ARP].pdst
                logger.debug(f"ARP request from {source_mac} for {requested_ip}")

                # Poison if not in analyze_only mode
                if not self.analyze_only and requested_ip not in self.active_hosts and requested_ip not in self.main_iface.added_ips:
                    requestor_ip = packet[ARP].psrc

                    # Add IP to iface
                    self.main_iface.add_ip(ip_address=requested_ip)

                    # Send poisoned ARP response
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
                        logger.info(f"Sent poisoned ARP response to {sender_ip} for {requested_ip}")
                    else:
                        logger.warning(f"Unexpected ARP reply for {requested_ip}! Removing from poisoning list!")
                        self.active_hosts[requested_ip] = from_mac
                        self.main_iface.remove_ip(requested_ip)

                elif requested_ip not in self.active_hosts:
                    self.active_hosts[requested_ip] = from_mac
                    logger.debug(f"Host {requested_ip} is now alive at {from_mac}")

    def __handle_non_arp(self, packet):
        # Ensure the packet is for our MAC address
        if Ether in packet and packet[Ether].dst.lower() != self.main_iface.main_interface_mac.lower():
            return

        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Only process if dst_ip is one of our "poisoned" IP addresses
        if dst_ip not in self.main_iface.added_ips:
            return

        # -- TCP logic --
        if TCP in packet:
            tcp_layer = packet[TCP]
            dport = tcp_layer.dport

            # Check for SYN
            if (tcp_layer.flags & 0x02) != 0:
                TCP_PROTOCOLS = {
                    21:   "FTP", 22:   "SSH", 23:   "Telnet", 25:   "SMTP",
                    80:   "HTTP", 88:   "Kerberos", 115:  "SFTP", 139:  "NetBIOS (TCP)",
                    143:  "IMAP", 389:  "LDAP", 443:  "HTTPS", 445:  "SMB",
                    465:  "SMTPS", 636:  "LDAPS", 990:  "FTPS", 993:  "IMAPS",
                    995:  "POP3S", 1433: "MsSQL", 1521: "OracleDB", 3306: "MySQL",
                    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"
                }
                protocol_name = TCP_PROTOCOLS.get(dport, "unknown")
                logger.info(f"{src_ip} attempted to connect on port {dport}/tcp ({protocol_name}) via the poisoned IP of {dst_ip}")
            return

        # -- UDP logic --
        elif UDP in packet:
            udp_layer = packet[UDP]
            dport = udp_layer.dport

            UDP_PROTOCOLS = {
                53:   "DNS", 67:   "DHCP (Server)", 68:   "DHCP (Client)",
                69:   "TFTP", 123:  "NTP", 161:  "SNMP", 514:  "Syslog"
            }
            protocol_name = UDP_PROTOCOLS.get(dport, "unknown")
            logger.info(f"{src_ip} sent a packet to port {dport}/udp ({protocol_name}) via the poisoned IP of {dst_ip}")

        # -- ICMP logic --
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            if icmp_layer.type == 8:
                logger.info(f"{src_ip} pinged you via the poisoned IP of {dst_ip}")
            else:
                logger.info(f"{src_ip} sent an ICMP packet (type {icmp_layer.type}) via the poisoned IP of {dst_ip}")

        else:
            proto_num = packet[IP].proto
            logger.info(f"{src_ip} sent IP protocol {proto_num} to {dst_ip}")

    def stop(self):
        self.stop_event.set()
        self.worker.join()