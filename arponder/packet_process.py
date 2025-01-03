import logging
import queue
import threading
from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, sendp
import time

# Get the logger for this module
logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, iface, analyze: bool):
        self.iface = iface
        self.analyze = analyze

        # Threading vars
        self.processer_stop_event = threading.Event()
        self.checker_stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.worker = threading.Thread(target=self.__process_packets, daemon=True)
        self.worker.start()
        self.stale_check_thread = None
        
        self.active_hosts = {}
        self.arp_requests = {}
        self.stale_timeout_period = None

    def enqueue_packet(self, packet):
        self.packet_queue.put(packet)

    def __process_packets(self):
        while not self.processer_stop_event.is_set():
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
            if packet[ARP].op == 1 and packet[ARP].hwsrc != self.iface.mac:
                # ARP Request (who-has)
                source_mac = packet[ARP].hwsrc
                requested_ip = packet[ARP].pdst
                requestor_ip = packet[ARP].psrc
                logger.debug(f"ARP request from {source_mac} for {requested_ip}")

                if requestor_ip not in self.active_hosts:
                    self.active_hosts[requestor_ip] = source_mac
                    logger.debug(f"Host {requestor_ip} is alive at {source_mac}")


                # Poison if not in analyze mode
                if not self.analyze and requested_ip not in self.active_hosts and requested_ip not in self.iface.added_ips:
                    # Add IP to iface
                    self.iface.add_ip(ip_address=requested_ip)
                elif self.analyze and requested_ip not in self.active_hosts and requested_ip not in self.iface.added_ips:
                    self.arp_requests[requested_ip] = time.time()
            else:
                # ARP Reply (is-at)
                from_mac = packet[ARP].hwsrc
                to_mac = packet[ARP].hwdst
                requested_ip = packet[ARP].psrc

                if requested_ip in self.iface.added_ips:
                    try:
                        sender_ip = [ip for ip, mac in self.active_hosts.items() if mac == to_mac][0]  # ERROR WITH STELTH! Trying to resolve sender IP with no active hosts list. Also could cause issue with new host if error not handled (IndexError)
                    except IndexError:
                        sender_ip = f'Unknown IP (MAC: {to_mac})'
                    if from_mac == self.iface.mac:
                        logger.info(f"Sent poisoned ARP response to {sender_ip} for {requested_ip}")
                    else:
                        logger.warning(f"Unexpected ARP reply for {requested_ip}! Removing from poisoning list!")
                        self.active_hosts[requested_ip] = from_mac
                        logger.debug(f"Host {requested_ip} is alive at {from_mac}")
                        self.iface.remove_ip(requested_ip)

                elif requested_ip not in self.active_hosts:
                    if self.analyze:
                        logger.debug(f"ARP response from {requested_ip} found! Removing from self.arp_requests")
                        pop_results = self.arp_requests.pop(requested_ip, "NOTFOUND")
                        if pop_results == "NOTFOUND":
                            logger.debug(f"ARP response from {requested_ip} ignored as request for {requested_ip} isn't in self.arp_requests")
                    else:
                        self.active_hosts[requested_ip] = from_mac
                        logger.debug(f"Host {requested_ip} is alive at {from_mac}")

    def __handle_non_arp(self, packet):
        # Ensure the packet is for our MAC address
        if Ether in packet and packet[Ether].dst.lower() != self.iface.mac.lower():
            return

        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Only process if dst_ip is one of our "poisoned" IP addresses
        if dst_ip not in self.iface.added_ips:
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
        self.processer_stop_event.set()
        self.worker.join()

    def __check_stale_entries(self):
        while not self.checker_stop_event.is_set():
            current_time = time.time()
            stale_ips = [ip for ip, timestamp in self.arp_requests.items() if current_time - timestamp > self.stale_timeout_period]
            for ip in stale_ips:
                del self.arp_requests[ip]
                self.iface.add(ip)
                logger.info(f"{ip} is stale!")
            time.sleep(1)

    def start_stale_checker(self, stale_timeout_period=5):
        self.stale_timeout_period = stale_timeout_period
        if self.stale_check_thread is None or not self.stale_check_thread.is_alive():
            self.checker_stop_event.clear()
            self.stale_check_thread = threading.Thread(target=self.__check_stale_entries, daemon=True)
            self.stale_check_thread.start()

    def stop_stale_checker(self):
        if self.stale_check_thread is not None and self.stale_check_thread.is_alive():
            self.checker_stop_event.set()
            self.stale_check_thread.join()
            self.stale_check_thread = None