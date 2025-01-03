import logging
from scapy.all import sniff, ARP, srp, Ether
import threading
import time

from arponder.packet_process import PacketProcessor

# Get the logger for this module
logger = logging.getLogger(__name__)

class Arponder:
    def __init__(self, iface, analyze_only=False, stealthy=False):
        self.iface = iface
        self.analyze_only = analyze_only
        self.stealthy = stealthy
        self.stale_timeout_period = None

        self.processor = None
        self.start_queue()
        self.scan_stop_event = threading.Event()

        # Add given interface to active hosts
        self.processor.active_hosts[self.iface.ip] = self.iface.mac

    def start_listener(self, stale_timeout_period=5):
        """
        ARP Scan the local network and starts sniffing ARP
        packets on the specified network interface.

        Will run until manually stopped (e.g., Ctrl+C).
        """
        self.stale_timeout_period = stale_timeout_period
        if self.stealthy:
            logger.info("Network scan skipped (Stealthy mode)")

        logger.info(f"Starting ARP listener on {self.iface.iface}")
        if self.analyze_only or self.stealthy:
            self.processor.start_stale_checker(stale_timeout_period=self.stale_timeout_period)
        sniff(iface=self.iface.iface, filter="", prn=self.__capture_callback, store=0)

    def start_queue(self):
        self.processor = PacketProcessor(self.iface, self.analyze_only)

    def stop_queue(self):
        self.processor.stop()

    def __capture_callback(self, packet):
        self.processor.enqueue_packet(packet)

    def scan_network(self, interval=0, aggressive=False):
        """
        Scans the local subnet for active hosts using ARP. Runs periodically at the specified interval (in minutes) if provided.

        Parameters:
            interval (int): Time in minutes between consecutive scans. 
                    - Set to 'None' to run the scan only once.
        """
        def _scan():
            while not self.scan_stop_event.is_set():
                if aggressive:
                    # Clear previous active host list
                    logger.debug(f"Clearing {len(self.processor.active_hosts)} former active host from active hosts list")
                    self.processor.active_hosts = {}
                    self.processor.active_hosts[self.iface.ip] = self.iface.mac

                # ARP scan local network
                logger.info(f"Scanning network {self.iface.network} for active hosts...")
                answered, unanswered = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.iface.network)),
                    timeout=2,
                    iface=self.iface.iface,
                    verbose=0
                )

                # Parse discovered hosts
                for snd, rcv in answered:
                    responding_ip = rcv.psrc
                    responding_mac = rcv.hwsrc

                    if responding_ip not in self.processor.active_hosts:
                        self.processor.active_hosts[responding_ip] = responding_mac
                        logger.debug(f"Host {responding_ip} is alive at {responding_mac}")

                logger.info(f"{len(self.processor.active_hosts)} hosts online in {self.iface.network}")
                
                if interval == None:
                    break

                logger.debug(f"Rescanning in {interval} minutes...")
                for _ in range(interval * 60):
                    if self.scan_stop_event.is_set():
                        return
                    time.sleep(1)

        # Start the scanning process in a separate thread
        self.scan_stop_event_worker = threading.Thread(target=_scan, daemon=True)
        self.scan_stop_event_worker.start()

    def stop_scan(self):
        """Stops the network scan thread gracefully."""
        if not self.stealthy and not self.analyze_only:
            if self.scan_stop_event:
                self.scan_stop_event.set()
                if hasattr(self, 'scan_stop_event_worker'):
                    # Wait for the thread to finish
                    self.scan_stop_event_worker.join()
                self.processor.stop_stale_checker()
                logger.debug("Network scanning stopped.")
        else:
            logger.debug("Network scanning not stopped since it was never started.")