import logging
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError, NetlinkDumpInterrupted
from scapy.all import get_if_hwaddr, get_if_addr
import threading
from concurrent.futures import ThreadPoolExecutor
import netifaces
import ipaddress
import time

# Get the logger for this module
logger = logging.getLogger(__name__)

class EditIface:
    def __init__(self, main_iface: str, dummy_iface=None, max_threads=256):
        self.iface_name = main_iface
        self.main_iface = main_iface
        self.dummy_iface = dummy_iface
        self.max_threads = max_threads

        # Parse interface info
        self.main_interface_mac = get_if_hwaddr(self.main_iface)
        self.main_ip = get_if_addr(self.main_iface)
        self.main_interface_addrs = netifaces.ifaddresses(self.main_iface)
        self.main_netmask = self.main_interface_addrs[netifaces.AF_INET][0]['netmask']
        self.main_network = ipaddress.ip_network(f"{self.main_ip}/{self.main_netmask}", strict=False)

        # Define general use vars
        self.ipr = IPRoute()
        self.added_ips = set()
        self.idx = self.ipr.link_lookup(ifname=self.iface_name)[0]

        # Act on Dummy Iface
        if dummy_iface:
            self.iface_name = dummy_iface
            self.__create_iface(dummy_iface)
            self.idx = self.ipr.link_lookup(ifname=dummy_iface)[0]
            self.max_threads = 10  # Testing showed better results for lower thread num on dummy iface
        else:
            logger.warning("Dummy interface not used! This could result in lost packets due to bottlenecks while interfaceing with the system")

        # Threading vars
        self.thread_executor = ThreadPoolExecutor(self.max_threads)
        self.shutdown_event = threading.Event()

    def __create_iface(self, dummy_iface):
        """Create a dummy interface and assign the host MAC address to it."""
        logger.info(f"Creating dummy interface '{dummy_iface}' with MAC '{self.main_interface_mac}'")

        self.ipr.link("add", ifname=dummy_iface, kind="dummy")
        self.ipr.link("set", index=self.idx, address=self.main_interface_mac)
        self.ipr.link("set", index=self.idx, state="up")

        logger.debug(f"Interface '{self.dummy_iface}' is up with MAC '{self.main_interface_mac}'")

    def remove_iface(self):
        """Remove the dummy interface if it exists."""
        if self.dummy_iface:
            logger.info(f"Removing dummy interface '{self.dummy_iface}'")
            self.ipr.link("del", index=self.idx)

            logger.debug(f"Interface '{self.dummy_iface}' removed successfully")
        else:
            logger.debug("Interface not removed since no dummy interface was created")

    def add_ip(self, ip_address: str, prefixlen=32):
        """Add an IP address to the interface if it is not already assigned."""
        if self.shutdown_event.is_set():
            logger.warning("Shutdown event is set. Skipping IP addition.")
            return

        # Create method for executor thread to avoid bottle neck with IP addtion
        def netlink_worker():
            try:
                self.ipr.addr("add", index=self.idx, address=ip_address, prefixlen=prefixlen)
            except NetlinkError as e:
                if e.code == 17:  # Error code for 'File exists' (aka IP already added)
                    logger.warning(f"IP address '{ip_address}' is already assigned to interface '{self.iface_name}'. Skipping.")
                    return
                else:
                    logger.error(f"Unexpected NetlinkError: {e.strerror} (Code: {e.code})")
                    raise
            except Exception as e:
                logger.error(f"Unexpected error in thread: {e}")
                raise

            logger.info(f"Added IP address '{ip_address}/{prefixlen}' to interface '{self.iface_name}'")

        self.thread_executor.submit(netlink_worker)
        self.added_ips.add(ip_address)

    def remove_ip(self, ip_address: str, prefixlen=32):
        """Remove an IP address from the interface if it exists."""
        # Get all IPs assigned to the interface
        try:
            existing_ips = self.ipr.get_addr(index=self.idx)
        except NetlinkDumpInterrupted as e:
            try:
                # Resource Busy. Sleep and retry
                time.sleep(2)
                existing_ips = self.ipr.get_addr(index=self.idx)
            except NetlinkDumpInterrupted as e:
                # Failed Twice, raise error
                logger.error(f"Unexpected NetlinkError: {e} (Code: {e.code})")
                raise
        for addr in existing_ips:
            if addr.get('attrs', [])[0][1] == ip_address:
                # Remove the IP if it exists
                self.ipr.addr("del", index=self.idx, address=ip_address, prefixlen=prefixlen)
                logger.debug(f"Removed IP address '{ip_address}/{prefixlen}' from interface '{self.iface_name}'")
                return
        logger.warning(f"IP address '{ip_address}/{prefixlen}' not found on interface '{self.iface_name}'. Nothing to remove.")

    def flush_ips(self):
        """Remove all IPs that were added to the interface."""
        added_ip_count = len(self.added_ips)
        logger.info(f"Removing {added_ip_count} IP addresses that was added to {self.iface_name}")
        for ip in self.added_ips:
            self.remove_ip(ip)

    def close_threads(self):
        logger.info("Shutting down IP addtion thread pool")
        self.shutdown_event.set()
        self.thread_executor.shutdown(wait=True)