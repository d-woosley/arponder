from pyroute2 import IPRoute
from scapy.all import get_if_hwaddr, get_if_addr
import netifaces
import ipaddress

class EditIface():
    def __init__(self, main_iface: str, dummy_iface_name=None, debug = False):
        self.iface_name = main_iface
        self.main_iface = main_iface
        self.debug = debug
        self.dummy_iface_name = dummy_iface_name

        self.ipr = IPRoute()
        self.added_ips = set()

        # Parse interface info
        self.main_interface_mac = get_if_hwaddr(self.main_iface)
        self.main_ip = get_if_addr(self.main_iface)
        self.main_interface_addrs = netifaces.ifaddresses(self.main_iface)
        self.main_netmask = self.main_interface_addrs[netifaces.AF_INET][0]['netmask']
        self.main_network = ipaddress.ip_network(f"{self.main_ip}/{self.main_netmask}", strict=False)

        if dummy_iface_name:
            self.iface_name = dummy_iface_name
            self.__create_iface(dummy_iface_name)
        else:
            print("[!] Dummy iface not used! This could result in lost packets due to system bottlenecks")

    def __create_iface(self, dummy_iface_name):
        """Create a dummy interface and assign the host MAC address to it."""
        print(f"[+] Creating dummy interface '{dummy_iface_name}' with MAC '{self.main_interface_mac}'")

        self.ipr.link("add", ifname=dummy_iface_name, kind="dummy")
        idx = self.ipr.link_lookup(ifname=dummy_iface_name)[0]
        self.ipr.link("set", index=idx, address=self.main_interface_mac)
        self.ipr.link("set", index=idx, state="up")

        if self.debug:
            print(f"[+] Interface '{self.dummy_iface_name}' is up with MAC '{self.main_interface_mac}'")

    def remove_iface(self):
        """Remove the dummy interface if it exists"""
        if self.dummy_iface_name:
            print(f"\n\n[+] Removing dummy interface '{self.dummy_iface_name}'")
            idx = self.ipr.link_lookup(ifname=self.dummy_iface_name)[0]
            self.ipr.link("del", index=idx)

            if self.debug:
                print(f"[+] Interface '{self.dummy_iface_name}' removed successfully")
        else:
            # Do nothing since no iface was created
            if self.debug:
                print(f"  [+] Interface not removed since no dummy interface was created")

    def __ip_exists(self, ip_address: str) -> bool:
        """Check if the given IP address is already assigned to the interface."""
        idx = self.ipr.link_lookup(ifname=self.iface_name)[0]
        existing_addresses = self.ipr.get_addr(index=idx)
        for addr in existing_addresses:
            if addr.get("attrs", [])[1][1] == ip_address:
                return True
        return False

    def add_ip(self, ip_address: str, prefixlen=32):
        """Add an IP address to the interface if it is not already assigned."""
        if self.__ip_exists(ip_address):
            if self.debug:
                print(f"  [!] IP address '{ip_address}' is already assigned to interface '{self.iface_name}'. Skipping.")
            return

        idx = self.ipr.link_lookup(ifname=self.iface_name)[0]
        self.ipr.addr("add", index=idx, address=ip_address, prefixlen=prefixlen)
        self.added_ips.add(ip_address)
        if self.debug:
            print(f"  [+] Added IP address '{ip_address}/{prefixlen}' to interface '{self.iface_name}'")

    def remove_ip(self, ip_address: str, prefixlen = 32):
        """Remove an IP address from the interface if it exists."""
        idx = self.ipr.link_lookup(ifname=self.iface_name)[0]

        # Get all IPs assigned to the interface
        existing_ips = self.ipr.get_addr(index=idx)
        for addr in existing_ips:
            if addr.get('attrs', [])[0][1] == ip_address:
                # Remove the IP if it exists
                self.ipr.addr("del", index=idx, address=ip_address, prefixlen=prefixlen)
                print(f"  [+] Removed IP address '{ip_address}/{prefixlen}' from interface '{self.iface_name}'")
                return
        if self.debug:
            print(f"  [~] IP address '{ip_address}/{prefixlen}' not found on interface '{self.iface_name}'. Nothing to remove.")

    def flush_ips(self):
        """Remove all IPs that were added to interface"""
        added_ip_count = len(self.added_ips)
        print(f"  [-] Removing {added_ip_count} IP addresses that were added to {self.iface_name}")
        for ip in self.added_ips:
            self.remove_ip(ip)

