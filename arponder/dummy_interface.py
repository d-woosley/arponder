from pyroute2 import IPRoute
import netifaces

class DummyIface:
    def __init__(self, host_iface: str, dummy_iface_name: str, debug = False):
        self.host_iface = host_iface
        self.dummy_iface_name = dummy_iface_name
        self.debug = debug

        self.ipr = IPRoute()
        self.host_mac = self.__get_host_mac()

        self.__create_iface()

    def __get_host_mac(self) -> str:
        """Retrieve the MAC address of the host interface."""
        return netifaces.ifaddresses(self.host_iface)[netifaces.AF_LINK][0]["addr"]

    def __create_iface(self):
        """Create a dummy interface and assign the host MAC address to it."""
        print(f"[+] Creating dummy interface '{self.dummy_iface_name}' with MAC '{self.host_mac}'")

        self.ipr.link("add", ifname=self.dummy_iface_name, kind="dummy")
        idx = self.ipr.link_lookup(ifname=self.dummy_iface_name)[0]
        self.ipr.link("set", index=idx, address=self.host_mac)
        self.ipr.link("set", index=idx, state="up")

        if self.debug:
            print(f"[+] Interface '{self.dummy_iface_name}' is up with MAC '{self.host_mac}'")

    def remove_iface(self):
        """Remove the dummy interface."""
        print(f"\n\n[+] Removing dummy interface '{self.dummy_iface_name}'")
        idx = self.ipr.link_lookup(ifname=self.dummy_iface_name)[0]
        self.ipr.link("del", index=idx)

        if self.debug:
            print(f"[+] Interface '{self.dummy_iface_name}' removed successfully")

    def add_ip(self, ip_address: str, prefixlen = 32):
        """Add an IP address to the dummy interface."""
        idx = self.ipr.link_lookup(ifname=self.dummy_iface_name)[0]
        self.ipr.addr("add", index=idx, address=ip_address, prefixlen=prefixlen)
        if self.debug:
            print(f"  [+] Added IP address '{ip_address}/{prefixlen}' to interface '{self.dummy_iface_name}'")

    def remove_ip(self, ip_address: str, prefixlen = 32):
        """Remove an IP address from the dummy interface if it exists."""
        idx = self.ipr.link_lookup(ifname=self.dummy_iface_name)[0]

        # Get all IPs assigned to the interface
        existing_ips = self.ipr.get_addr(index=idx)
        for addr in existing_ips:
            if addr.get('attrs', [])[0][1] == ip_address:
                # Remove the IP if it exists
                self.ipr.addr("del", index=idx, address=ip_address, prefixlen=prefixlen)
                if self.debug:
                    print(f"[+] Removed IP address '{ip_address}/{prefixlen}' from interface '{self.dummy_iface_name}'")
                return
        if self.debug:
            print(f"[~] IP address '{ip_address}/{prefixlen}' not found on interface '{self.dummy_iface_name}'. Nothing to remove.")