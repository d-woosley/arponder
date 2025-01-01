import logging
import time

from arponder.input_args import load_args
from arponder.arponder import Arponder
from arponder.logo import ascii_logo
from arponder.interfaces import EditIface
from arponder.custom_logger import setup_logging

def main():
    ascii_logo()
    args = load_args()
    iface = None

    setup_logging(args.debug, args.log, args.log_file)

    try:
        iface = EditIface(main_iface=args.net_interface, dummy_iface_name=args.dummy_iface)
        arponder = Arponder(main_iface=iface, analyze_only=args.analyze)
        if not args.analyze:
            arponder.scan_network(interval=args.scan_interval, aggressive=args.aggressive)
            time.sleep(3)  # Allow time for scan to complete
        arponder.start_listener()
    finally:
        if iface:
            iface.close_threads()
            if not args.analyze:
                iface.flush_ips()
            iface.remove_iface()
        if arponder:
            arponder.stop_queue()
            arponder.stop_scan()

if __name__ == "__main__":
    main()