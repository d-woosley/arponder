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
    logger = logging.getLogger(__name__)

    try:
        iface = EditIface(iface=args.net_interface, dummy_iface=args.dummy_iface, analyze=args.analyze)
        arponder = Arponder(iface=iface, analyze=args.analyze, stealthy=args.stealthy)
        if not args.analyze and not args.stealthy:
            arponder.scan_network(interval=args.scan_interval, aggressive=args.aggressive)
            time.sleep(3)  # Allow time for scan to complete
        elif args.stealthy:
            logger.info("Network scan skipped (Stealthy mode)")
        elif args.analyze:
            logger.info("Network scan skipped (Analyze mode)")
        arponder.start_listener(stale_timeout_period=args.timeout_period)
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