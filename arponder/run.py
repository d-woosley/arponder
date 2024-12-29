from arponder.input_args import load_args
from arponder.arponder import Arponder
from arponder.logo import ascii_logo
from arponder.interfaces import EditIface

def main():
    ascii_logo()
    args = load_args()
    iface = None

    try:
        iface = EditIface(main_iface=args.net_interface, dummy_iface_name=args.dummy_iface, debug=args.debug)
        arponder = Arponder(main_iface=iface, analyze_only=args.analyze, debug=args.debug)
        arponder.start_listener()
    except KeyboardInterrupt:
        print("\n\nKeyboardInterrupt: Program terminated by user.")
    finally:
        if iface:
            iface.flush_ips()
            iface.remove_iface()

if __name__ == "__main__":
    main()