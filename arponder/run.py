from arponder.keyexcept_decorator import keyboard_interrupt_handler
from arponder.input_args import load_args
from arponder.arponder import Arponder
from arponder.logo import ascii_logo
from arponder.dummy_interface import DummyIface

@keyboard_interrupt_handler
def main():
    ascii_logo()
    args = load_args()

    dummy_iface = DummyIface(
        host_iface=args.net_interface,
        dummy_iface_name=args.dummy_iface_name,
        debug=args.debug
    )
    arponder = Arponder(
        net_interface=args.net_interface,
        dummy_iface=dummy_iface,
        analyze_only=args.analyze,
        debug=args.debug
    )

    try:
        arponder.start_listener()
    finally:
        dummy_iface.remove_iface()

if __name__ == "__main__":
    main()