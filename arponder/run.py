from arponder.keyexcept_decorator import keyboard_interrupt_handler
from arponder.input_args import load_args
from arponder.arponder import Arponder
from arponder.logo import ascii_logo

@keyboard_interrupt_handler
def main():
    ascii_logo()
    args = load_args()
    arponder = Arponder(
        net_interface=args.net_interface,
        analyze_only=args.analyze,
        debug=args.debug
    )

    arponder.start_listener()
    exit()

if __name__ == "__main__":
    main()