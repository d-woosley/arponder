from argparse import ArgumentParser, ArgumentTypeError

import re

def validate_alphanumeric(value):
    """Ensure the input value contains only alphanumeric characters (1-9, a-z, A-Z)."""
    if not re.fullmatch(r'[a-zA-Z0-9]+', value):
        raise ArgumentTypeError(f"'{value}' must only contain numbers 1-9 or letters a-z or A-Z.")
    return value

def load_args():
    parser = ArgumentParser(
        description="Automatic stale ARP poisoning for penetration testing and red teaming",
        epilog="by: Duncan Woosley (github.com/d-woosley)",
    )

    # Add arguments
    parser.add_argument(
        '-I',
        '--interface',
        dest="net_interface",
        metavar="<INTERFACE>",
        help='Network interface to use for listening',
        required=True,
        type=validate_alphanumeric
        )
    parser.add_argument(
        '-A',
        "--analyze",
        dest="analyze",
        help="Analyze ARP traffic without sending poisoned responses",
        action="store_true",
        default=False
        )
    parser.add_argument(
        '-s',
        "--stealthy",
        dest="stealthy",
        help="Run attack without performing any network scanning. Relies on hearing dead ARP request at least once before sending poisoned responses",
        action="store_true",
        default=False
        )
    parser.add_argument(
        '--dummy-iface',
        dest="dummy_iface",
        metavar="<NAME>",
        help="Create a virtual interface with the given name to handle ARP spoofing",
        type=validate_alphanumeric
        )
    parser.add_argument(
        '--scan-interval',
        dest="scan_interval",
        metavar="<MINTUES>",
        help="Time (in minutes) to rescan the local network with ARP (default=15)",
        type=int,
        default=15
        )
    parser.add_argument(
        '--aggressive',
        dest="aggressive",
        help="Flush the former active host list each time the local network ARP scan is rerun",
        action="store_true",
        default=False
        )
    parser.add_argument(
        '--timeout-period',
        dest="timeout_period",
        metavar="<SECONDS>",
        help="Time (in seconds) to wait to hear ARP response until assuming host is offline (Default=5). Increase in slow networks",
        type=int,
        default=5
        )
    parser.add_argument(
        '-d',
        "--debug",
        dest="debug",
        help="Set output to debug",
        action="store_true",
        default=False
        )
    parser.add_argument(
        '-l',
        '--log',
        dest="log",
        help="Log the results to a file",
        action="store_true",
        default=False
    )
    parser.add_argument(
        '-lf',
        '--log-file',
        dest="log_file",
        metavar="<LOG_FILE>",
        help="Path to save log to a file (Default=arponder.log)",
        type=str,
        default="arponder.log"
    )

    # Get arg results
    args = parser.parse_args()

    return(args)