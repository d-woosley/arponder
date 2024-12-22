from argparse import ArgumentParser


def load_args():
    parser = ArgumentParser(
        description="Automatic stale ARP poisoning for penetration testing and red teaming",
        epilog="by: Duncan Woosley (github.com/d-woosley)",
    )

    parser.add_argument(
        '-I',
        '--interface',
        dest="net_interface",
        metavar="<INTERFACE>",
        help='Network interface to use for listening',
        required=True,
        type=str
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
        '--dummy-name',
        dest="dummy_iface_name",
        metavar="<NAME>",
        help="Name of the interface to create (default=arp0)",
        default="arp0",
        type=str
        )

    parser.add_argument(
        '-d',
        "--debug",
        dest="debug",
        help="Set output to debug",
        action="store_true",
        default=False
        )

    # Get arg results
    args = parser.parse_args()

    return(args)