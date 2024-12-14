from argparse import ArgumentParser


def load_args():
    parser = ArgumentParser(
        description="Automatic stale ARP poisoning for penetration testing and red teaming",
        epilog="by: Duncan Woosley (github.com/d-woosley)",
    )

    parser.add_argument('-I',
        dest="net_interface",
        metavar="<INTERFACE>",
        help='Network interface to use for listening',
        required=True,
        type=str
        )

    # Get arg results
    args = parser.parse_args()

    return(args)