#!/usr/bin/env python3

# Import dependencies
import warnings
warnings.filterwarnings("ignore") # Ignore all warnings... not best practice
from sys import argv
from argparse import ArgumentParser
from colorama import Fore
from netifaces import ifaddresses,AF_INET,AF_LINK
from threading import Thread,Lock
from scapy.all import sniff,ARP,Ether,srp
from time import sleep

class main():
    def runProgram(self):
        # Call for ASCII Logo (To be added...)
        main().ascii()

        print(Fore.LIGHTBLACK_EX + "\n[-] Starting..." + Fore.RESET)

        # Call for passed flags
        args = main().getArgs()
        
        # Define varables
        netInterface = args.INTERFACE
        netTimeout = args.TIMEOUT

        if args.Command == 'check':
            self.checkProtections(netInterface,netTimeout)

    def ascii(self):
        print(Fore.LIGHTRED_EX + "   _____ ____________________ " + Fore.LIGHTBLACK_EX + "                _           " + Fore.RESET)
        print(Fore.LIGHTRED_EX + "  /  _  \\\\______   \\______   \\" + Fore.LIGHTBLACK_EX + "               | |          " + Fore.RESET)
        print(Fore.LIGHTRED_EX + " /  /_\  \|       _/|     ___/" + Fore.LIGHTBLACK_EX + " ___  _ __   __| | ___ _ __ " + Fore.RESET)
        print(Fore.LIGHTRED_EX + "/    |    \    |   \|    |" + Fore.LIGHTBLACK_EX + "    / _ \| '_ \ / _` |/ _ \ '__|" + Fore.RESET)
        print(Fore.LIGHTRED_EX + "\\____|__  /____|_  /|____|" + Fore.LIGHTBLACK_EX + "   | (_) | | | | (_| |  __/ |   " + Fore.RESET)
        print(Fore.LIGHTRED_EX + "        \\/       \\/" + Fore.LIGHTBLACK_EX + "           \___/|_| |_|\__,_|\___|_|    " + Fore.RESET)
        print(Fore.LIGHTWHITE_EX + "___________________________________________________________" + Fore.RESET)
        return

    def getArgs(self):
        parser = ArgumentParser(
        description = "A Modern Layer-2 Attack Toolkit",
        epilog = "by: Duncan Woosley (@a2trdm)"
        )

        # Check to make sure that an input was given. If had a wierd issue on linux when there was no input
        if len(argv) <= 1:
            print("\n")
            print(parser.print_usage())
            print(Fore.LIGHTBLACK_EX + "\n[-] Shutting down...\n" + Fore.RESET)
            exit(1)

        # Add Sub Command
        subParsers = parser.add_subparsers(help='Choose a Method', dest='Command')

        # Define the flag groups
        parseCheck = subParsers.add_parser('check', help='Check to see if there are ARP spoofing protections in place')

        parseCheck.add_argument('-I',
                            dest='INTERFACE',
                            help='Network adaptor interface',
                            required=True,
                            type=str
                            )
        parseCheck.add_argument('-t',
                            dest='TIMEOUT',
                            help='Timeout (in seconds) to listen for your own bogus ARP annoucment. Default = 5',
                            required=False,
                            default=5,
                            type=int
                            )

        # Get arg results
        args = parser.parse_args()

        return(args)

    def printError(self,Message):
        print(Fore.LIGHTRED_EX + Message + Fore.RESET)
        print(Fore.LIGHTBLACK_EX + "\n[-] Shutting down..." + Fore.RESET)
        exit(1)

    def checkProtections(self,netInterface,netTimeout):
        # Getting interface info
        netifaceInfo = ifaddresses(netInterface)
        netIP = netifaceInfo[AF_INET][0]['addr']
        netMAC = netifaceInfo[AF_LINK][0]['addr']

        # Create an ARP response packet w/ bogus MAC
        bogusMAC = "00:0c:29:ff:ff:ff"
        bogusARPRequest = Ether(dst=bogusMAC)/ARP(pdst=netIP)

        # Start network listener in seperate thread
        global arpProtection
        global arpProtectionLock
        arpProtectionLock = Lock()  # Lock for synchronization (Avoid race conditions)
        with arpProtectionLock:     # Acquire lock
            arpProtection = True    # This isn't an ideal solution but I can't figure out another way to get results from the sniff

        # Define sniffer thread
        arpSnifferThread = Thread(target=sniffStart, args=(netIP,bogusMAC,netTimeout,netInterface))

        # Start the thread
        print(Fore.LIGHTBLACK_EX + "\n  [-] Starting network listener" + Fore.RESET)
        arpSnifferThread.start()
        sleep(2) # Sleep to allow listner to start
        
        # Send the packet and wait for the response
        print(Fore.LIGHTBLACK_EX + "\n  [-] Sending bogus ARP announcement" + Fore.RESET)
        srp(bogusARPRequest, timeout=1, verbose=False)

        # Create an ARP response packet w/ correct MAC
        realARPRequest = Ether(dst=netMAC)/ARP(pdst=netIP)
            
        # Reset ARP to correct MAC
        print(Fore.LIGHTBLACK_EX + "\n  [-] Resetting by sending correct ARP announcement" + Fore.RESET)
        srp(realARPRequest, timeout=1, verbose=False)

        # Wait for the thread to finish
        arpSnifferThread.join()

        # Check if arpProtection was found
        with arpProtectionLock:     # Acquire lock
            if arpProtection:
                print(Fore.RED + "\n    [!] ARP protections are in place!" + Fore.RESET)
            else:
                print(Fore.GREEN + "\n    [+] ARP protections are NOT in place!" + Fore.RESET)


def ARPParser(packet,netIP,bogusMAC):
    # Pull in global varables
    global arpProtection
    global arpProtectionLock
    
    # Filter on ARP Annoucments
    if packet[ARP].op == 1:
        ARPIP = packet.getfieldval("pdst")
        ARPMAC = packet.getfieldval("dst")

        if ARPIP == netIP and ARPMAC == bogusMAC:
            # Found ARP for netIP with bogusMAC
            with arpProtectionLock:     # Acquire lock (To avoid race condtions by using lock)
                arpProtection = False
            return True
        else:
            return False

    return False
            
def sniffStop(pkt,netIP, bogusMAC):
    # stop filter for sniff function
    return pkt.haslayer('ARP') and ARPParser(pkt, netIP, bogusMAC)

def sniffStart(netIP,bogusMAC,netTimeout,netInterface):
    try:
        sniff(lfilter=lambda pkt: pkt.haslayer('ARP') and ARPParser(pkt, netIP, bogusMAC),timeout=netTimeout, iface=netInterface,stop_filter=lambda pkt: sniffStop(pkt, netIP, bogusMAC))
    except PermissionError:
        main().printError("  [!] Permission Error! Rerun with sudo")

if __name__ == "__main__":
    try:
        # Start the main module
        main().runProgram()
        exit(0)
    except KeyboardInterrupt:           # Catch Ctrl+C
        main().printError("  [!] Keyboard Interrupted! (Ctrl+C Pressed)")
