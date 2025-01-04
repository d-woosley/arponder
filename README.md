# Arponder
```text
   _____ ____________________                 _           
  /  _  \\______   \\______  \               | |          
 /  /_\  \|       _/|     ___/ ___  _ __   __| | ___ _ __ 
/    |    \    |   \|    |    / _ \| '_ \ / _` |/ _ \ '__|
\____|__  /____|_  /|____|   | (_) | | | | (_| |  __/ |   
        \/       \/           \___/|_| |_|\__,_|\___|_|    
```
Automatic stale ARP poisoning for penetration testing and red teaming. Think "Responder for Stale ARP".

> **NOTE**: Arponder **ONLY** poisons stale ARP. It will not spin up fake services for credential collection so you will likely want to run another service poisoning tool like [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [NTLMRelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)

# Disclaimer
This project is in Beta testing! It has been tested in a lab but has not been tested in the field. I will be running the tool in the field and updating this page shortly; however, in the meantime please realize there is increased risk of disruption if an unexpected error occurs. Note that all testing has been performed in Kali Linux and I can't confirm that the tool will work on other distributions (although it likely should work on all Debian based Linux distributions)

> **NOTE**: This project is intended for authorized security testing only! Do not run this tool in environments where you do not have expressly written approval.

# Attack Theory and Safety
Isn't ARP poisoning too risky to perform on a security assessment? Yes, it is... if you were doing Full-Duplex ARP spoofing. Half-Duplex ARP spoofing of dead IPs (A.K.A. Stale ARP spoofing) is significantly safer and causes less disruption than other poisoning tools like Responder and MITM6.

## Why?
Some IPs are hardcoded into systems or programs on internal networks for specific connections, such as database queries or file sharing. If the server is moved or decommissioned, the network admin may not realize there is a host that will still search for the dead/moved host. This results in many ARP requests for the dead/moved IP that get no ARP responses (AKA, stale ARP requests). 

These ARP requests can be "poisoned" by sending false responses to the ARP requests resolving the IP to an attacker-controlled system's MAC address. From there, the attacker will receive the connection for whatever the victim was trying to send to the dead/moved host. This is most often HTTP(S) requests but can sometimes be requests for credentialed services like SNMP, SMB. In more rare cases, you may find that the dead/moved host was a former domain controller and receive cleartext Active Directory credentials via LDAP connections. 

Since the victim was unable to reach the dead or moved host in the first place, poisoning this traffic will likely cause no additional disruption to the network, as the connection was presumably unimportant and went unnoticed when it pointed to the wrong IP.

Additionally, you may find stale DNS entries that have even more value. A DNS entry that points to a host in the local network that is no longer online is also vulnerable to ARP spoofing. This is particularly useful in attacks like WebDAV coercion where you need a NetBIOS name.

> **NOTE**: Checking for stale DNS names is not currently implemented into the tool. As of right now, that is something you will have to do on your own.

## Arponder Safety Features
In order to make sure that ARP responses are ONLY sent for stale/dead IPs, Arponder implements the following checks:

 - ARP Scans local network for active hosts (*only in Normal Mode*)
 - Rescans network on regular interval to keep the active hosts list current (interval can be changed with the `--scan-interval` flag)
 - Automatically detects newly active hosts by listening to ARP Replies from other hosts and removes newly active host from poisoning list

# Installation
```bash
pipx install git+https://github.com/d-woosley/arponder
```

> **NOTE**: Using pip is not recommended. Kali Linux recently added Pipx to apt (`sudo apt install python-pipx`) and its use in installation is highly encouraged!

# Testing Modes
| Mode | Flag | Description | Use Case | Difference |
| - | - | - | - | - |
| Normal | *none* | Noisy and safe | Pentesting | Run local network ARP scans and only respond to requests for host you know are offline from the ARP scan results. Will rescan every 15 minutes to stay current. |
| Stealth | `-s` or `--stealthy` | Quiet and slightly lossy | Red Teaming | Do not run any ARP scanning and only poison ARP requests once you see an ARP request for a IP that does not get a response. You may miss an opportunity to poison an IP, but this is rare since stale ARP requests are typically part of an automated process and will retry shortly. |
| Analyze |  `-A` or `--analyze` | Fully passive (no poisoning) | Pre-attack analysis | Listen for stale ARP requests without scanning the network or ever sending a packet across the wire. This is good for analysis prior to running any attacks. |

# Run
**Quick Run (Normal Mode)**
```bash
sudo arponder -I <Network Interface>
```

**Stealth Mode**
```bash
sudo arponder -I <Network Interface> -s
```

**Analyze Mode**
```bash
sudo arponder -I <Network Interface> -A
```

> **NOTE**: Arponder **ONLY** poisons stale ARP. It will not spin up fake services for credential collection so you will likely want to run another service poisoning tool like [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [NTLMRelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)

# Dummy Interface
By adding the `--dummy-iface` flag, you can create a virtual interface that is a clone of the main interface and will be used to add and remove stale IPs. From my limited testing I've found this interface to be slight quicker in responding than the main host interface, but its primary use is during development. If a program error occurs, the interface can be removed manually without impacting the main host.

For normal testing, there is no need to add this flag but if you are in an environment with lots of stale ARP requests, you may get better performance using a dummy interface. It's also helpful for systems that you remote into since program failure could cause you to lose your connection otherwise.

> **NOTE**: Even when you are using a dummy interface, you will still want to run your poisoners (Like responder) against the main (`-I`) interface.

# Remediation
Full remediation requires implementing Dynamic ARP Inspection (DAI) on all switches. If you are using DHCP, DAI can be configured to use the DHCP data for validation. However, if you use static IP assignment, you will need to create a static ARP table for DAI to work correctly.

In many cases, DAI is not supported by the switch and will require the purchase of new hardware, making this issue extremely difficult to remediate. Additionally, some network administrators report that running DAI significantly slows down network performance. Unfortunately, I'm not aware of any alternative mitigation at the time minus just removing all automatic stale ARP requests and hoping to never miss type an IP again. 

> **NOTE**: Successful Half-Duplex ARP spoofing does not necessarily mean you can perform Full-Duplex ARP spoofing. Many switches are configured to send out ARP announcements for themselves whenever they detect an ARP reply or announcement sent for the switch's IP with a different MAC address. This can make full-duplex ARP spoofing nearly impossible but does nothing to address half-duplex ARP spoofing.

# Thanks and Credits
This project was inspired by the work of BlackHill's [eavesarp](https://github.com/ImpostorKeanu/eavesarp) and [Responder](https://github.com/lgandx/Responder). Special thanks to the contributors of these tools for their foundational work and inspiration for this project!

# To-Do
 - Add Stale DNS checking functionality


