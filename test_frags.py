#!/usr/bin/env python2

import logging
from random import randint
from time import sleep
from multiprocessing import Process
from scapy.all import IPv6, ICMPv6PacketTooBig, UDP, IPv6ExtHdrFragment, \
        sniff, send, DNS, DNSQR, DNSRROPT
from argparse import ArgumentParser


def set_log_level(args_level):
    log_level = logging.ERROR
    if args_level == 1:
        log_level = logging.WARN
    elif args_level == 2:
        log_level = logging.INFO
    elif args_level > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


def get_args():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-T', '--timeout', default=2, type=int)
    parser.add_argument('-M', '--mtu', default=1280, type=int)
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('servers', nargs='+')
    return parser.parse_args()


def stop_filter(pkt, port):
    if pkt.haslayer(UDP):
        return (pkt.dport == port)
    return False


def sniffer(ipv6, port, timeout=2):
    filter = 'src host {}'.format(ipv6)
    logging.debug('sniffing for {}'.format(filter))
    pkt = sniff(filter=filter, timeout=timeout, stop_filter=lambda x: stop_filter(x, port))
    if not pkt:
        logging.error('{}: no response recived'.format(ipv6))
        return
    pkt = pkt[-1]
    if pkt.haslayer(IPv6ExtHdrFragment):
        print '{}: is fragmenting'.format(ipv6)
    elif pkt.haslayer(DNS) and pkt[DNS].tc:
        print '{}: is sending truncated'.format(ipv6)
    else:
        logging.error('{}: something went wrong'.format(ipv6))


def test_root_server(server, mtu=1280, timeout=2):
    sport = randint(1024, 65536)
    logging.debug('{}: sending ICMPv6 PTB with MTU = {}'.format(server, mtu))
    ipv6  = IPv6(dst=server)
    send(ipv6 / ICMPv6PacketTooBig(mtu=mtu), verbose=False)
    packet = ipv6 / UDP(sport=sport) / DNS(
            qd=DNSQR(qname='.', qtype='ALL'), ar=DNSRROPT(rclass=4096))
    s = Process(target=sniffer, args=(server, sport))
    s.start()
    # sleep a bit just to make sure the listener is started
    sleep(0.1)
    send(packet, verbose=False)


def main():
    args = get_args()
    set_log_level(args.verbose)
    for server in args.servers:
        test_root_server(server, args.mtu, args.timeout)
        # we dont actully want this threaded so we sleep
        # untill the thread gets a chance to time out
        sleep(args.timeout)


if __name__ == '__main__':
    main()
