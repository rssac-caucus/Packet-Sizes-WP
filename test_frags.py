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
    # This stop filter adds filtering for our initial src port
    if pkt.haslayer(UDP):
        return (pkt[UDP].dport == port)
    return False


def sniffer(ipv6, port, timeout=2):
    # create filter listening for IP address
    # ideally we should be able to specify the port here
    # however scapy doesn't understand frags so we use the stop_filter
    filter = 'src host {}'.format(ipv6)
    logging.debug('sniffing for {}'.format(filter))
    pkt = sniff(filter=filter, timeout=timeout,
            stop_filter=lambda x: stop_filter(x, port))
    # if we get nothing we have timedout
    if not pkt:
        logging.error('{}: Timeout'.format(ipv6))
        return
    pkt = pkt[-1]
    # Check if we have recived an packet with an IPv6 frag header
    if pkt.haslayer(IPv6ExtHdrFragment):
        print '{}: is fragmenting'.format(ipv6)
    # check if the TC bit is set
    elif pkt.haslayer(DNS) and pkt[DNS].tc:
        print '{}: is sending truncated'.format(ipv6)
    else:
        logging.error('{}: something went wrong'.format(ipv6))


def test_server(server, mtu=1280, timeout=2):
    sport = randint(1024, 65536)
    logging.debug('{}: sending ICMPv6 PTB with MTU = {}'.format(server, mtu))
    ipv6  = IPv6(dst=server)
    # Send gratuitous ICMPv6 PTB
    # in theory we should send a get a big response before sending ICMPv6 PTB
    # however testing seems to indicate that we can just send it gratuitously
    send(ipv6 / ICMPv6PacketTooBig(mtu=mtu), verbose=False)
    # create DNS Questions '. IN ANY'
    packet = ipv6 / UDP(sport=sport) / DNS(
            qd=DNSQR(qname='.', qtype='ALL'), ar=DNSRROPT(rclass=4096))
    # set up packet sniffer
    s = Process(target=sniffer, args=(server, sport))
    s.start()
    # sleep a bit just to make sure the listener is started
    sleep(0.1)
    # send DNS query
    send(packet, verbose=False)


def main():
    args = get_args()
    set_log_level(args.verbose)
    for server in args.servers:
        test_server(server, args.mtu, args.timeout)
        # We only use threads to ensure the sniffer is running
        # when we send the query.  to many sniffers running simultaniously
        # is likley bad so we sleep utill the sniffer times out
        sleep(args.timeout)


if __name__ == '__main__':
    main()
