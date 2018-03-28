#!/usr/bin/env python2

import logging
from random import randint
from time import sleep
from multiprocessing import Process
from scapy.all import IPv6, ICMPv6PacketTooBig, UDP, IPv6ExtHdrFragment, \
        sniff, send, DNS, DNSQR, DNSRROPT, sr1
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
    parser.add_argument('-Q', '--qname', default='.', type=str)
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('servers', nargs='+')
    return parser.parse_args()


def stop_filter(pkt, port):
    '''This stop filter adds filtering for our initial src port'''
    if pkt.haslayer(UDP) and pkt.haslayer(IPv6ExtHdrFragment):
        # if we have frags we want to keep collecting untill we have the last frag
        return (pkt[UDP].dport == port and pkt[IPv6ExtHdrFragment].m == 0)
    elif pkt.haslayer(UDP):
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
    # Check if last packet to see if its a frag
    if pkt[-1].haslayer(IPv6ExtHdrFragment):
        frag_str = ''
        for p in pkt:
            frag_str += '{}/'.format(p[IPv6].plen)
        logging.info('{}: {} Fragments ({})'.format(ipv6, len(pkt), frag_str[:-1]))
    # if not check if the TC bit is set
    elif pkt[-1].haslayer(DNS) and pkt[-1][DNS].tc:
        logging.info('{}: is truncating'.format(ipv6))
    elif pkt[-1].haslayer(DNS):
        logging.info('{}: Recived Answer ({})'.format(ipv6, pkt[-1][IPv6].plen))
    else:
        logging.error('{}: something went wrong'.format(ipv6))


def send_ptb(server, mtu=1280):
    ipv6  = IPv6(dst=server)
    # First send a small question so we can create a believable PTB
    # create DNS Questions '. IN NS'
    packet = ipv6 / UDP() / DNS(qd=DNSQR(qname='.', qtype='SOA'))
    logging.debug('{}: generate some DNS traffic'.format(server, mtu))
    ans = sr1(packet, verbose=False)
    # Send ICMPv6 PTB message with geniune data
    logging.debug('{}: sending ICMPv6 PTB with MTU = {}'.format(server, mtu))
    send(ipv6 / ICMPv6PacketTooBig(mtu=mtu) / ans.original[:512], verbose=False)


def test_server(server, qname='.', timeout=2, send_ptb=True):
    sport = randint(1024, 65536)
    ipv6  = IPv6(dst=server)
    # set up packet sniffer
    s = Process(target=sniffer, args=(server, sport))
    s.start()
    # sleep a bit just to make sure the listener is started
    sleep(0.1)
    # create DNS Questions '. IN ANY'
    packet = ipv6 / UDP(dport=53, sport=sport) / DNS(
            qd=DNSQR(qname=qname, qtype='ALL'), ar=DNSRROPT(rclass=4096))
    # send DNS query
    send(packet, verbose=False)


def main():
    args = get_args()
    set_log_level(args.verbose)
    for server in args.servers:
        # Collect stats before the PTB
        logging.info('{}: collect stats pre ICMPv6 PTB'.format(server))
        test_server(server, args.qname, args.timeout, False)
        # sleep until the sniffer times out
        sleep(args.timeout)
        # send PTB
        logging.info('{}: send ICMPv6 PTB'.format(server))
        send_ptb(server)
        # Collect stats after the PTB
        logging.info('{}: collect stats post ICMPv6 PTB'.format(server))
        test_server(server, args.qname, args.timeout)
        # sleep until the sniffer times out
        sleep(args.timeout)


if __name__ == '__main__':
    main()
