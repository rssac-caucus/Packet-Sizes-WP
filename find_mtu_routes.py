#!/usr/bin/env python
route_file = '/proc/net/ipv6_route'
RTF_MODIFIED = 0x0020
mtu_hosts = []
with open(route_file) as input_file:
    for line in input_file:
        entries = line.split()
        if int(entries[8], 16) & RTF_MODIFIED:
            ip_str = entries[0]
            ipv6 = ':'.join([ip_str[i:i + 4] for i in range(0, len(ip_str), 4)])
            mtu_hosts.append(ipv6)

print '\n'.join(mtu_hosts)
