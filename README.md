This test script is used to check if a DNS server favours fragmented packets or setting the TC bit if the maximum ipv6 MTU is set to a specific value.  An example use case is show below


```bash
root@ubuntu:~/git/RSSAC-Caucus-Packet-Sizes-WP# ./test_frags.py $(for i in {a..m}; do dig +short aaaa ${i}.root-servers.net ; done)
2001:503:ba3e::2:30: Is truncating (edns: 4096)
2001:503:ba3e::2:30: Is truncating (edns: 1232)
ERROR:root:2001:500:200::b: Timeout
2001:500:200::b: Is Fragmenting (3 -> 1240/1240/689)
2001:500:2::c: Is Fragmenting (3 -> 1240/1240/689)
2001:500:2::c: Is Fragmenting (3 -> 1240/1240/689)
2001:500:2d::d: Is truncating (edns: 4096)
2001:500:2d::d: Is truncating (edns: 4096)
2001:500:a8::e: Is truncating (edns: 1232)
2001:500:a8::e: Is truncating (edns: 1232)
2001:500:2f::f: Is truncating (edns: 1232)
2001:500:2f::f: Is truncating (edns: 1232)
ERROR:root:2001:500:12::d0d: Timeout
ERROR:root:2001:500:12::d0d: Timeout
2001:500:1::53: Is Fragmenting (3 -> 1240/1240/117)
2001:500:1::53: Is Fragmenting (3 -> 1240/1240/117)
2001:7fe::53: Is Fragmenting (3 -> 1240/1240/689)
2001:7fe::53: Is Fragmenting (3 -> 1240/1240/689)
2001:503:c27::2:30: Is truncating (edns: 1232)
2001:503:c27::2:30: Is truncating (edns: 1232)
2001:7fd::1: Is Fragmenting (3 -> 1240/1240/117)
2001:7fd::1: Is Fragmenting (3 -> 1240/1240/117)
ERROR:root:2001:500:9f::42: Timeout
2001:500:9f::42: Is Fragmenting (3 -> 1240/1240/899)
2001:dc3::35: Is Fragmenting (3 -> 1240/1240/689)
2001:dc3::35: Is Fragmenting (3 -> 1240/1240/689)
```

The following tests a query which produces a responses of ~1270 bytes
```bash
root@ubuntu:~/git/RSSAC-Caucus-Packet-Sizes-WP# ./test_frags.py -Q aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa. $(for i in {a..m}; do dig +short aaaa ${i}.root-servers.net ; done)
2001:503:ba3e::2:30: Is truncating (edns: 1232)
2001:503:ba3e::2:30: Is truncating (edns: 1232)
2001:500:200::b: Is Fragmenting (2 -> 1240/39)
2001:500:200::b: Is Fragmenting (2 -> 1240/39)
2001:500:2::c: Is Fragmenting (2 -> 1240/39)
2001:500:2::c: Is Fragmenting (2 -> 1240/39)
2001:500:2d::d: Is Answering Normally (1263)
2001:500:2d::d: Is Fragmenting (2 -> 1240/39)
2001:500:a8::e: Is truncating (edns: 1232)
2001:500:a8::e: Is truncating (edns: 1232)
2001:500:2f::f: Is truncating (edns: 1232)
2001:500:2f::f: Is truncating (edns: 1232)
2001:500:12::d0d: Is Answering Normally (1263)
2001:500:12::d0d: Is Answering Normally (1263)
2001:500:1::53: Is Answering Normally (1266)
2001:500:1::53: Is Answering Normally (1266)
2001:7fe::53: Is Fragmenting (2 -> 1240/39)
2001:7fe::53: Is Fragmenting (2 -> 1240/39)
2001:503:c27::2:30: Is truncating (edns: 1232)
2001:503:c27::2:30: Is truncating (edns: 1232)
2001:7fd::1: Is Fragmenting (2 -> 1240/42)
2001:7fd::1: Is Fragmenting (2 -> 1240/42)
2001:500:9f::42: Is Fragmenting (2 -> 1240/42)
2001:500:9f::42: Is Fragmenting (2 -> 1240/42)
2001:dc3::35: Is Fragmenting (2 -> 1240/39)
2001:dc3::35: Is Fragmenting (2 -> 1240/39)
```

this work is based on the C and perl scripts available at https://github.com/gih900/icmpv6
