This test script is used to check if a DNS server favours fragmented packets or setting the TC bit if the maximum ipv6 MTU is set to a specific value.  An example use case is show below


```bash
root@ubuntu:/home/jbond# ./test_frags.py $(for i in {a..m}; do dig +short aaaa ${i}.root-servers.net ; done)
2001:503:ba3e::2:30: is truncating
2001:500:200::b: is fragmenting
2001:500:2::c: is fragmenting
2001:500:2d::d: is truncating
2001:500:a8::e: is truncating
2001:500:2f::f: is truncating
ERROR:root:2001:500:12::d0d: Timeout
2001:500:1::53: is fragmenting
2001:7fe::53: is fragmenting
2001:503:c27::2:30: is truncating
2001:7fd::1: is fragmenting
2001:500:9f::42: is fragmenting
2001:dc3::35: is fragmenting
```


this work is based on the C and perl scripts avalible at https://github.com/gih900/icmpv6
