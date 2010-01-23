%% From http://en.wikipedia.org/wiki/EtherType
-define(ETHTYPE_IPV4, 16#0800).
-define(ETHTYPE_IPV6, 16#86DD).

-define(IPPROTO_IP, 0). 
-define(IPPROTO_ICMP, 1). 
-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).

-define(ICMP_ECHOREPLY, 0).
-define(ICMP_DEST_UNREACH, 3).
-define(ICMP_SOURCE_QUENCH, 4).
-define(ICMP_REDIRECT, 5).
-define(ICMP_ECHO, 8).
-define(ICMP_TIME_EXCEEDED, 11).
-define(ICMP_PARAMETERPROB, 12).
-define(ICMP_TIMESTAMP, 13).
-define(ICMP_TIMESTAMPREPLY, 14).
-define(ICMP_INFO_REQUEST, 15).
-define(ICMP_INFO_REPLY, 16).
-define(ICMP_ADDRESS, 17).
-define(ICMP_ADDRESSREPLY, 18).

-record(ether, {
        dhost, shost, type, crc
    }).

-record(ipv4, {
        valid = false,
        v = 4, hl = 5, tos = 0, len = 20, 
        id, df = 0, mf = 0, 
        off = 0, ttl = 0, p = ?IPPROTO_TCP, sum = 0,
        saddr = {127,0,0,1}, daddr = {127,0,0,1}
    }). 

-record(ipv6, {
        valid = false,
        v = 6, class = 0, flow = 0, 
        len = 40, next = 0, hop = 0,
        saddr, daddr
    }). 

-record(tcp, {
        valid = false,
        sport = 0, dport = 0,
        seqno = 0,
        ackno = 0,
        off = 0, cwr = 0, ece = 0, urg = 0, ack = 0,
            psh = 0, rst = 0, syn = 0, fin = 0, win = 0,
        sum, urp = 0,
        opt = <<>>
    }). 

-record(udp, {
        valid = false,
        sport = 0, dport = 0, ulen = 0, sum = 0
    }). 

-record(icmp, {
        valid,
        type, code, checksum,
        id, sequence,
        gateway,
        un,
        mtu
    }).


