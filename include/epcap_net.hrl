%% From http://en.wikipedia.org/wiki/EtherType
-define(ETH_P_IP, 16#0800).
-define(ETH_P_ARP, 16#0806).
-define(ETH_P_IPV6, 16#86DD).
-define(ETH_P_ALL, 16#0300).

-define(ARPHRD_ETHER, 1).
-define(ARPHRD_IEEE80211, 801).

-define(ARPOP_REQUEST, 1).                  % ARP request
-define(ARPOP_REPLY, 2).                    % ARP reply
-define(ARPOP_RREQUEST, 3).                 % RARP request
-define(ARPOP_RREPLY, 4).                   % RARP reply
-define(ARPOP_InREQUEST, 8).                % InARP request
-define(ARPOP_InREPLY, 9).                  % InARP reply
-define(ARPOP_NAK, 10).                     % (ATM)ARP NAK

-define(IPPROTO_IP, 0).
-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).
-define(IPPROTO_SCTP, 132).

-define(ICMP_ECHOREPLY, 0).
-define(ICMP_DEST_UNREACH, 3).
-define(    ICMP_UNREACH_NET, 0).           % bad net
-define(    ICMP_UNREACH_HOST, 1).          % bad host
-define(    ICMP_UNREACH_PROTOCOL, 2).      % bad protocol
-define(    ICMP_UNREACH_PORT, 3).          % bad port
-define(    ICMP_UNREACH_NEEDFRAG, 4).      % IP_DF caused drop
-define(    ICMP_UNREACH_SRCFAIL, 5 ).      % src route failed
-define(ICMP_SOURCE_QUENCH, 4).
-define(ICMP_REDIRECT, 5).
-define(    ICMP_REDIRECT_NET, 0).          % for network
-define(    ICMP_REDIRECT_HOST, 1).         % for host
-define(    ICMP_REDIRECT_TOSNET, 2).       % for tos and net
-define(    ICMP_REDIRECT_TOSHOST, 3).      % for tos and host
-define(ICMP_ECHO, 8).
-define(ICMP_TIME_EXCEEDED, 11).
-define(    ICMP_TIMXCEED_INTRANS, 0).      % ttl==0 in transit
-define(    ICMP_TIMXCEED_REASS, 1).        % ttl==0 in reass
-define(ICMP_PARAMETERPROB, 12).
-define(ICMP_TIMESTAMP, 13).
-define(ICMP_TIMESTAMPREPLY, 14).
-define(ICMP_INFO_REQUEST, 15).
-define(ICMP_INFO_REPLY, 16).
-define(ICMP_ADDRESS, 17).
-define(ICMP_ADDRESSREPLY, 18).

-record(ether, {
        dhost = <<0,0,0,0,0,0>>,
        shost = <<0,0,0,0,0,0>>,
        type = ?ETH_P_IP,
        crc = 0
    }).

-record(arp, {
        hrd = ?ARPHRD_ETHER,
        pro = ?ETH_P_IP,
        hln = 6,
        pln = 4,
        op = ?ARPOP_REPLY,

        sha = <<0,0,0,0,0,0>>,
        sip = {127,0,0,1},

        tha = <<0,0,0,0,0,0>>,
        tip = {127,0,0,1}
    }).

-record(ipv4, {
        v = 4, hl = 5, tos = 0, len = 20,
        id = 0, df = 0, mf = 0,
        off = 0, ttl = 64, p = ?IPPROTO_TCP, sum = 0,
        saddr = {127,0,0,1}, daddr = {127,0,0,1},
        opt = <<>>
    }).

-record(ipv6, {
        v = 6, class = 0, flow = 0,
        len = 40, next = 0, hop = 0,
        saddr, daddr
    }).

-record(tcp, {
        sport = 0, dport = 0,
        seqno = 0,
        ackno = 0,
        off = 5, cwr = 0, ece = 0, urg = 0, ack = 0,
        psh = 0, rst = 0, syn = 0, fin = 0, win = 0,
        sum = 0, urp = 0,
        opt = <<>>
    }).

-record(udp, {
        sport = 0, dport = 0, ulen = 8, sum = 0
    }).

-record(icmp, {
        type = ?ICMP_ECHO, code = 0, checksum = 0,
        id = 0, sequence = 0,
        gateway = {127,0,0,1},
        un = <<0:32>>,
        mtu = 0,
        pointer = 0,
        ts_orig = 0, ts_recv = 0, ts_tx = 0
    }).

-record(sctp, {
	sport = 0, dport = 0, vtag = 0, sum = 0,
	chunks = []
	}).
-record(sctp_chunk, {
	type = 0, flags = 0, len = 0, payload = 0
	}).
-record(sctp_chunk_data, {
	tsn = 0, sid = 0, ssn = 0, ppi = 0, data
	}).
