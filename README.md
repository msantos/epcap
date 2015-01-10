An Erlang port interface to libpcap.

epcap includes a small example program called sniff.

## Changes

 * 0.05: The packet message format has changed and is now documented.

 * 0.06: epcap doesn't register itself, so multiple instances can be run.

 * 0.7.0: removed epcap\_net.erl (moved to https://github.com/msantos/pkt)

## QUICK SETUP

    cd epcap
    make
    make examples

    # Allow your user to epcap with root privs
    sudo visudo
    youruser ALL = NOPASSWD: /path/to/epcap/priv/epcap
    # And if requiretty is enabled, disable it by using one of these
    Defaults!/path/to/epcap/priv/epcap !requiretty
    Defaults:youruser !requiretty

    erl -pa ebin deps/*/ebin # or: rebar shell

    % Start the sniffer process
    sniff:start_link().

    % Use your interface, or leave it out and trust in pcap
    sniff:start([{interface, "eth0"}]).

    % To change the filter
    sniff:start([{filter, "icmp or (tcp and port 80)"},{interface, "eth0"}]).

    % To stop sniffing
    sniff:stop().


## USAGE

    epcap:start() -> {ok, pid()}
    epcap:start(Args) -> {ok, pid()}
    epcap:start_link() -> {ok, pid()}
    epcap:start_link(Args) -> {ok, pid()}

        Types   Args = [Options]
                Options = {chroot, string()} | {group, string()} | {interface, string()} | {promiscuous, boolean()} |
                            {user, string()} | {filter, string()} | {progname, string()} | {file, string()} |
                            {monitor, boolean()} | {cpu_affinity, string()} | {cluster_id, non_neg_integer()}} |
                            {inject, boolean()} | {snaplen, non_neg_integer} | {buffer, non_neg_integer()}

        Packets are delivered as messages:

            {packet, DataLinkType, Time, Length, Packet}

        The DataLinkType is an integer representing the link layer,
        e.g., ethernet, Linux cooked socket.

        The Time is a tuple in the same format as erlang:now/0:

        {MegaSecs, Secs, MicroSecs}

        The Length corresponds to the actual packet length on the
        wire. The captured packet may have been truncated. To get the
        captured packet length, use byte_size(Packet).

        The Packet is a binary holding the captured data.

        If the version of the pcap library supports it, the pcap buffer
        size can be set to avoid dropped packets by using the 'buffer'
        option. The buffer size must be larger than the snapshot
        length (default: 65535) plus some overhead for the pcap data
        structures. Using some multiple of the snapshot length is
        suggested.

    epcap:send(Ref, Packet) -> ok

        Types   Ref = pid()
                Packet = binary()

        Inject a packet on the network interface. To enable sending
        packets, start_link/1 must be called with the {inject, true} option
        (default: {inject, false}). When disabled, any data sent
        to the epcap port is silently discarded.

        Packet injection failures are treated as fatal errors, terminating
        the epcap port. Partial writes are not considered to be errors
        and are ignored (an error message will be printed to stderr if
        the verbose option is used).

## PF_RING

        In case you want to compile epcap with PF_RING support,
        just specify the path to the libpfring and modified libpcap libraries
        via shell variable PFRING.

            PFRING=/home/user/pfring make

        As a result epcap binary will be linked with the following flags: -static -lpfring -lpthread

        To complete the configuration you need to set up the cluster_id option.
        The value of the cluster_id option is integer and should be in range between 0 and 255.

            epcap:start_link([{interface, "lo"}, {cluster_id, 2}]).

        You can also specify the option cpu_affinity to set up CPU affinity for epcap port:

            epcap:start_link([{interface, "lo"}, {cluster_id, 2}, {cpu_affinity, "1,3,5-7"}]).


## SCREENSHOT

    =INFO REPORT==== 27-Oct-2013::11:47:43 ===
        pcap: [{time,"2013-10-27 11:47:43"},
               {caplen,653},
               {len,653},
               {datalink,en10mb}]
        ether: [{source_macaddr,"F0:BD:4F:AA:BB:CC"},
                {destination_macaddr,"B3:4B:19:00:11:22"}]
        ipv6: [{protocol,tcp},
               {source_address,"2607:F8B0:400B:80B::1000"},
               {destination_address,"2002:26F:92:AE::123"}]
        tcp: [{source_port,80},
              {destination_port,47980},
              {flags,[ack,psh]},
              {seq,686139900},
              {ack,725208397},
              {win,224}]
        payload_size: 567
        payload: "HTTP/1.0 301 Moved Permanently..Location: http://www.google.ca/..Content-Type: text/html; charset=UTF-8..Date: Sun, 27 Oct 2013 15:47:49 GMT..Expires: Tue, 26 Nov 2013 15:47:49 GMT..Cache-Control: public, max-age=2592000..Server: gws..Content-Length: 218..X-XSS-Protection: 1; mode=block..X-Frame-Options: SAMEORIGIN..Alternate-Protocol: 80:quic....<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">.<TITLE>301 Moved</TITLE></HEAD><BODY>.<H1>301 Moved</H1>.The document has moved.<A HREF=\"http://www.google.ca/\">here</A>...</BODY></HTML>.." 

And a screenshot of the number of packets epcap is processing on a
production system:

![IPTraf Screenshot](https://cloud.githubusercontent.com/assets/13721/4917083/8fe7754c-64e0-11e4-9165-17e21c57ee06.png)

## TODO

* return error atoms/tuples instead of using errx

* add support for retrieving packet statistics using pcap\_stats(3PCAP)
