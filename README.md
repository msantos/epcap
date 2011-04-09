
An Erlang port interface to libpcap.

epcap includes a small example program called sniff.

## Changes

0.05: The packet message format has changed and is now documented.

## QUICK SETUP

    cd epcap
    make
    
    # Allow your user to epcap with root privs
    sudo visudo
    youruser ALL = NOPASSWD: /path/to/epcap/priv/epcap
    
    erl -pa ebin deps/*/ebin
    % Start the gen_server
    sniff:start_link().
    
    % Use your interface, or leave it out and trust in pcap
    sniff:start([{interface, "eth0"}]).
    
    % To change the filter
    sniff:start([{filter, "icmp or (tcp and port 80)"},{interface, "eth0"}]).
    
    % To stop sniffing
    sniff:stop().


## USAGE

    epcap:start() -> pid()
    epcap:start(Args) -> pid()
    
        Types   Args = [Options]
                Options = {chroot, string()} | {group, string()} | {interface, string()} | {promiscuous, boolean()} |
                            {user, string()} | {filter, string()} | {progname, string()} | {file, string()} |
                            {monitor, boolean()}

        Packets are delivered as messages:

            {packet, DataLinkType, Time, Length, Packet}

        The DataLinkType is an integer representing the link layer,
        e.g., ethernet, Linux cooked socket.

        The Time is a tuple in the same format as erlang:now/0, {MegaSecs,
        Secs, MicroSecs}.

        The Length corresponds to the actual packet length on the
        wire. The captured packet may have been truncated. To get the
        captured packet length, use byte_size(Packet).

        The Packet is a binary holding the captured data.


## SCREENSHOT

    =INFO REPORT==== 6-Jan-2010::20:35:18 ===
        time: "2010-01-06 20:35:18"
        caplen: 562
        len: 562
        source_macaddr: "0:16:B6:xx:xx:xx"
        source_address: {207,97,227,239}
        source_port: 80
        destination_macaddr: "0:15:AF:xx:xx:xx"
        destination_address: {192,168,1,2}
        destination_port: 56934
        protocol: tcp
        protocol_header: [{flags,["ack","psh"]},
                          {seq,2564452231},
                          {ack,3156269309},
                          {win,46}]
        payload_bytes: 492
        payload: "HTTP/1.1 301 Moved Permanently..Server: nginx/0.7.61..Date: Thu, 07 Jan 2010 01:35:17 GMT..Content-Type: text/html; charset=utf-8..Connection: close..Status: 301 Moved Permanently..Location: http://github.com/dashboard..X-Runtime: 2ms..Content-Length: 93..Set-Cookie: _github_ses=BAh7BiIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNoSGFzaHsABjoKQHVzZWR7AA%3D%3D--884981fc5aa85daf318eeff084d98e2cff92578f; path=/; expires=Wed, 01 Jan 2020 08:00:00 GMT; HttpOnly..Cache-Control: no-cache"


## TODO

* return error atoms/tuples instead of using errx


## CONTRIBUTORS

* Olivier Girondel:
    * preliminary IPv6 support

* Harald Welte:
    * support reading packets from pcap file
    * SCTP support
    * datalink types

* Gregory Haskins:
    * application file fix

