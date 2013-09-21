
An Erlang port interface to libpcap.

epcap includes a small example program called sniff.

## Changes

0.05: The packet message format has changed and is now documented.
0.06: epcap doesn't register itself, so multiple instances can be run.


## QUICK SETUP

    cd epcap
    make all
        
    # Allow your user to epcap with root privs
    sudo visudo
    youruser ALL = NOPASSWD: /path/to/epcap/priv/epcap
    
    erl -pa $PWD/examples/ebin $PWD/rule/ebin $PWD/deps/*/ebin $PWD/content_app/ebin $PWD/epcap_app/ebin 
    # or: ./start.sh
    
    application:start(sasl).

    % start epcap application in epcap_app folder
    % listens for tcp, udp etc. packages
    application:start(epcap). 

    % start content application in content_app folder
    % is an app that filters received content based on given rules
    % content is just one of the apps, there could be many more
    application:start(content).
    
    MatchFun1 = fun(Payload) -> 
			A = parser_combinator_bitstring:pBinarystring(<<"www.heise.de">>),
			B = parser_combinator_bitstring:pUntilN( A, 100 ),
			C = parser_combinator_bitstring:pBinarystringCaseInsensitive(<<"MELDUNG">>),
			D = parser_combinator_bitstring:pBetweenN(B, C,14),
			parser_combinator_bitstring:parse(D,Payload) end.
    % matches for content that started with "www.heise.de" within the first 100 chanracters
    % followed by the not case sensitive text "MELDUNG" e.g. "Meldung" within 14 characters
    % There are almost unlimited options with the given parser combiantor. See the parser_combinator_bitstring module
    % in the content_app/src directory and the examples in the parsertest module in the same directory.

    % here you find such an URL: http://www.heise.de/newsticker/meldung/4k-Tablet-fuer-4500-Euro-1951905.html

    % feel free to start the Erlang observer (available from Erlang 16A) 
    observer:start(). % go to tab "Application", optional
    % if you use an older Erlang release try appmon:start().

    {ok, Result1} = rule:start([{epcap,[{interface, "eth0"}]}, {content, [{matchfun, MatchFun1}]}, {message, "Found:*www.heise.de*Meldung*"}]).

    or

    AlwaysMatchFun = fun(Payload) -> no_fail end. % matches every packet received

    {ok, Result2} = rule:start([{epcap,[{filter, "icmp or (tcp and port 80)"}]}, {content, [{matchfun, AlwaysMatchFun}]}, {message, "Received an icmp or tcp (on port 80) package"}]). 

    % Feel free to use other matchfuns

    % Above starts the epcap_app with the parameter and pipes the received packages into the content app

    NeverMatchFun = fun(Payload) -> fail end. % this does not make much sense, except it's an example

    {ok, Result3} = rule:start([{epcap,[{filter, "icmp or (tcp and port 80)"}]}, {content, [{matchfun, NeverMatchFun}]}, {message, "This should never ocurr!!!"}]).
    
    % Note, as long as the epcap parameter do not change the same instance of the epcap_worker is used (see observer -> Applications)
    % Now stop this (works in any order):
    rule:stop(Result1). % watch the observer application tab
    rule:stop(Result2).
    rule:stop(Result3).



## USAGE

    {ok, Roleback} = rule:start([{AppName1,[{key1, value1}, {key2, value2}, ...]}, {AppName2,[{key1, value1}, {key2, value2}, ...]}, ..., {AppNameN,[{key1, value1}, {key2, value2}]}).
    epcap:start() -> {ok, pid()}
    epcap:start(Args) -> {ok, pid()}
    
    1) epcap:
        directoy: epcap_app 
        
        Types   Args = [Options]
                Options = {chroot, string()} | {group, string()} | {interface, string()} | {promiscuous, boolean()} |
                            {user, string()} | {filter, string()} | {progname, string()} | {file, string()} |
                            {monitor, boolean() | {cpu_affinity, string()} | {cluster_id, non_neg_integer()}}

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


## PF_RING

        In case you want to compile epcap with PF_RING support,
        just specify the path to the libpfring and modified libpcap libraries
        via shell variable PFRING.

            PFRING=/home/user/pfring make

        As a result epcap binary will be linked with the following flags: -static -lpfring -lpthread

        To complete the configuration you need to set up the cluster_id option.
        The value of the cluster_id option is integer and should be in range between 0 and 255.

            epcap:start([{interface, "lo"}, {cluster_id, 2}]).

        You can also specify the option cpu_affinity to set up CPU affinity for epcap port:

            epcap:start([{interface, "lo"}, {cluster_id, 2}, {cpu_affinity, "1,3,5-7"}]).


## SCREENSHOT

=INFO REPORT==== 9-Sep-2013::20:39:39 ===
    <0.88.0>
    time: "2013-09-09 20:39:39"
    caplen: 1290
    len: 1290
    datalink: ether
    source_macaddr: "0:25:22:A9:7C:5D"
    source_address: "192.168.178.30"
    source_port: 43499
    destination_macaddr: "9C:C7:A6:6D:77:DC"
    destination_address: "80.190.166.27"
    destination_port: 80
    protocol: tcp
    protocol_header: [{flags,[ack,psh]},
                      {seq,819627729},
                      {ack,3045257862},
                      {win,115}]
    payload_bytes: 1224
    payload: "GET /288689636920174/wt?p=322,www.heise.de.newsticker.meldung.neuartiger-tablet-browser-von-opera-1952873,1,1680x1050,24,1,1378751979484,1,1680x939,1&tz=2&eid=2137642977100470310&one=0&fns=1&la=en&cg1=www.heise.de&cg2=newsticker&cg3=meldung&cg4=neuartiger-tablet-browser-von-opera-1952873&cg9=neuartiger-tablet-browser-von-opera-1952873&cg10=meldung&cp2=browser%3Btablet%3Bipad&cp6=browser%3Btablet%3Bipad&eor=1 HTTP/1.1..Host: prophet.heise.de..Connection: keep-alive..Accept: image/webp,*/*;q=0.8..User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36..DNT: 1..Referer: http://www.heise.de/newsticker/meldung/Neuartiger-Tablet-Browser-von-Opera-1952873.html..Accept-Encoding: gzip,deflate,sdch..Accept-Language: en-US,en;q=0.8..Cookie: __gads=ID=a3d2bc03cf48a706:T=1376429781:S=ALNI_MbLQO8Z29ZkWr-55HwHP9Xmu3U5PQ; wt3_eid=%3B288689636920174%7C2137642977100470310; search_properties=%7B%22sort%22%3A%22d%22%2C%22__timestamp%22%3A1376590411%7D_X_53f402d5f58f7ac1a6e39b05fe98ada1e019f659; u2uforum_properties=eNqrVoqPL8nMTS0uScwtULIyNDa3MDAyMDC30FGKL85MUbJSysryNHDxTq7MTjaJUqoFAHAADq4%3D_X_bdc2ace25285a4fcd8685a0e83c85fbae1224b6a; wt3_sid=%3B288689636920174...."



## TODO

* return error atoms/tuples instead of using errx
* make it distributed application
* add futher applications

## Interesting Books:

Erlang and OTP in Action, Martin Logan, Eric Merritt, Richard Carlsson / for Erlang OTP

For intrusion detection:
Snort 2.0 Intrusion Detectionby Brian Caswell, Jeffrey Pusluns and Jay Beale from Syngress Media (May 1st 2003) 


## CONTRIBUTORS

* Olivier Girondel:
    * preliminary IPv6 support

* Harald Welte:
    * support reading packets from pcap file
    * SCTP support
    * datalink types

* Gregory Haskins:
    * application file fix

* Alexey Larin
    * support of devices without ipwq

* Artem Teslenko
    * allow listening on different interfaces
