%% Copyright (c) 2010-2013, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(epcap_lib).
-include_lib("pkt/include/pkt.hrl").

-export([decode/2,
	 ether_addr/1, 
	 header/1, 
	 iso_8601_fmt/1, 
	 payload/1,
	 port/2, 
	 tcp_flags/1, 
	 timestamp/1,
	 to_ascii/1]).

-define(is_print(C), C >= $ , C =< $~).

timestamp(Now) when is_tuple(Now) ->
    iso_8601_fmt(calendar:now_to_local_time(Now)).

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B",
				[Year, Month, Day, Hour, Min, Sec])).

header(#tcp{ackno = Ackno, seqno = Seqno, win = Win} = Hdr) ->
    [{flags, tcp_flags(Hdr)},
     {seq, Seqno},
     {ack, Ackno},
     {win, Win}];
header(#udp{ulen = Ulen}) ->
    [{ulen, Ulen}];
header(#icmp{code = Code, type = Type}) ->
    [{type, Type},
     {code, Code}];
header(Packet) ->
    Packet.

port(sport, #tcp{sport = SPort}) -> SPort;
port(sport, #udp{sport = SPort}) -> SPort;
port(dport, #tcp{dport = DPort}) -> DPort;
port(dport, #udp{dport = DPort}) -> DPort;
port(_,_) -> "".

payload(Payload) ->
    [ to_ascii(C) || <<C:8>> <= Payload ].

to_ascii(C) when ?is_print(C) -> C;
to_ascii(_) -> $..

ether_addr(B) when is_binary(B) ->
    ether_addr(binary_to_list(B));
ether_addr(L) when is_list(L) ->
    [ hd(io_lib:format("~.16B", [N])) || N <- L ].

tcp_flags(#tcp{cwr = CWR, ece = ECE, urg = URG, ack = ACK,
	       psh = PSH, rst = RST, syn = SYN, fin = FIN}) ->
    [ F || {F,V} <- [
		     {cwr, CWR},
		     {ece, ECE},
		     {urg, URG},
		     {ack, ACK},
		     {psh, PSH},
		     {rst, RST},
		     {syn, SYN},
		     {fin, FIN}
		    ], V =:= 1 ].

decode(ether, Packet) ->
    pkt:decapsulate({ether, Packet});
decode(DLT, Packet) ->
						% Add a fake ethernet header
    [_Linktype, IP, Hdr, Payload] = pkt:decapsulate({DLT, Packet}),
    [#ether{}, IP, Hdr, Payload].
