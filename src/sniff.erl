%% Copyright (c) 2009, Michael Santos <michael.santos@gmail.com>
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

-module(sniff).
-include("epcap_net.hrl").

-export([start/0, start/1]).


start() ->
    start([{filter, "tcp and port 80"}, {interface, "en1"}, {chroot, "priv/tmp"}]).
start(L) ->
    epcap:start(L),
    loop().

loop() ->
    receive
        [{pkthdr, {{time, Time},_,_}},{packet, Packet}] ->
            try epcap_net:decapsulate(Packet) of
                P -> dump(Time, P)
            catch
                error:Error ->
                    io:format("~s *** Error decoding packet ***~n~p~n~p~n~p~n", [
                            timestamp(Time),
                            Error,
                            erlang:get_stacktrace(),
                            Packet])
            end,
            loop();
        stop ->
            ok
    end.

timestamp(Now) when is_tuple(Now) ->
    iso_8601_fmt(calendar:now_to_local_time(Now)).

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B",
            [Year, Month, Day, Hour, Min, Sec])).

dump(Time, [Ether, IP, Hdr, Payload]) ->
    io:format("~s =======================================~n", [timestamp(Time)]), 
    io:format("SRC:~p~s (~s)~nDST:~p~s (~s)~n", [
            IP#ipv4.saddr, port(sport, Hdr), string:join(epcap_net:ether_addr(Ether#ether.shost), ":"),
            IP#ipv4.daddr, port(dport, Hdr), string:join(epcap_net:ether_addr(Ether#ether.dhost), ":")
        ]),
    proto(Hdr),
    io:format("length ~p~n~s~n", [byte_size(Payload), epcap_net:payload(Payload)]).

proto(#tcp{} = Hdr) ->
    io:format("Flags ~p seq ~p, ack ~p, win ~p, ", [
            epcap_net:tcp_flags(Hdr),
            Hdr#tcp.seqno, Hdr#tcp.ackno, Hdr#tcp.win
        ]);
proto(#udp{} = Hdr) ->
    io:format("ulen ~p, ", [ Hdr#udp.ulen ]);
proto(#icmp{} = Hdr) ->
    io:format("type ~p code ~p, ", [ Hdr#icmp.type, Hdr#icmp.code ]).

port(sport, #tcp{sport = SPort}) -> ":" ++ integer_to_list(SPort);
port(sport, #udp{sport = SPort}) -> ":" ++ integer_to_list(SPort);
port(dport, #tcp{dport = DPort}) -> ":" ++ integer_to_list(DPort);
port(dport, #udp{dport = DPort}) -> ":" ++ integer_to_list(DPort);
port(_,_) -> "".


