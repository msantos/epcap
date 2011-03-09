%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
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
-behaviour(gen_fsm).

-include("pkt.hrl").

% Interface
-export([start/0, start/1, stop/0]).
-export([start_link/0]).
% States
-export([waiting/2, sniffing/2]).
% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).

-define(is_print(C), C >= $ , C =< $~).


%%--------------------------------------------------------------------
%%% Interface
%%--------------------------------------------------------------------
start() ->
    start([{filter, "tcp and port 80"},
            {interface, "en1"},
            {chroot, "priv/tmp"}]).
start(Arg) when is_list(Arg) ->
    gen_fsm:send_event(?MODULE, {start, Arg}).

stop() ->
    gen_fsm:send_event(?MODULE, stop).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
start_link() ->
    gen_fsm:start({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    {ok, waiting, []}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.


%%
%% State: sniffing
%%
handle_info([
        {pkthdr, [{time, Time}, {caplen, CapLen}, {len, Len}, {datalink, DLT}]},
        {packet, Packet}
    ], sniffing, _) ->
    [Ether, IP, Hdr, Payload] = pkt:decapsulate(Packet),
    error_logger:info_report([
            {time, timestamp(Time)},
            {caplen, CapLen},
            {len, Len},
            {datalink, DLT},

            % Source
            {source_macaddr, string:join(ether_addr(Ether#ether.shost), ":")},
            {source_address, IP#ipv4.saddr},
            {source_port, port(sport, Hdr)},

            % Destination
            {destination_macaddr, string:join(ether_addr(Ether#ether.dhost), ":")},
            {destination_address, IP#ipv4.daddr},
            {destination_port, port(dport, Hdr)},

            {protocol, pkt:proto(IP#ipv4.p)},
            {protocol_header, header(Hdr)},

            {payload_bytes, byte_size(Payload)},
            {payload, payload(Payload)}

        ]),
    {next_state, sniffing, []};

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, sniffing, _) ->
    {next_state, sniffing, []};

%%
%% State: waiting
%%

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, waiting, _) ->
    {next_state, waiting, []}.


terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.


%%--------------------------------------------------------------------
%%% States
%%--------------------------------------------------------------------
waiting({start, Arg}, _) ->
    epcap:start(Arg),
    {next_state, sniffing, []}.

sniffing({start, Arg}, _) ->
    epcap:stop(),
    epcap:start(Arg),
    {next_state, sniffing, Arg};
sniffing(stop, _) ->
    epcap:stop(),
    {next_state, waiting, []}.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
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
    [ atom_to_list(F) || {F,V} <-
        [{cwr,CWR}, {ece,ECE}, {urg,URG}, {ack,ACK}, {psh,PSH}, {rst,RST}, {syn,SYN}, {fin,FIN}], V =:= 1 ].

