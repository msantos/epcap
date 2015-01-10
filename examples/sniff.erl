%% Copyright (c) 2010-2015, Michael Santos <michael.santos@gmail.com>
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

-include_lib("pkt/include/pkt.hrl").

% Interface
-export([start/0, start/1, stop/0]).
-export([start_link/0]).
% States
-export([waiting/2, sniffing/2]).
% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).

-define(is_print(C), C >= $\s, C =< $~).

-record(state, {
        pid,
        crash = true,
        format = [] % full packet dump: binary, hex
        }).


%%--------------------------------------------------------------------
%%% Interface
%%--------------------------------------------------------------------
start() ->
    start([{filter, "tcp and port 80"},
            {chroot, "priv/tmp"}]).
start(Opt) when is_list(Opt) ->
    gen_fsm:send_event(?MODULE, {start, Opt}).

stop() ->
    gen_fsm:send_event(?MODULE, stop).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
start_link() ->
    gen_fsm:start({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    process_flag(trap_exit, true),
    {ok, waiting, #state{}}.

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.


%%
%% State: sniffing
%%
handle_info({packet, DLT, Time, Len, Data}, sniffing,
    #state{format = Format} = State) ->
    Packet = decode(DLT, Data, State),
    Headers = header(Packet),

    error_logger:info_report([
            {pcap, [{time, timestamp(Time)},
                    {caplen, byte_size(Data)},
                    {len, Len},
                    {datalink, pkt:dlt(DLT)}]}
        ] ++ Headers ++ packet(Format, Data)),
    {next_state, sniffing, State};

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, sniffing, State) ->
    {next_state, sniffing, State};

%%
%% State: waiting
%%

% epcap port stopped
handle_info({'EXIT', _Pid, normal}, waiting, State) ->
    {next_state, waiting, State}.

terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.


%%--------------------------------------------------------------------
%%% States
%%--------------------------------------------------------------------
waiting({start, Opt}, State) ->
    Format = proplists:get_value(format, Opt, []),
    Snaplen = proplists:get_value(snaplen, Opt),
    {ok, Pid} = epcap:start_link(Opt),
    {next_state, sniffing, State#state{
            pid = Pid,
            format = Format,
            crash = Snaplen =:= undefined
        }}.

sniffing({start, Opt}, #state{pid = Pid} = State) ->
    epcap:stop(Pid),
    {ok, Pid1} = epcap:start_link(Opt),
    {next_state, sniffing, State#state{pid = Pid1}};
sniffing(stop, #state{pid = Pid} = State) ->
    epcap:stop(Pid),
    {next_state, waiting, State}.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
decode(DLT, Data, #state{crash = true}) ->
    pkt:decapsulate({pkt:dlt(DLT), Data});
decode(DLT, Data, #state{crash = false}) ->
    case pkt:decode(pkt:dlt(DLT), Data) of
        {ok, {Headers, Payload}} ->
            Headers ++ [Payload];
        {error, SoFar, _Failed} ->
            SoFar
    end.

header(Payload) ->
    header(Payload, []).

header([], Acc) ->
    lists:reverse(Acc);
header([#ether{shost = Shost, dhost = Dhost}|Rest], Acc) ->
    header(Rest, [{ether, [{source_macaddr, ether_addr(Shost)},
                    {destination_macaddr, ether_addr(Dhost)}]}|Acc]);
header([#ipv4{saddr = Saddr, daddr = Daddr, p = Proto}|Rest], Acc) ->
    header(Rest, [{ipv4, [{protocol, pkt:proto(Proto)},
                    {source_address, inet_parse:ntoa(Saddr)},
                    {destination_address, inet_parse:ntoa(Daddr)}]}|Acc]);
header([#ipv6{saddr = Saddr, daddr = Daddr, next = Proto}|Rest], Acc) ->
    header(Rest, [{ipv6, [{protocol, pkt:proto(Proto)},
                    {source_address, inet_parse:ntoa(Saddr)},
                    {destination_address, inet_parse:ntoa(Daddr)}]}|Acc]);
header([#tcp{sport = Sport, dport = Dport, ackno = Ackno, seqno = Seqno,
            win = Win, cwr = CWR, ece = ECE, urg = URG, ack = ACK, psh = PSH,
            rst = RST, syn = SYN, fin = FIN}|Rest], Acc) ->
    Flags = [ F || {F,V} <- [{cwr, CWR}, {ece, ECE}, {urg, URG}, {ack, ACK},
                   {psh, PSH}, {rst, RST}, {syn, SYN}, {fin, FIN} ], V =:= 1 ],
    header(Rest, [{tcp, [{source_port, Sport}, {destination_port, Dport},
                    {flags, Flags}, {seq, Seqno}, {ack, Ackno}, {win, Win}]}|Acc]);
header([#udp{sport = Sport, dport = Dport, ulen = Ulen}|Rest], Acc) ->
    header(Rest, [{udp, [{source_port, Sport}, {destination_port, Dport},
                    {ulen, Ulen}]}|Acc]);
header([#icmp{type = Type, code = Code}|Rest], Acc) ->
    header(Rest, [{icmp, [{type, Type}, {code, Code}]}|Acc]);
header([#icmp6{type = Type, code = Code}|Rest], Acc) ->
    header(Rest, [{icmp6, [{type, Type}, {code, Code}]}|Acc]);
header([Hdr|Rest], Acc) when is_tuple(Hdr) ->
    header(Rest, [{header, Hdr}|Acc]);
header([Payload|Rest], Acc) when is_binary(Payload) ->
    header(Rest, [{payload, to_ascii(Payload)},
            {payload_size, byte_size(Payload)}|Acc]).

packet(Format, Bin) ->
    packet(Format, Bin, []).
packet([], _Bin, Acc) ->
    lists:reverse(Acc);
packet([binary|Rest], Bin, Acc) ->
    packet(Rest, Bin, [{packet, Bin}|Acc]);
packet([hex|Rest], Bin, Acc) ->
    packet(Rest, Bin, [{packet, to_hex(Bin)}|Acc]).

to_ascii(Bin) when is_binary(Bin) ->
    [ to_ascii(C) || <<C:8>> <= Bin ];
to_ascii(C) when ?is_print(C) -> C;
to_ascii(_) -> $..

to_hex(Bin) when is_binary(Bin) ->
    [ integer_to_list(N, 16) || <<N:8>> <= Bin ].

ether_addr(MAC) ->
    string:join(to_hex(MAC), ":").

timestamp(Now) when is_tuple(Now) ->
    iso_8601_fmt(calendar:now_to_local_time(Now)).

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B",
            [Year, Month, Day, Hour, Min, Sec])).
