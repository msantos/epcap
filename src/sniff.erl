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
-behaviour(gen_server).

-include("epcap_net.hrl").

-define(SERVER, ?MODULE).

-export([start_link/0,start/0,start/1,stop/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).


start() ->
    start([{filter, "tcp and port 80"},
            {interface, "en1"},
            {chroot, "priv/tmp"}]).
start(Arg) when is_list(Arg) ->
    gen_server:call(?SERVER, {start, Arg}).

stop() ->
    gen_server:call(?SERVER, stop).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).


%%
%% gen_server callbacks
%%
init([]) ->
    {ok, waiting}.

handle_call({start, Arg}, _From, waiting) ->
    epcap:start(Arg),
    {reply, ok, sniffing};
handle_call({start, Arg}, _From, sniffing) ->
    epcap:stop(),
    epcap:start(Arg),
    {reply, ok, sniffing};
handle_call(stop, _From, sniffing) ->
    epcap:stop(),
    {reply, ok, waiting}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info([{pkthdr, {{time, Time},{caplen, CapLen},{len, Len}}}, {packet, Packet}], State) ->
    [Ether, IP, Hdr, Payload] = epcap_net:decapsulate(Packet),
    error_logger:info_report([
            {time, timestamp(Time)},
            {caplen,CapLen},
            {len,Len},

            % Source 
            {source_macaddr, string:join(epcap_net:ether_addr(Ether#ether.shost), ":")},
            {source_address, IP#ipv4.saddr},
            {source_port, port(sport, Hdr)},

            % Destination 
            {destination_macaddr, string:join(epcap_net:ether_addr(Ether#ether.dhost), ":")},
            {destination_address, IP#ipv4.daddr},
            {destination_port, port(dport, Hdr)},

            {protocol, epcap_net:proto(IP#ipv4.p)},
            {protocol_header, header(Hdr)},

            {payload_bytes, byte_size(Payload)},
            {payload, epcap_net:payload(Payload)}

        ]),
    {noreply, State};
% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% 
%% Internal functions
%% 
timestamp(Now) when is_tuple(Now) ->
    iso_8601_fmt(calendar:now_to_local_time(Now)).

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B",
            [Year, Month, Day, Hour, Min, Sec])).

header(#tcp{ackno = Ackno, seqno = Seqno, win = Win} = Hdr) ->
    [{flags, epcap_net:tcp_flags(Hdr)},
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


