%% Copyright (c) 2013-2015, Michael Santos <michael.santos@gmail.com>
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
-module(epcap_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-include_lib("pkt/include/pkt.hrl").

epcap_test_() ->
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Ref} = epcap:start(epcap_dev() ++ [
            inject,
            {filter, "tcp and ( port 29 or port 39 )"},
            promiscuous
        ]),

    {timeout, 480, [
            {?LINE, fun() -> epcap_filter(Ref) end},
            {?LINE, fun() -> epcap_send(Ref) end}
        ]}.

epcap_dev() ->
    case os:getenv("EPCAP_TEST_INTERFACE") of
        false -> [];
        Dev -> [{interface, Dev}]
    end.

epcap_filter(_Ref) ->
    {error, timeout} = gen_tcp:connect({8,8,8,8}, 29, [binary], 2000),

    receive
        {packet, DataLinkType, Time, Length, Packet} ->
            error_logger:info_report([
                    {dlt, DataLinkType},
                    {time, Time},
                    {length, Length},
                    {packet, Packet}
                ]),
            [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] = pkt:decapsulate(Packet)
    end.

epcap_send(Ref) ->
    {error, timeout} = gen_tcp:connect({8,8,8,8}, 29, [binary], 2000),

    Frame = receive
        {packet, _DataLinkType, _Time, _Length, Packet} ->
            [#ether{} = Ether, #ipv4{} = IP, #tcp{} = TCP, Payload] = pkt:decapsulate(Packet),
            TCP1 = TCP#tcp{dport = 39, sport = 39, sum = 0},
            Sum0 = pkt:makesum(IP#ipv4{sum = 0}),
            Sum1 = pkt:makesum([IP, TCP1, Payload]),
            list_to_binary([
                    pkt:ether(Ether),
                    pkt:ipv4(IP#ipv4{sum = Sum0}),
                    pkt:tcp(TCP1#tcp{sum = Sum1}),
                    Payload
                ])
    end,
    error_logger:info_report([{frame, Frame}]),
    ok = epcap:send(Ref, Frame),
    epcap_send_1().

epcap_send_1() ->
    receive
        {packet, DataLinkType, Time, Length, Packet} ->
            case pkt:decapsulate(Packet) of
                [#ether{}, #ipv4{}, #tcp{dport = 39}, _Payload] ->
                    error_logger:info_report([
                        {dlt, DataLinkType},
                        {time, Time},
                        {length, Length},
                        {packet, Packet}
                    ]),
                    ok;
                % TCP SYN retries
                [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] ->
                    epcap_send_1()
            end
    end.
