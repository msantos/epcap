%% Copyright (c) 2013-2020, Michael Santos <michael.santos@gmail.com>
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
-module(epcap_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("pkt/include/pkt.hrl").

-export([suite/0, all/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    getopts/1,
    filter/1,
    filter_with_microsecond/1,
    filter_with_outbound/1,
    filter_with_inbound/1,
    send/1,
    timeout_immediate/1,
    timeout_0/1,
    timeout_3000/1,
    timeout_infinity/1
]).

all() ->
    [
        getopts,
        filter,
        filter_with_microsecond,
        filter_with_outbound,
        filter_with_inbound,
        send,
        timeout_immediate,
        timeout_0,
        timeout_3000,
        timeout_infinity
    ].

suite() -> [{timetrap, {seconds, 60}}].

init_per_testcase(filter_with_microsecond, Config) ->
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {time_unit, microsecond},
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                promiscuous
            ]
    ),
    [{drv, Drv} | Config];
init_per_testcase(filter_with_outbound, Config) ->
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {time_unit, microsecond},
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                {direction, out},
                promiscuous
            ]
    ),
    [{drv, Drv} | Config];
init_per_testcase(filter_with_inbound, Config) ->
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {time_unit, microsecond},
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                {direction, in},
                promiscuous
            ]
    ),
    [{drv, Drv} | Config];
init_per_testcase(Test, Config) when Test > timeout_, Test < timeout_zzz ->
    "timeout_" ++ TimeoutStr = atom_to_list(Test),
    Timeout =
        try
            list_to_integer(TimeoutStr)
        catch
            _:_ -> list_to_atom(TimeoutStr)
        end,
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                {timeout, Timeout},
                promiscuous
            ]
    ),
    [{drv, Drv} | Config];
init_per_testcase(send, Config) ->
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                promiscuous
            ]
    ),
    {ok, Drv1} =
        case os:type() of
            {unix, linux} ->
                % XXX Linux: injected packet is not seen by filter
                epcap:start(
                    Dev ++
                        [
                            {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                            {filter, "tcp and port 39"},
                            promiscuous
                        ]
                );
            _ ->
                {ok, undefined}
        end,
    [{drv, Drv}, {drv1, Drv1} | Config];
init_per_testcase(getopts, Config) ->
    Config;
init_per_testcase(_Test, Config) ->
    Dev =
        case os:getenv("EPCAP_TEST_INTERFACE") of
            false -> [];
            N -> [{interface, N}]
        end,
    Verbose = list_to_integer(os:getenv("EPCAP_TEST_VERBOSE", "0")),
    % Solaris pcap using DLPI requires the interface to be in promiscuous
    % mode for outgoing packets to be captured
    {ok, Drv} = epcap:start(
        Dev ++
            [
                {exec, os:getenv("EPCAP_TEST_EXEC", "sudo -n")},
                inject,
                {verbose, Verbose},
                {filter, "tcp and ( port 29 or port 39 )"},
                promiscuous
            ]
    ),
    [{drv, Drv} | Config].

end_per_testcase(send, Config) ->
    Drv = (?config(drv, Config)),
    Drv1 = (?config(drv1, Config)),
    epcap:stop(Drv),
    epcap:stop(Drv1);
end_per_testcase(getopts, _Config) ->
    ok;
end_per_testcase(_Test, Config) ->
    Drv = (?config(drv, Config)),
    epcap:stop(Drv).

getopts(_Config) ->
    [
        Sudo,
        "-n",
        Progname,
        "-b",
        "1024",
        "-d",
        "/tmp/",
        "-e",
        "PCAP_PF_RING_CLUSTER_ID=0",
        "-g",
        "nobody",
        "-i",
        "eth0",
        "-M",
        "-P",
        "-s",
        "256",
        "-T",
        "1",
        "-u",
        "nobody",
        "-v",
        "-vvv",
        "-X",
        "-Q",
        "inout",
        "-t",
        "1",
        "-t",
        "-1",
        "-t",
        "0",
        "-e",
        "FOO=bar",
        "tcp and port 80"
    ] =
        epcap:getopts([
            {buffer, 1024},
            {chroot, "/tmp/"},
            {cluster_id, 0},
            {group, "nobody"},
            {interface, "eth0"},
            monitor,
            promiscuous,
            {snaplen, 256},
            {time_unit, microsecond},
            {time_out, 60},
            {user, "nobody"},
            verbose,
            {verbose, 3},
            {verbose, 0},
            inject,
            {direction, inout},
            {filter, "tcp and port 80"},
            {timeout, 1},
            {timeout, infinity},
            {timeout, immediate},
            {exec, "sudo -n"},
            {env, "FOO=bar"}
        ]),
    "sudo" = filename:basename(Sudo),
    "epcap" = filename:basename(Progname),
    [Progname, "-f", "/tmp/foo"] = epcap:getopts([
        {file, "/tmp/foo"},
        {exec, "sudo -n"}
    ]),
    ok.

filter(_Config) ->
    {error, _Reason} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 2000),
    receive
        {packet, DataLinkType, {A, B, C} = Time, Length, Packet} when A > 0, B > 0, C > 0 ->
            ct:pal(
                io_lib:format(
                    "~p",
                    [
                        [
                            {dlt, DataLinkType},
                            {time, Time},
                            {length, Length},
                            {packet, Packet}
                        ]
                    ]
                )
            ),
            [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] = pkt:decapsulate(Packet)
    end.

filter_with_microsecond(_Config) ->
    {error, _} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 2000),
    receive
        {packet, DataLinkType, Time, Length, Packet} when Time > 0 ->
            ct:pal(
                io_lib:format(
                    "~p",
                    [
                        [
                            {dlt, DataLinkType},
                            {time, Time},
                            {length, Length},
                            {packet, Packet}
                        ]
                    ]
                )
            ),
            [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] = pkt:decapsulate(Packet)
    end.

filter_with_outbound(_Config) ->
    {error, _} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 2000),
    receive
        {packet, DataLinkType, Time, Length, Packet} when Time > 0 ->
            ct:pal(
                io_lib:format(
                    "~p",
                    [
                        [
                            {dlt, DataLinkType},
                            {time, Time},
                            {length, Length},
                            {packet, Packet}
                        ]
                    ]
                )
            ),
            [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] = pkt:decapsulate(Packet)
    end.

filter_with_inbound(_Config) ->
    {error, _} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 2000),
    receive
        fail_when_some_received -> ok
    after 1000 -> ok
    end.

timeout_immediate(Config) ->
    timeout(Config, 0).

timeout_0(Config) ->
    timeout(Config, 0).

timeout_3000(Config) ->
    timeout(Config, 3000).

timeout(_Config, ExpDelay) ->
    Start = erlang:monotonic_time(millisecond),
    {error, _Reason} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 500),
    receive
        {packet, DataLinkType, {A, B, C} = Time, Length, Packet} when
            A > 0, B > 0, C > 0
        ->
            Stop = erlang:monotonic_time(millisecond),
            ct:pal(
                io_lib:format(
                    "~p",
                    [
                        [
                            {dlt, DataLinkType},
                            {time, Time},
                            {length, Length},
                            {packet, Packet},
                            {delay, Stop - Start}
                        ]
                    ]
                )
            ),
            true = (Stop - Start) < ExpDelay + 1000,
            [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] = pkt:decapsulate(Packet)
    end.

timeout_infinity(_Config) ->
    Start = erlang:monotonic_time(millisecond),
    {error, _Reason} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 500),
    receive
        {packet, DataLinkType, {A, B, C} = Time, Length, Packet} when
            A > 0, B > 0, C > 0
        ->
            Stop = erlang:monotonic_time(millisecond),
            ct:pal(
                io_lib:format(
                    "~p",
                    [
                        [
                            {dlt, DataLinkType},
                            {time, Time},
                            {length, Length},
                            {packet, Packet},
                            {delay, Stop - Start}
                        ]
                    ]
                )
            ),
            ct:fail("Unexpected packet (infinite timeout)")
    after 5000 -> ok
    end.

send(Config) ->
    Drv = (?config(drv, Config)),
    {error, _} = gen_tcp:connect({8, 8, 8, 8}, 29, [binary], 2000),
    Frame =
        receive
            {packet, _DataLinkType, _Time, _Length, Packet} ->
                [#ether{} = Ether, #ipv4{} = IP, #tcp{} = TCP, Payload] =
                    pkt:decapsulate(Packet),
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
    ct:pal(io_lib:format("~p", [[{frame, Frame}]])),
    ok = epcap:send(Drv, Frame),
    send_1().

send_1() ->
    receive
        {packet, DataLinkType, Time, Length, Packet} ->
            case pkt:decapsulate(Packet) of
                [#ether{}, #ipv4{}, #tcp{dport = 39}, _Payload] ->
                    ct:pal(
                        io_lib:format(
                            "~p",
                            [
                                [
                                    {dlt, DataLinkType},
                                    {time, Time},
                                    {length, Length},
                                    {packet, Packet}
                                ]
                            ]
                        )
                    ),
                    ok;
                % TCP SYN retries
                [#ether{}, #ipv4{}, #tcp{dport = 29}, _Payload] ->
                    send_1()
            end
    end.
