%% Copyright (c) 2013, Michael Santos <michael.santos@gmail.com>
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
    {ok, Ref} = epcap:start(epcap_dev() ++ [{filter, "tcp and port 29"}]),

    {timeout, 480, [
            {?LINE, fun() -> epcap_filter(Ref) end}
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
