%%% Copyright (c) 2013-2015, Michael Santos <michael.santos@gmail.com>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% Redistributions of source code must retain the above copyright
%%% notice, this list of conditions and the following disclaimer.
%%%
%%% Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% Neither the name of the author nor the names of its contributors
%%% may be used to endorse or promote products derived from this software
%%% without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%%% POSSIBILITY OF SUCH DAMAGE.
-module(icmp_resend).
-export([start/1, start/2]).

%% An example of using epcap to send packets. It sniffs the
%% network for ICMP packets and spoofs them.
%%
%% Listen on a network device:
%%
%% $ ./start.sh
%% 1> icmp_resend:start("eth0").
%%
%% In another shell, run ping:
%%
%% $ ping google.com
%% PING google.com (173.194.43.69) 56(84) bytes of data.
%% 64 bytes from yyz08s09-in-f5.1e100.net (173.194.43.69): icmp_req=1 ttl=54 time=36.0 ms
%% 64 bytes from yyz08s09-in-f5.1e100.net (173.194.43.69): icmp_req=1 ttl=54 time=37.2 ms (DUP!)
%% 64 bytes from yyz08s09-in-f5.1e100.net (173.194.43.69): icmp_req=2 ttl=54 time=13.9 ms
%% 64 bytes from yyz08s09-in-f5.1e100.net (173.194.43.69): icmp_req=2 ttl=54 time=15.7 ms (DUP!)
%% ^C
%% --- google.com ping statistics ---
%% 2 packets transmitted, 2 received, +2 duplicates, 0% packet loss, time 1001ms
%% rtt min/avg/max/mdev = 13.914/25.738/37.222/10.915 ms

start(Dev) ->
    start(Dev, 0).
start(Dev, Verbose) ->
    {ok, Ref} = epcap:start([
            {verbose, Verbose},
            {inteface, Dev},
            inject,
            {filter, "icmp"}
        ]),
    resend(Ref).

resend(Ref) ->
    receive
        {packet, _DataLinkType, _Time, _Length, Packet} ->
            ok = epcap:send(Ref, Packet),
            resend(Ref)
    end.
