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
-module(epcap).

-export([start/0, start/1, stop/0]).

-define(PROGNAME, "sudo priv/epcap").

start() ->
    start([]).
start(PL) when is_list(PL) ->
    Args = make_args(PL),
    Port = Args,
    Pid = self(),
    spawn_link(fun() -> init(Pid, Port) end).
stop() ->
    ?MODULE ! stop.

init(Pid, ExtPrg) ->
    register(?MODULE, self()),
    process_flag(trap_exit, true),
    Port = open_port({spawn, ExtPrg}, [{packet, 2}, binary, exit_status]),
    loop(Pid, Port).

loop(Caller, Port) ->
    receive
        {Port, {data, Data}} ->
            Caller !  binary_to_term(Data),
            loop(Caller, Port);
        {Port, {exit_status, Status}} when Status > 128 ->
            io:format("Port terminated with signal: ~p~n", [Status - 128]),
            exit({port_terminated, Status});
        {Port, {exit_status, Status}} ->
            io:format("Port terminated with status: ~p~n", [Status]),
            exit({port_terminated, Status});
        {'EXIT', Port, Reason} ->
            exit(Reason);
        stop ->
            erlang:port_close(Port),
            exit(normal)
    end.

make_args(PL) ->
    proplists:get_value(progname, PL, ?PROGNAME) ++ " " ++
    string:join([ get_switch(proplists:lookup(Arg, PL)) || Arg <- [
            chroot,
            group,
            interface,
            promiscuous,
            user,
            snaplen,
            timeout,

            filter
        ], proplists:lookup(Arg, PL) /= none ],
    " ").

get_switch({chroot, Arg})       -> "-d " ++ Arg;
get_switch({group, Arg})        -> "-g " ++ Arg;
get_switch({interface, Arg})    -> "-i " ++ Arg;
get_switch({promiscuous, Arg})  -> "-P";
get_switch({snaplen, Arg})      -> "-s " ++ integer_to_list(Arg);
get_switch({timeout, Arg})      -> "-t " ++ integer_to_list(Arg);
get_switch({user, Arg})         -> "-u " ++ Arg;
get_switch({filter, Arg})       -> "\"" ++ Arg ++ "\"".


