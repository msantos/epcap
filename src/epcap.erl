%% Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
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

-behaviour(gen_server).

%% API
-export([start/0, start/1, start/2, stop/1]).
-export([start_link/2]).
-export([send/2]).
-export([getopts/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {pid :: pid(), port :: port()}).

start() ->
    start_link(self(), []).
start(Options) ->
    start_link(self(), Options).
start(Pid, Options) when is_pid(Pid), is_list(Options) ->
    start_link(Pid, Options).

start_link(Pid, Options) ->
    gen_server:start_link(?MODULE, [Pid, Options], []).

send(Pid, Packet) when is_pid(Pid) ->
    case iolist_size(Packet) < 16#ffff of
        true ->
            gen_server:call(Pid, {send, Packet}, infinity);
        false ->
            erlang:error(badarg)
    end.

stop(Pid) ->
    gen_server:call(Pid, stop).

init([Pid, Options]) ->
    process_flag(trap_exit, true),
    Options1 = setopts([
            {chroot, filename:join([basedir(), "tmp"])},
            {timeout, timeout()}
        ], Options),
    ok = filelib:ensure_dir(filename:join(proplists:get_value(
                chroot,
                Options1
            ), ".")),
    Cmd = string:join(getopts(Options1), " "),
    Port = open_port({spawn, Cmd}, [{packet, 2}, binary, exit_status]),
    {ok, #state{pid = Pid, port = Port}}.

handle_call({send, Packet}, _From, #state{port = Port} = State) ->
    Reply = try erlang:port_command(Port, Packet) of
        true ->
            ok
        catch
            error:badarg ->
                {error,closed}
        end,
    {reply, Reply, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #state{port = Port}) ->
    catch erlang:port_close(Port),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Port communication
%%--------------------------------------------------------------------
handle_info({Port, {data, Data}}, #state{port = Port, pid = Pid} = State) ->
    Pid ! binary_to_term(Data),
    {noreply, State};

handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) when Status > 128 ->
    {stop, {port_terminated, Status-128}, State};
handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) ->
    {stop, {port_terminated, Status}, #state{port = Port} = State};
handle_info({'EXIT', Port, Reason}, #state{port = Port} = State) ->
    {stop, {shutdown, Reason}, State};

% WTF
handle_info(Info, State) ->
    error_logger:error_report([{wtf, Info}]),
    {noreply, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
setopts([], Options) ->
    proplists:compact(Options);
setopts([{Key,Val}|Rest], Options) ->
    case proplists:get_value(Key, Options) of
        undefined ->
            setopts(Rest, [{Key,Val}|Options]);
        _ ->
            setopts(Rest, Options)
    end.

getopts(Options) when is_list(Options) ->
    Exec = exec(Options),
    Progname = proplists:get_value(progname, Options, progname()),
    Cpu_affinity = cpu_affinity(Options),
    Filter = proplists:get_value(filter, Options, ""),

    Switches0 = [ optarg(Opt) || Opt <- Options ],
    Switches = Switches0 ++ [quote(Filter)],

    [ N || N <- [Exec, Cpu_affinity, Progname|Switches], N /= ""].

optarg({buffer, Arg})       -> switch("b", Arg);
optarg({chroot, Arg})       -> switch("d", Arg);
optarg({cluster_id, Arg})   -> switch("e", env("PCAP_PF_RING_CLUSTER_ID", Arg));
optarg({file, Arg})         -> switch("f", Arg);
optarg({group, Arg})        -> switch("g", Arg);
optarg({interface, Arg})    -> switch("i", Arg);
optarg(monitor)             -> switch("M");
optarg(promiscuous)         -> switch("P");
optarg({snaplen, Arg})      -> switch("s", Arg);
optarg({timeout, Arg})      -> switch("t", Arg);
optarg({user, Arg})         -> switch("u", Arg);
optarg(verbose)             -> switch("v");
optarg({verbose, Arg})      -> switch(string:copies("v", Arg));
optarg(inject)              -> switch("X");
optarg(_)                   -> "".

switch(Switch) ->
    lists:concat(["-", Switch]).

switch(Switch, Arg) ->
    lists:concat(["-", Switch, " ", Arg]).

env(Key, Val) ->
    lists:concat([Key, "=", Val]).

quote("") ->
    "";
quote(Str) ->
    "\"" ++ Str ++ "\"".

-spec basedir() -> string().
basedir() ->
    case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            filename:join([
                filename:dirname(code:which(?MODULE)),
                "..",
                "priv",
                ?MODULE
            ]);
        Dir ->
            Dir
    end.

-spec progname() -> string().
progname() ->
    filename:join([basedir(), ?MODULE]).

-spec exec([proplists:property()]) -> string().
exec(Options) ->
    Exec = proplists:get_value(exec, Options, "sudo"),
    case proplists:is_defined(file, Options) of
        true -> "";
        false -> Exec
    end.

-spec cpu_affinity([proplists:property()]) -> string().
cpu_affinity(Options) ->
    case proplists:get_value(cpu_affinity, Options) of
        undefined -> "";
        CPUs ->
            "taskset -c " ++ CPUs
    end.

timeout() ->
    case os:type() of
        {unix, linux} -> 0;
        _ -> 500
    end.
