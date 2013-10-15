%% Copyright (c) 2009-2013, Michael Santos <michael.santos@gmail.com>
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

send(Pid, Packet) when is_pid(Pid), is_binary(Packet), byte_size(Packet) < 16#ffff ->
    gen_server:call(Pid, {send, Packet}, infinity).

stop(Pid) ->
    gen_server:call(Pid, stop).

init([Pid, Options]) ->
    process_flag(trap_exit, true),
    Chroot = case proplists:get_value(chroot, Options) of
        undefined ->
            filename:join([basedir(), "tmp"]);
        Value ->
            Value
    end,
    ok = filelib:ensure_dir(filename:join(Chroot, "dummy")),
    Timeout = case os:type() of
        {unix, linux} -> 0;
        _ -> 500
    end,
    Cmd = make_args(Options ++ [{chroot, Chroot}, {timeout, Timeout}]),
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
make_args(PL) ->
    Sudo = case proplists:is_defined(file, PL) of
        true -> "";
        false -> "sudo "
    end,
    proplists:get_value(progname, PL, Sudo ++ pfring(PL) ++ cpu_affinity(PL) ++ progname()) ++ " " ++
    string:join([get_switch(proplists:lookup(Arg, PL)) || Arg <- [
            chroot,
            group,
            interface,
            file,
            monitor,
            promiscuous,
            inject,
            user,
            snaplen,
            timeout,
            verbose,
            filter
        ], proplists:lookup(Arg, PL) /= none], " ").

get_switch({chroot, Arg})       -> "-d " ++ Arg;
get_switch({file, Arg})         -> "-f " ++ Arg;
get_switch({group, Arg})        -> "-g " ++ Arg;
get_switch({interface, Arg})    -> "-i " ++ Arg;
get_switch({monitor, true})     -> "-M";
get_switch({promiscuous, true}) -> "-P";
get_switch({snaplen, Arg})      -> "-s " ++ integer_to_list(Arg);
get_switch({timeout, Arg})      -> "-t " ++ integer_to_list(Arg);
get_switch({user, Arg})         -> "-u " ++ Arg;
get_switch({verbose, Arg})      -> string:copies("-v ", Arg);
get_switch({inject, true})      -> "-X";
get_switch({filter, Arg})       -> "\"" ++ Arg ++ "\"".

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

-spec pfring([proplists:property()]) -> string().
pfring(Options) ->
    case proplists:get_value(cluster_id, Options) of
        undefined -> "";
        Value ->
            "PCAP_PF_RING_CLUSTER_ID=" ++ integer_to_list(Value) ++ " "
    end.

-spec cpu_affinity([proplists:property()]) -> string().
cpu_affinity(Options) ->
    case proplists:get_value(cpu_affinity, Options) of
        undefined -> "";
        CPUs ->
            "taskset -c " ++ CPUs ++ " "
    end.
