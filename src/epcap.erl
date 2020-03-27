%%% @copyright 2009-2020 Michael Santos <michael.santos@gmail.com>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from
%%% this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%%% HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
%%% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
%%% PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-module(epcap).

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, start_link/2, stop/1]).

-export([start/0, start/1, start/2]).

-export([send/2]).

-export([getopts/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-export_type([time_unit/0, options/0]).

-record(state, {pid  :: pid(), port  :: port()}).

-type time_unit() :: timestamp | microsecond.

%% @doc start the epcap port process
-spec start() -> ignore | {error, _} | {ok, pid()}.

start() -> start(self(), []).

%% @doc start the epcap port process
-spec start(options()) -> ignore | {error, _} | {ok, pid()}.

start(Options) -> start(self(), Options).

%% @doc start the epcap port process
-spec start(pid(), options()) -> ignore | {error, _} | {ok, pid()}.

start(Pid, Options) when is_pid(Pid), is_list(Options) ->
    gen_server:start(?MODULE, [Pid, Options], []).

%% @doc start and link with the epcap port process
-spec start_link() -> ignore | {error, _} | {ok, pid()}.

start_link() -> start_link(self(), []).

%% @doc start and link with the epcap port process
-spec start_link(options()) -> ignore | {error, _} | {ok, pid()}.

start_link(Options) -> start_link(self(), Options).

%% @doc start and link with the epcap port process
%%
%% Packets are delivered as messages:
%%
%% ```
%% {packet, DataLinkType, Time, Length, Packet}
%% '''
%%
%% The DataLinkType is an integer representing the link layer,
%% e.g., ethernet, Linux cooked socket.
%%
%% The Time can be either in microseconds or a timestamp in the same
%% format as erlang:now/0 depending on the value of the time_unit
%% option (default: timestamp):
%%
%% ```
%% {MegaSecs, Secs, MicroSecs}
%% '''
%%
%% The Length corresponds to the actual packet length on the
%% wire. The captured packet may have been truncated. To get the
%% captured packet length, use byte_size(Packet).
%%
%% The Packet is a binary holding the captured data.
%%
%% If the version of the pcap library supports it, the pcap buffer
%% size can be set to avoid dropped packets by using the 'buffer'
%% option. The buffer size must be larger than the snapshot
%% length (default: 65535) plus some overhead for the pcap data
%% structures. Using some multiple of the snapshot length is
%% suggested.
-spec start_link(pid(), options()) -> ignore | {error, _} | {ok, pid()}.

start_link(Pid, Options) -> gen_server:start_link(?MODULE, [Pid, Options], []).

%% @doc Inject a packet on the network interface.
%%
%% To enable sending packets, start_link/1 must be called with the
%% `{inject, true}' option (default: `{inject, false}'). When disabled,
%% any data sent to the epcap port is silently discarded. Packet injection
%% failures are treated as fatal errors, terminating the epcap port. Partial
%% writes are not considered to be errors and are ignored (an error message
%% will be printed to stderr if the verbose option is used).
-spec send(pid(), iodata()) -> ok.

send(Pid, Packet) when is_pid(Pid) ->
    case iolist_size(Packet) < 65535 of
      true -> gen_server:call(Pid, {send, Packet}, infinity);
      false -> erlang:error(badarg)
    end.

-spec stop(pid()) -> ok.

stop(Pid) -> catch gen_server:call(Pid, stop), ok.

init([Pid, Options0]) ->
    process_flag(trap_exit, true),
    Options = setopts([{chroot, filename:join([basedir(), "tmp"])},
                       {timeout, timeout()}, {direction, inout}],
                      Options0),
    ok = filelib:ensure_dir(filename:join(proplists:get_value(chroot, Options),
                                          ".")),
    [Cmd | Argv] = getopts(Options),
    Port = open_port({spawn_executable, Cmd},
                     [{args, Argv}, {packet, 2}, binary, exit_status]),
    % Block until the port has fully initialized
    receive
      {Port, {data, Data}} ->
          {epcap, ready} = binary_to_term(Data), {ok, #state{pid = Pid, port = Port}};
      {'EXIT', Port, normal} -> {stop, {error, port_init_failed}};
      {'EXIT', Port, Reason} -> {stop, {error, Reason}}
    end.

handle_call({send, Packet}, _From, #state{port = Port} = State) ->
    Reply = try erlang:port_command(Port, Packet) of
              true -> ok
            catch
              error:badarg -> {error, closed}
            end,
    {reply, Reply, State};
handle_call(stop, _From, State) -> {stop, normal, ok, State}.

handle_cast(_Msg, State) -> {noreply, State}.

terminate(_Reason, #state{port = Port}) -> catch erlang:port_close(Port), ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%--------------------------------------------------------------------
%%% Port communication
%%--------------------------------------------------------------------
handle_info({Port, {data, Data}}, #state{port = Port, pid = Pid} = State) ->
    Pid ! binary_to_term(Data), {noreply, State};
handle_info({'EXIT', Port, Reason}, #state{port = Port} = State) ->
    {stop, {shutdown, Reason}, State};
handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) ->
    case Status of
      0 -> {stop, normal, State};
      _ when 128 < Status -> {stop, {port_terminated, Status - 128}, State};
      _ -> {stop, {port_terminated, Status}, State}
    end;
handle_info(Info,
            State) ->  %% WTF
    error_logger:error_report([{wtf, Info}]), {noreply, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
-type arg_num() :: string() | non_neg_integer().

-type options() :: [inject | monitor | promiscuous | verbose |
                    {buffer, arg_num()} | {chroot, string()} | {cluster_id, arg_num()} |
                    {direction, in | out | inout} | {env, string()} | {exec, string()} |
                    {file, string()} | {filter, string()} | {group, string()} |
                    {interface, string()} | {progname, string()} | {snaplen, arg_num()} |
                    {time_unit, time_unit()} | {timeout, arg_num()} | {user, string()} |
                    {verbose, arg_num()}].

-spec setopts(options(), options()) -> options().

setopts([], Options) -> proplists:compact(Options);
setopts([{Key, Val} | Rest], Options) ->
    case proplists:get_value(Key, Options) of
      undefined -> setopts(Rest, [{Key, Val} | Options]);
      _ -> setopts(Rest, Options)
    end.

-spec getopts(options()) -> [string()].

getopts(Options) when is_list(Options) ->
    Exec = exec(Options),
    Progname = proplists:get_value(progname, Options, progname()),
    Cpu_affinity = cpu_affinity(Options),
    Filter = proplists:get_value(filter, Options, ""),
    Switches0 = lists:append([optarg(Opt) || Opt <- Options]),
    Switches = Switches0 ++ [Filter],
    [Cmd | Argv] = [N
                    || N <- string:tokens(Exec, " ") ++ [Cpu_affinity, Progname | Switches],
                       N /= ""],
    [find_executable(Cmd) | Argv].

-spec optarg(atom() | tuple()) -> string().

optarg({buffer, Arg}) -> switch("b", maybe_string(Arg));
optarg({chroot, Arg}) -> switch("d", Arg);
optarg({cluster_id, Arg}) -> switch("e", env("PCAP_PF_RING_CLUSTER_ID", Arg));
optarg({env, Arg}) -> switch("e", Arg);
optarg({file, Arg}) -> switch("f", Arg);
optarg({group, Arg}) -> switch("g", Arg);
optarg({interface, Arg}) -> switch("i", Arg);
optarg(monitor) -> switch("M");
optarg(promiscuous) -> switch("P");
optarg({snaplen, Arg}) -> switch("s", maybe_string(Arg));
optarg({time_unit, Arg}) -> switch("T", time_unit(Arg));
optarg({timeout, Arg}) -> switch("t", maybe_string(Arg));
optarg({user, Arg}) -> switch("u", Arg);
optarg(verbose) -> switch("v");
optarg({verbose, 0}) -> "";
optarg({verbose, Arg}) -> switch(string:copies("v", Arg));
optarg(inject) -> switch("X");
optarg({direction, Arg}) -> switch("Q", maybe_string(Arg));
optarg(_) -> "".

switch(Switch) -> [lists:concat(["-", Switch])].

switch(Switch, Arg) -> [lists:concat(["-", Switch]), Arg].

env(Key, Val) -> lists:concat([Key, "=", maybe_string(Val)]).

-spec basedir() -> string().

basedir() ->
    case code:priv_dir(?MODULE) of
      {error, bad_name} ->
          filename:join([filename:dirname(code:which(?MODULE)), "..", "priv", ?MODULE]);
      Dir -> Dir
    end.

-spec progname() -> string().

progname() -> filename:join([basedir(), ?MODULE]).

-spec exec(proplists:proplist()) -> string().

exec(Options) ->
    Exec = proplists:get_value(exec, Options, "sudo"),
    case proplists:is_defined(file, Options) of
      true -> "";
      false -> Exec
    end.

-spec cpu_affinity(proplists:proplist()) -> string().

cpu_affinity(Options) ->
    case proplists:get_value(cpu_affinity, Options) of
      undefined -> "";
      CPUs -> "taskset -c " ++ CPUs
    end.

-spec timeout() -> 0 | 500.

timeout() ->
    case os:type() of
      {unix, linux} -> 0;
      _ -> 500
    end.

%-spec time_unit(time_unit()) -> "0" | "1".
time_unit(timestamp) -> "0";
time_unit(microsecond) -> "1".

find_executable(Exe) ->
    case os:find_executable(Exe) of
      false -> erlang:error(badarg, [Exe]);
      N -> N
    end.

maybe_string(T) when is_list(T) -> T;
maybe_string(T) when is_integer(T) -> integer_to_list(T);
maybe_string(T) when is_atom(T) -> atom_to_list(T);
maybe_string(T) when is_binary(T) -> binary_to_list(T).

