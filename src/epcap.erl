%%% @copyright 2009-2023 Michael Santos <michael.santos@gmail.com>
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

%% @doc An Erlang port interface to libpcap.
%%
%% == SETUP ==
%%
%% ```
%% # Allow your user to epcap with root privs
%% sudo visudo
%% youruser ALL = NOPASSWD: /path/to/epcap/priv/epcap
%% # And if requiretty is enabled, disable it by using one of these
%% Defaults!/path/to/epcap/priv/epcap !requiretty
%% Defaults:youruser !requiretty
%% '''
%%
%% == EXAMPLES ==
%%
%% To run the `sniff' example:
%%
%% ```
%% $ mkdir -p ebin
%% $ erlc +debug_info -I _build/default/lib -o ebin examples/*.erl
%% '''
%%
%% ```
%% rebar3 shell
%%
%% % Start the sniffer process
%% sniff:start_link().
%%
%% % Use your interface, or leave it out and trust in pcap
%% sniff:start([{interface, "eth0"}]).
%%
%% % To change the filter
%% sniff:start([{filter, "icmp or (tcp and port 80)"},{interface, "eth0"}]).
%%
%% % To stop sniffing
%% sniff:stop().
%% '''
%%
%% == PF_RING ==
%%
%% In case you want to compile epcap with PF_RING support, just specify
%% the path to the libpfring and modified libpcap libraries via shell
%% variable PFRING.
%%
%% ```
%% PFRING=/home/user/pfring rebar3 do clean, compile
%% '''
%%
%% To complete the configuration you need to set up the cluster_id
%% option. The value of the cluster_id option is integer and should be in
%% range between 0 and 255.
%%
%% ```
%% epcap:start_link([{interface, "lo"}, {cluster_id, 2}]).
%% '''
%%
%% You can also specify the option cpu_affinity to set up CPU affinity for
%% epcap port:
%%
%% ```
%% epcap:start_link([{interface, "lo"}, {cluster_id, 2}, {cpu_affinity, "1,3,5-7"}]).
%% '''
%%
%% == PROCESS RESTRICTIONS ==
%%
%% Setting the `RESTRICT_PROCESS' environment variable controls which
%% mode of process restriction is used. The available modes are:
%% 
%% * seccomp: linux
%% 
%% * pledge: openbsd (default)
%% 
%% * capsicum: freebsd (default)
%% 
%% * rlimit: all (default: linux)
%% 
%% * null: all
%% 
%% For example, to force using the seccomp process restriction on linux:
%% 
%% ```
%% RESTRICT_PROCESS=rlimit rebar3 do clean, compile
%% '''
%% 
%% The `null' mode disables process restrictions and can be used for debugging.
%% 
%% ```
%% RESTRICT_PROCESS=null rebar3 do clean, compile
%% 
%% epcap:start([{exec, "sudo strace -f -s 4096 -o rlimit.trace"}, {filter, "port 9997"}]).
%% 
%% RESTRICT_PROCESS=seccomp rebar3 do clean, compile
%% 
%% epcap:start([{exec, "sudo strace -f -s 4096 -o seccomp.trace"}, {filter, "port 9997"}]).
%% '''
-module(epcap).

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, start_link/2, stop/1]).

-export([start/0, start/1, start/2]).

-export([send/2]).

-export([getopts/1]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-export_type([time_unit/0, options/0]).

-record(state, {pid :: pid(), port :: port()}).

-type time_unit() :: timestamp | microsecond.

%% @doc Start the epcap port process.
%% @see start_link/2
-spec start() -> ignore | {error, _} | {ok, pid()}.
start() -> start(self(), []).

%% @doc Start the epcap port process with options.
%% @see start_link/2
-spec start(options()) -> ignore | {error, _} | {ok, pid()}.
start(Options) -> start(self(), Options).

%% @doc Start the epcap port process with owner and options.
%% @see start_link/2
-spec start(pid(), options()) -> ignore | {error, _} | {ok, pid()}.
start(Pid, Options) when is_pid(Pid), is_list(Options) ->
    gen_server:start(?MODULE, [Pid, Options], []).

%% @doc Start and link with the epcap port process.
%% @see start_link/2
-spec start_link() -> ignore | {error, _} | {ok, pid()}.
start_link() -> start_link(self(), []).

%% @doc Start and link with the epcap port process.
%% @see start_link/2
-spec start_link(options()) -> ignore | {error, _} | {ok, pid()}.
start_link(Options) -> start_link(self(), Options).

%% @doc Start and link with the epcap port process.
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
%%
%% == Examples ==
%%
%% ```
%% 1> epcap:start([{filter, "icmp or (tcp and port 80)"},{interface, "eth0"}]).
%% {ok,<0.197.0>}
%% 2> flush().
%% Shell got {packet,1,
%%                   {1693,57279,417781},
%%                   98,
%%                   <<0,22,62,179,157,38,0,22,62,91,72,102,8,0,69,0,0,84,231,22,
%%                     64,0,64,1,130,73,100,115,92,198,8,8,8,8,8,0,164,231,23,
%%                     127,0,1,255,0,234,100,0,0,0,0,141,95,6,0,0,0,0,0,16,17,18,
%%                     19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,
%%                     38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55>>}
%% Shell got {packet,1,
%%                   {1693,57279,450447},
%%                   98,
%%                   <<0,22,62,91,72,102,0,22,62,179,157,38,8,0,69,0,0,84,0,0,0,
%%                     0,115,1,118,96,8,8,8,8,100,115,92,198,0,0,172,231,23,127,
%%                     0,1,255,0,234,100,0,0,0,0,141,95,6,0,0,0,0,0,16,17,18,19,
%%                     20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,
%%                     39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55>>}
%% ok
%% '''
-spec start_link(pid(), options()) -> ignore | {error, _} | {ok, pid()}.
start_link(Pid, Options) -> gen_server:start_link(?MODULE, [Pid, Options], []).

%% @doc Inject a packet on the network interface.
%%
%% To enable sending packets, start_link/1 must be called with the
%% `{inject, true}' option (default: `{inject, false}'). When disabled,
%% any data sent to the epcap port is silently discarded. Packet injection
%% failures are treated as fatal errors terminating the epcap port. Partial
%% writes are not considered to be errors and are ignored (an error message
%% will be printed to stderr if the verbose option is used).
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Port} = epcap:start([inject]).
%% {ok,<0.197.0>}
%% 2> {packet, _, _, _, Packet} = receive N -> N end.
%% {packet,1,
%%         {1693,58033,222196},
%%         74,
%%         <<0,22,62,179,157,38,0,22,62,91,72,102,8,0,69,0,0,60,205,
%%           40,64,0,64,6,...>>}
%% 3> epcap:send(Port, Packet).
%% ok
%% '''
-spec send(pid(), iodata()) -> ok.
send(Pid, Packet) when is_pid(Pid) ->
    case iolist_size(Packet) < 65535 of
        true -> gen_server:call(Pid, {send, Packet}, infinity);
        false -> erlang:error(badarg)
    end.

%% @doc Stop the epcap port.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Port} = epcap:start([{filter, "icmp or (tcp and port 80)"},{interface, "eth0"}]).
%% {ok,<0.205.0>}
%% 2> epcap:stop(Port).
%% ok
%% '''
-spec stop(pid()) -> ok.
stop(Pid) ->
    catch gen_server:call(Pid, stop),
    ok.

%% @private
init([Pid, Options0]) ->
    process_flag(trap_exit, true),
    Options = setopts(
        [
            {chroot, filename:join([basedir(), "tmp"])},
            {timeout, timeout()},
            {direction, inout}
        ],
        Options0
    ),
    ok = filelib:ensure_dir(
        filename:join(
            proplists:get_value(chroot, Options),
            "."
        )
    ),
    [Cmd | Argv] = getopts(Options),
    Port = open_port(
        {spawn_executable, Cmd},
        [{args, Argv}, {packet, 2}, binary, exit_status]
    ),
    % Block until the port has fully initialized
    receive
        {Port, {data, Data}} ->
            {epcap, ready} = binary_to_term(Data),
            {ok, #state{pid = Pid, port = Port}};
        {'EXIT', Port, normal} ->
            {stop, {error, port_init_failed}};
        {'EXIT', Port, Reason} ->
            {stop, {error, Reason}}
    end.

%% @private
handle_call({send, Packet}, _From, #state{port = Port} = State) ->
    Reply =
        try erlang:port_command(Port, Packet) of
            true -> ok
        catch
            error:badarg -> {error, closed}
        end,
    {reply, Reply, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

%% @private
terminate(_Reason, #state{port = Port}) ->
    catch erlang:port_close(Port),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%--------------------------------------------------------------------
%%% Port communication
%%--------------------------------------------------------------------

%% @private
handle_info({Port, {data, Data}}, #state{port = Port, pid = Pid} = State) ->
    Pid ! binary_to_term(Data),
    {noreply, State};
handle_info({'EXIT', Port, Reason}, #state{port = Port} = State) ->
    {stop, {shutdown, Reason}, State};
handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) ->
    case Status of
        0 -> {stop, normal, State};
        _ when 128 < Status -> {stop, {port_terminated, Status - 128}, State};
        _ -> {stop, {port_terminated, Status}, State}
    end;
handle_info(
    Info,
    %% WTF
    State
) ->
    error_logger:error_report([{wtf, Info}]),
    {noreply, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
-type arg_num() :: string() | non_neg_integer().

-type options() :: [
    inject
    | monitor
    | promiscuous
    | verbose
    | {buffer, arg_num()}
    | {chroot, string()}
    | {cluster_id, arg_num()}
    | {direction, in | out | inout}
    | {env, string()}
    | {exec, string()}
    | {file, string()}
    | {filter, string()}
    | {group, string()}
    | {interface, string()}
    | {progname, string()}
    | {snaplen, arg_num()}
    | {time_unit, time_unit()}
    | {timeout, arg_num() | infinity | immediate}
    | {user, string()}
    | {verbose, arg_num()}
].

-spec setopts(options(), options()) -> options().
setopts([], Options) ->
    proplists:compact(Options);
setopts([{Key, Val} | Rest], Options) ->
    case proplists:get_value(Key, Options) of
        undefined -> setopts(Rest, [{Key, Val} | Options]);
        _ -> setopts(Rest, Options)
    end.

%% @private
-spec getopts(options()) -> [string()].
getopts(Options) when is_list(Options) ->
    Exec = exec(Options),
    Progname = proplists:get_value(progname, Options, progname()),
    Cpu_affinity = cpu_affinity(Options),
    Filter = proplists:get_value(filter, Options, ""),
    Switches0 = lists:append([optarg(Opt) || Opt <- Options]),
    Switches = Switches0 ++ [Filter],
    [Cmd | Argv] = [
        N
     || N <- string:tokens(Exec, " ") ++ [Cpu_affinity, Progname | Switches],
        N /= ""
    ],
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
optarg({timeout, immediate}) -> switch("t", "0");
optarg({timeout, infinity}) -> switch("t", "-1");
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
        Dir ->
            Dir
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
