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
-module(epcap_worker).

-behaviour(gen_server).
%% API
-export([start_link/2, register_child_worker_Pid/2, stop/1, unregister_worker/2, unregister_child_worker_Pid/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {
	  pid_list :: [pid()], 
	  port :: port(),
	  instance::integer(),
          options::[tuple]
	 }).
-define(SERVER, ?MODULE).

unregister_worker(EPCAP_worker_Pid, Rule_worker_Pid) ->
    gen_server:call(Rule_worker_Pid, {unregister_process, EPCAP_worker_Pid}).	

start_link(Instance, Options)-> %% when is_integer(Instance) and is_list(InterfaceOptions) ->
    Instance_s = integer_to_list(Instance),
    Ref_s = erlang:ref_to_list(make_ref()),
    Fun = fun(ElementX,ElementY) -> (element(1,ElementX) > element(1,ElementY)) end,
    %% sort interface options alphabetically after insertion.
    OptionsSorted = lists:sort(Fun, Options),
						%Name_s = ?MODULE_STRING ++ "_" ++ Instance_s ++ "_" ++ Ref_s ++ lists:flatten(io_lib:format("~p", [OptionsSorted])),
    Name_s = ?MODULE_STRING ++ "_" ++ Instance_s ++ "_" ++ Ref_s ++ "_" ++ lists:flatten(io_lib:format("~p",[now()])) ++ lists:flatten(io_lib:format("~p", [OptionsSorted])),
    Name = list_to_atom (Name_s),
    error_logger:info_report("gen_server:start_link(~p)~n",[[{local, Name},?MODULE,[],[],self()]]),
    gen_server:start_link({local,Name},?MODULE,[Instance, OptionsSorted],[]).
						%gen_server:start_link(?MODULE,[Instance, OptionsSorted],[]).

register_child_worker_Pid(WorkerPid,ChildWorkerPid) ->
    gen_server:call(WorkerPid, {register_child_worker_Pid,  ChildWorkerPid}).

unregister_child_worker_Pid(WorkerPid,ChildWorkerPid) ->
    gen_server:call(WorkerPid, {unregister_child_worker_Pid,  ChildWorkerPid}).

stop(WorkerPid) ->
    gen_server:call(WorkerPid, stop_worker).
init([Instance, Options]) ->
    {ok, #state{instance = Instance, options = Options, pid_list = []}, 0}.

handle_call({register_child_worker_Pid, ChildWorkerPid}, _From, State) ->
    NewState = State#state{instance = State#state.instance+1, pid_list = [ChildWorkerPid|State#state.pid_list]},
    {reply, ok, NewState};
handle_call({unregister_child_worker_Pid,  ChildWorkerPid}, _From, State) ->
    Pid_list = lists:delete(ChildWorkerPid, State#state.pid_list),
    NewState = State#state{pid_list = Pid_list},
    Response = case Pid_list of 
		   [] ->
		       no_children_left; % child can be stopped
		   _NonEmptyLits ->
		       children_left     % still children left, child can not be stopped
	       end,     
    {reply, Response, NewState};
handle_call({unregister_process, EPCAP_worker_Pid}, _From, State) ->
    epcap_server:unregister_interface_by_pid(EPCAP_worker_Pid, self()),
    {reply, ok, State};
handle_call(stop_worker, _From, State) ->
    {stop, normal, ok, State};
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
handle_info({Port, {data, Data}}, #state{port = Port, pid_list = Pid_list} = State) ->
    %% send message to initial process and all further regsitered processes
    send_messages(Pid_list, Data), 
    {noreply, State};

handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) when Status > 128 ->
    {stop, {port_terminated, Status-128}, State};
handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) ->
    {stop, {port_terminated, Status}, #state{port = Port} = State};


handle_info({'EXIT', Port, Reason}, #state{port = Port} = State) ->
    {stop, {shutdown, Reason}, State};

handle_info(timeout, State) ->
    Options = State#state.options,
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
    io:format("~nOpen Port: ~p~n",[Cmd]),	
    Port = open_port({spawn, Cmd}, [{packet, 2}, binary, exit_status]),
    io:format("Port: ~p~n",[Port]),	
    {noreply, State#state{port = Port}};

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
get_switch({filter, Arg})       -> "\"" ++ Arg ++ "\"".

-spec basedir() -> string().
basedir() ->
    case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            filename:join([
			   filename:dirname(code:which(?MODULE)),
			   "../..", %% changed by mj
			   "priv" %,
			   %% ?MODULE commented out by mj
			  ]);
        Dir ->
            Dir
    end.

-spec progname() -> string().
progname() ->
    filename:join([basedir(), epcap]). %% commented out by mj: ?MODULE]).

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

-spec send_messages(list(),binary()) -> atom(). %% just a guess
send_messages([], _Data) ->
    ok;
send_messages([Pid|Pid_list], Data) ->
    Pid ! binary_to_term(Data),
    %%io:format("Sending message to PID_list~p, Pid~p~n",[[Pid|Pid_list],[Pid]]),
    send_messages(Pid_list, Data).



