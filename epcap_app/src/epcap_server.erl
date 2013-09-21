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
-module(epcap_server).

-behaviour(gen_server).

%% API
-export([start_link/0, start_worker/1, stop_worker/1,  rule_element_register/3, 
	 rule_element_unregister/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {
	  instance::integer(),
	  package_worker_list::[tuple()]}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

start_worker(OptionTupleList) ->
    gen_server:call(?MODULE, {start_worker, OptionTupleList}).

stop_worker(WorkerPid) ->
    gen_server:call(?MODULE, {stop_worker, WorkerPid}).

rule_element_register(RuleOptionList, ChildWorkerPid, _RuleElements)->  
    case register_interface(RuleOptionList) of
	{registering, WorkerPid, _InterfaceOptionsSorted} ->
	    register_child_worker_Pid(WorkerPid, ChildWorkerPid),
	    Result = {ok, WorkerPid};
	{already_registered, WorkerPid, _InterfaceOptionsSorted} -> 
	    register_child_worker_Pid(WorkerPid, ChildWorkerPid),
	    Result = {ok, WorkerPid};
	FailReason ->
	    Result = {fail, FailReason}
    end, 
    Result.  

register_interface(OptionTupleList)->
    gen_server:call(?MODULE, {register_interface, OptionTupleList}).

register_child_worker_Pid(WorkerPid,ChildWorkerPid) ->
    epcap_worker:register_child_worker_Pid(WorkerPid,ChildWorkerPid).

rule_element_unregister(WorkerPid, ChildWorkerPid, RuleOptionList)->
    gen_server:call(?MODULE, {rule_element_unregister, WorkerPid, ChildWorkerPid, RuleOptionList}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    io:format("Ecap_server started\n"),
    {ok, #state{instance = 0, package_worker_list = []}}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_call({start_worker, Options}, _From, State) ->
    StateNew = #state{instance = State#state.instance + 1}, 	
    Reply = epcap_root_sup:start_worker(StateNew#state.instance, Options),
    {reply, Reply, StateNew};
handle_call({stop_worker, Pid}, _From, State) ->
    Reply = epcap_root_sup:stop_worker(Pid),
    {reply, Reply, State};
handle_call({register_interface, OptionTupleList}, _From, State) ->
    case get_package_worker_pid_by_interface_options(State#state.package_worker_list, OptionTupleList) of
	{not_found, InterfaceOptionsSorted} ->
	    {ok, WorkerPid} = epcap_root_sup:start_worker(State#state.instance, InterfaceOptionsSorted),
	    StateNew = State#state{instance = State#state.instance +1, package_worker_list = insert_element(State#state.package_worker_list, 						{OptionTupleList, WorkerPid})},
	    Reply = {registering, WorkerPid, InterfaceOptionsSorted};
	{found, WorkerPid, InterfaceOptionsSorted} ->
	    StateNew = State,
	    Reply = {already_registered, WorkerPid, InterfaceOptionsSorted};
	false ->
	    StateNew = State,
	    Reply = {server_options_not_found, ?SERVER, OptionTupleList}
    end,	
    {reply, Reply, StateNew};
handle_call({rule_element_unregister, WorkerPid, ChildWorkerPid, _RuleOptionList}, _From, State) ->
    Res = epcap_root_sup:stop_worker(WorkerPid, ChildWorkerPid),
    case Res of
	children_left ->
		StateNew = State, % do nothing.
		Reply = {unregistered_child_worker, WorkerPid};
	ok ->
		case remove_package_worker_by_pid(State#state.package_worker_list, WorkerPid) of 
			{not_found, WorkerPid} ->
	    			Reply = {error, not_registered, WorkerPid},
				StateNew = State;
			{found, WorkerPid, NewPackage_worker_list} ->
				Reply = {unregistered, WorkerPid},
				StateNew = State#state{package_worker_list = NewPackage_worker_list}
		end
    end, 
    {reply, Reply, StateNew};

handle_call({unregister_interface, WorkerPid, ChildWorkerPid}, _From, State) ->
    case remove_package_worker_by_pid(State#state.package_worker_list, WorkerPid) of
	{not_found, WorkerPid} ->
	    Reply = {not_registered, WorkerPid},
	    StateNew = State;
	{found, WorkerPid, NewPackage_worker_list} ->
	    Reply = epcap_root_sup:stop_worker(WorkerPid, ChildWorkerPid), % stops the worker only, when the last childworker is stopped.
	    StateNew = State#state{package_worker_list = NewPackage_worker_list}
    end,
    {reply, Reply, StateNew};
handle_call({register_rule, OptionTupleList, Rule_worker_module, RuleWorkerOptionList}, _From, State) ->
    case lists:keyfind(1,?SERVER, OptionTupleList) of
	{?SERVER, InterfaceOptions} -> 
	    case get_package_worker_pid_by_interface_options(State#state.package_worker_list, InterfaceOptions) of
		{not_found, InterfaceOptionsSorted} ->
		    {ok, EPCAP_WorkerPid} = epcap_root_sup:start_worker(State#state.instance, InterfaceOptionsSorted),
		    StateNew = State#state{instance = State#state.instance +1, package_worker_list = insert_element(State#state.package_worker_list, {InterfaceOptions, EPCAP_WorkerPid})},
		    {ok, Rule_WorkerPid} = epcap_worker:start_rule_worker(EPCAP_WorkerPid, Rule_worker_module, RuleWorkerOptionList),
		    Reply = {registering_rule, Rule_WorkerPid, InterfaceOptionsSorted, RuleWorkerOptionList};
		{found, EPCAP_WorkerPid, InterfaceOptionsSorted} ->
		    StateNew = State,
		    {ok, Rule_WorkerPid} = epcap_worker:start_rule_worker(EPCAP_WorkerPid, Rule_worker_module, RuleWorkerOptionList),
		    Reply = {registering_rule, Rule_WorkerPid, InterfaceOptionsSorted, RuleWorkerOptionList}	
	    end;	
	false ->
	    StateNew = State,
	    Reply = {server_options_not_found, ?SERVER, OptionTupleList}
    end,
    {reply, Reply, StateNew};

handle_call({unregister_rule_by_ID, {ModulePID, ModuleRuleID}}, _From, State) ->
    Reply = epcap_worker:stop_rule_worker(ModulePID, ModuleRuleID),
    StateNew = State,
    {reply, Reply, StateNew};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_package_worker_pid_by_interface_options(Package_worker_list, InterfaceOptions)->
    Fun = fun(ElementX,ElementY) -> (element(1,ElementX) > element(1,ElementY)) end,
    %% sort interface options alphabetically
    InterfaceOptionsSorted = lists:sort(Fun, InterfaceOptions),
    get_package_worker_pid_by_interface_options_sorted(Package_worker_list, InterfaceOptionsSorted).

get_package_worker_pid_by_interface_options_sorted([], InterfaceOptionsSorted)->
    {not_found, InterfaceOptionsSorted};
get_package_worker_pid_by_interface_options_sorted([{InterfaceOptionsSorted, Pid}|_Package_worker_elements], InterfaceOptionsSorted)->
    {found, Pid, InterfaceOptionsSorted};
get_package_worker_pid_by_interface_options_sorted([_Package_worker_element|Package_worker_elements], InterfaceOptionsSorted)->
    get_package_worker_pid_by_interface_options_sorted(Package_worker_elements, InterfaceOptionsSorted).

remove_package_worker_by_pid(Package_worker_list, Pid)->
    remove_package_worker_by_pid(Package_worker_list, [], Pid, not_found).

remove_package_worker_by_pid([], _Accum, Pid, not_found)->
    {not_found, Pid};		
remove_package_worker_by_pid([], Accum, Pid, found)->
    {found, Pid, lists:reverse(Accum)};
remove_package_worker_by_pid([{_PackageInterfaceOptions, SearchPid}|Package_worker_elements], Accum, SearchPid, _Found)->
    remove_package_worker_by_pid(Package_worker_elements, Accum, SearchPid, found);		
remove_package_worker_by_pid([Package_worker_element|Package_worker_elements], Accum, SearchPid, Found)->
    remove_package_worker_by_pid(Package_worker_elements, [Package_worker_element| Accum],SearchPid, Found).


insert_element(Package_worker_list, {InterfaceOptions, Pid})->
    Fun = fun(ElementX,ElementY) -> (element(1,ElementX) > element(1,ElementY)) end,
    %% sort interface options alphabetically
    InterfaceOptionsSorted = lists:sort(Fun, InterfaceOptions),
    Package_worker_listNew = [{InterfaceOptionsSorted, Pid}|Package_worker_list],
    Package_worker_listNew. 


