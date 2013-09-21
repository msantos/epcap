%%%-------------------------------------------------------------------
%%% @author michael <michael@noname>
%%% @copyright (C) 2013, michael
%%% @doc
%%%
%%% @end
%%% Created :  1 Sep 2013 by michael <michael@noname>
%%%-------------------------------------------------------------------
-module(content_server).

-behaviour(gen_server).

%% API
-export([rule_element_register/3,start_link/0, start_worker/2, stop_worker/1, rule_element_unregister/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-record(state, {
	  instance::integer(),
	  content_worker_list::[tuple()],
	  rule_elements::[tuple]
	 }).

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

start_worker(OptionTupleList, RuleElements) ->
    gen_server:call(?MODULE, {start_worker, OptionTupleList, RuleElements}).

stop_worker(WorkerPid) ->
    gen_server:call(?MODULE, {stop_worker, WorkerPid}).

rule_element_register(OptionTupleList, undefined, RuleElements) ->
    Res = start_worker(OptionTupleList, RuleElements), 
    case  Res of
	{ok, Pid} ->
	    {ok, Pid};
	{ok, Pid, Term} ->
	    {ok, Pid, Term};
	{FailReason, _Pid} ->
	    {fail, FailReason};
	FailReason ->
	    {fail, FailReason}
    end.

rule_element_unregister(WorkerPid, _ChildWorkerPid, _RuleOptionList) ->
    stop_worker(WorkerPid).

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
    io:format("Content_server started\n"),
    {ok, #state{instance = 0, content_worker_list = []}}.

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
handle_call({start_worker, OptionTupleList, RuleElements}, _From, State) ->
    StateNew = #state{instance = State#state.instance + 1, rule_elements = RuleElements}, 
    %% rule elements is for future use. For now it is just stored and every time a new process started.
    Reply = content_root_sup:start_worker(StateNew#state.instance, OptionTupleList),
    io:format("Content worker started with Result:~p~n", [Reply]),
    {reply, Reply, StateNew};
handle_call({stop_worker, Pid}, _From, State) ->
    Reply = content_root_sup:stop_worker(Pid),
    {reply, Reply, State};
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
