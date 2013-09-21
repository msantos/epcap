-module(epcap_root_sup).

-behaviour(supervisor).
%% API
-export([start_link/0, start_worker/2, stop_worker/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_worker(Instance, Options) ->
    Instance_s = integer_to_list(Instance),
    Ref_s = erlang:ref_to_list(make_ref()),                       
    %% Ref_s makes the instance unique after restart
    %% as instance starts again at 0
    Name_s = ?MODULE_STRING ++ "_" ++ Instance_s ++ "_" ++ Ref_s,  
    Name = list_to_atom (Name_s),
    %% the name must be a unique atom
    EPCAP_worker = {Name, {epcap_worker, start_link, [Instance, Options]},
		    temporary, 2000, worker, [epcap_worker]},
    {ok, Result} = supervisor:start_child(?SERVER, EPCAP_worker),
    io:format("Supervisor ~p start result: ~p~n", [?SERVER, Result]), 
    {ok, Result}.

stop_worker(WorkerPid, ChildWorkerPid) ->
						%Result = supervisor:terminate_child(?SERVER, WorkerPid), 
						%io:format("Supervisor stopping Pid ~p with result~p~n", [WorkerPid, Result]), 
						%Result.
    Res = epcap_worker:unregister_child_worker_Pid(WorkerPid,ChildWorkerPid),
    case Res of
	no_children_left ->
	    epcap_worker:stop(WorkerPid);
	children_left ->
	    children_left % do nothing
    end.
						%gen_server:call(WorkerPid, stop_worker).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 10,
    MaxSecondsBetweenRestarts = 60,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    EPCAP_server = {{local, epcap_server}, {epcap_server, start_link, []},
		    permanent, 2000, worker, [epcap_server]},
    %%EPCAP_worker = {epcap_worker,{epcap_worker, start_link, []},
    %%			  temporary, 2000, worker, [epcap_worker]},
    {ok, {SupFlags, [EPCAP_server]}}. %%, EPCAP_worker]}}.
%%%===================================================================
%%% Internal functions
%%%===================================================================
