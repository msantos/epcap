%%%-------------------------------------------------------------------
%%% @author michael <michael@noname>
%%% @copyright (C) 2013, michael
%%% @doc
%%%
%%% @end
%%% Created :  1 Sep 2013 by michael <michael@noname>
%%%-------------------------------------------------------------------
-module(rule).

%% API
-export([start/1, stop/1]).

start(RuleOptionList) -> 
						% starts in the reverse order (epcap_server at last: Note epcap_server should always be the first tuple in RuleOptionList.)
    start(lists:reverse(RuleOptionList), [], undefined). % for epcap_server the ParentPid is undefined

start([], RolebackAccu, _ChildPid) ->
    {ok, RolebackAccu};

start([RuleElement|RuleElements], RolebackAccu, ChildWorkerPid)->
    {RuleName, RuleOptionList} = RuleElement,
    RuleServer = list_to_atom(atom_to_list(RuleName) ++ "_server"),
    case (RuleServer:rule_element_register(RuleOptionList, ChildWorkerPid, RuleElements)) of 
	%% RuleElements is in some cases helpful to decide, whether a new worker needs to bes started or an existing worker can be used.
	{ok, WorkerPid} -> 
	    io:format("Started rule server: ~p  with Pid: ~p~n", [RuleServer, WorkerPid]),
	    start(RuleElements, [{RuleServer, RuleOptionList, WorkerPid, ChildWorkerPid}|RolebackAccu], WorkerPid);
	{fail, FailReason} ->
	    io:format("Failed to start rule server: ~p with reason: ~p~n", [RuleServer, FailReason]),
						% stops in the reverse order (e.g. if started epcap_server, epcap_server at first)
	    ok = roleback(lists:reverse(RolebackAccu)), 
            failed
    end.			 

stop(RolebackAccu) ->
						% stops in the reverse order (epcap_server at first)
    roleback(lists:reverse(RolebackAccu)).

roleback([]) ->
    ok; % everithing has heen cleaned up

roleback([{RuleServer, RuleOptionList, WorkerPid, ChildWorkerPid}|RuleElements]) ->
    RuleServer:rule_element_unregister(WorkerPid, ChildWorkerPid, RuleOptionList),
    roleback(RuleElements).

