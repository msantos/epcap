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

