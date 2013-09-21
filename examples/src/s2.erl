-module(s2).

%% API
-export([s/0]).
s()->
    %% test case:
    %% start 2 rules
    %% stop 2 rules 

    application:start(sasl),
    Res_epcap_start = application:start(epcap),
    io:format("epcap_app started Res: ~p~n",[Res_epcap_start]),	
    Res_content_start = application:start(content),
    io:format("content_app started Res: ~p~n",[Res_content_start]),	
    %% traces for testing
    %%dbg:tracer(),
    %%dbg:p(all,c),
    %%dbg:tpl(epcap_server, x),
    %%dbg:tpl(content_server, x),
    %%dbg:tpl(epcap_root_sup, x),
    %%dbg:tpl(content_root_sup, x),	
    %%dbg:tpl(echo_server, x),
    %%dbg:tpl(supervisor, x),
    %%dbg:p(new, m),
    %%dbg:p(new, p),
    MatchFun1 = fun(Payload) -> 
			A = parser_combinator_bitstring:pBinarystring(<<"www.heise.de">>),
			B = parser_combinator_bitstring:pUntilN( A, 100 ),
			C = parser_combinator_bitstring:pBinarystringCaseInsensitive(<<"MELDUNG">>),
			E = parser_combinator_bitstring:pBetweenN(B, C,14),
			parser_combinator_bitstring:parse(E,Payload) end,

    {ok, Result1} = rule:start([{epcap,[{interface, "eth0"}]}, {content, [{matchfun, MatchFun1}, {message, "Found: www.heise.de*Meldung*"}]}]),
    io:format("Start result 1: ~p~n",[Result1]),
    MatchFun2 = fun(Payload) -> 
			A = parser_combinator_bitstring:pBinarystring(<<"www.heise.de">>),
			B = parser_combinator_bitstring:pUntilN( A, 100 ),
			C = parser_combinator_bitstring:pBinarystringCaseInsensitive(<<"thema">>),
			E = parser_combinator_bitstring:pBetweenN(B, C,14),
			parser_combinator_bitstring:parse(E,Payload) end,
    {ok, Result2} = rule:start([{epcap,[{interface, "eth0"}]}, {content, [{matchfun, MatchFun2}, {message, "Found: www.heise.de*Thema*"}]}]),
    io:format("Start result 2: ~p~n",[Result2]),
    StopResult1 = rule:stop(Result1),
    io:format("Stop result 1: ~p~n",[StopResult1]),
    StopResult2 = rule:stop(Result2),
    io:format("Stop result 2: ~p~n",[StopResult2]),
    Res_epcap_stop = application:stop(epcap),
    io:format("epcap_app stop Res: ~p~n",[Res_epcap_stop]),	
    Res_content_stop = application:stop(content),
    io:format("content_app stop Res: ~p~n",[Res_content_stop]).


