-module(s4).

%% API
-export([s/0]).
s()->
    application:start(sasl),
    Res = application:start(epcap),
    io:format("epcap_app started Res: ~p~n",[Res]),	
    Res1 = application:start(content),
    io:format("content started Res: ~p~n",[Res1]),	
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

    Result1 = rule:start([{epcap,[{interface, "eth0"}]}, {content, [{matchfun, MatchFun1}, {message, "Found: www.heise.de*Meldung*"}]}]),	
    io:format("Result: ~p~n",[Result1]),
    start(1000).

start(0)->
	ok;

start(Number) ->
    %% just simulate to create load
    MatchFunNeverMatch = fun(_Payload) -> fail end,
    Result1 = rule:start([{epcap,[{interface, "eth0"}]}, {content, [{matchfun, MatchFunNeverMatch}, {message, "Found: www.heise.de*Meldung*"}]}]),	
    io:format("Result: ~p~n",[Result1]),
    start(Number-1).


