
-module(parsertest).

-export([example/0]).

example() ->
    A = parser_combinator_bitstring:pBinarystring(<<"Michael">>),
    B = parser_combinator_bitstring:pBinarystring(<<"Andreas">>),
    C = parser_combinator_bitstring:pNot(B),
    E = parser_combinator_bitstring:pAnd([A, B]),
    F = parser_combinator_bitstring:pAnd([A, C]),
    G = parser_combinator_bitstring:pBetweenN(A, B,5),
    H = parser_combinator_bitstring:pHexCode(<<"41 6E 64 72 65 61 73">>),
    I = parser_combinator_bitstring:pBetweenN(A, H,5),
    J = parser_combinator_bitstring:pBetweenN(A, H,4),
    K = parser_combinator_bitstring:pIgnoreNChar(5),
    L = parser_combinator_bitstring:pBinarystringCaseInsensitive(<<"Andreas">>),
    M = parser_combinator_bitstring:pBinarystringCaseInsensitive(<<"Michael">>),
    io:format(" Test0: ~p~n",[parser_combinator_bitstring:parse(A,<<"Michael1234Andreas">>)]),
    io:format(" Test1: ~p~n",[parser_combinator_bitstring:parse(G,<<"Michael12345Andreas">>)]),
    io:format(" Test2: ~p~n",[parser_combinator_bitstring:parse(G,<<"Michael123456Andreas">>)]), 
    io:format(" Test3: ~p~n",[parser_combinator_bitstring:parse(G,<<"MichaelAAAAAAndreas">>)]),
    io:format(" Test4: ~p~n",[parser_combinator_bitstring:parse(G,<<"MichaelAAAAAndreas">>)]),
    io:format(" Test5: ~p~n",[parser_combinator_bitstring:parse(G,<<"Michael1234Andreas">>)]),
    io:format(" Test6: ~p~n",[parser_combinator_bitstring:parse(I,<<"MichaelAndreAndreas">>)]),
    io:format(" Test7: ~p~n",[parser_combinator_bitstring:parse(I,<<"MichaelAndAndreas">>)]),
    io:format(" Test8: ~p~n",[parser_combinator_bitstring:parse(H,<<"MichaelAndreAndreas">>)]),
    io:format(" Test9: ~p~n",[parser_combinator_bitstring:parse(H,<<"And">>)]),  
    io:format(" Test10: ~p~n",[parser_combinator_bitstring:parse(J,<<"MichaelAndreAndreas">>)]),
    io:format(" Test11: ~p~n",[parser_combinator_bitstring:parse(K,<<"1234">>)]),
    io:format(" Test12: ~p~n",[parser_combinator_bitstring:parse(K,<<"12345">>)]),
    io:format(" Test13: ~p~n",[parser_combinator_bitstring:parse(K,<<"123456">>)]),
    io:format(" Test14: ~p~n",[parser_combinator_bitstring:parse(L,<<"Andreas">>)]),
    io:format(" Test15: ~p~n",[parser_combinator_bitstring:parse(L,<<"ANDREAS">>)]),
    io:format(" Test16: ~p~n",[parser_combinator_bitstring:parse(L,<<"andreas">>)]),
    io:format(" Test17: ~p~n",[parser_combinator_bitstring:parse(M,<<"andreas">>)]).
