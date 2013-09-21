%%---------------------------------------------------------------------
%% FILE:              parser.erl
%% DESCRIPTION:       Parser functions
%% DATE:              08/21/2001
%% LANGUAGE PLATFORM: Erlang 5.0.1.1
%% OS PLATFORM:       RedHat Linux 7.0
%% AUTHOR:            Jeffrey A. Meunier
%% EMAIL:             jeffm@cse.uconn.edu
%%---------------------------------------------------------------------

%% This module is based on the Haskell Parsec parser library written
%% by Erik Meijer.

%% This module has been modified by M. Josenhans
%%
%% changed from working with Lists / Strings to working with Bitstrings
%% After conversion from Lists / Strings to working with Bitstrings not all functions have been tested!!!!
%% Feel free to fix bugs, if there should be any.

-module( parser_combinator_bitstring ).

%% important functions
-export( [ parse/2
         ] ).

%% parsers
-export( [ pAlphaNum/1
	   , pAnd/1
	   , pAWord/1
	   , pBetween/2
	   , pBetweenN/3
	   , pCapWord/1
	   , pChar/1
	   , pDebug/1
	   , pDigit/1
	   , pHexCode/1
	   , pEoi/1
	   , pEol/1
	   , pIgnoreNChar/1
	   , pList/4            %% begin, element, separator, end
	   , pLower/1
	   , pMany/1
	   , pMany1/1
	   , pMaybe/1
	   , pNewline/1
	   , pNonCapWord/1
	   , pNot/1
	   , pNotFollowedBy/2
	   , pOr/1
	   , pSat/1
	   , pSkipMany/1
	   , pSpace/1
	   , pSpaces/1
	   , pSpaces1/1
	   , pBinarystring/1
	   , pBinarystringCaseInsensitive/1
	   , pTheWord/1
	   , pThen/2
	   , pUntil/1
           , pUntilN/2
	   , pUpper/1
	   , pWhile/1
	   , pWordSep/1
         ] ).

%% predicates
-export( [ isAlpha/1
	   , isAlphaNum/1
	   , isDigit/1
	   , isHexDigit/1
	   , isLower/1
	   , isNl/1
	   %%         , isPunct/1
	   , isSpace/1
	   , isUpper/1
	   , isWordSep/1
         ] ).

%% test exports
-export( [ scan/3
         ] ).




binary_revers(L) ->
    binary_revers(L, <<>>).

binary_revers(<<H:8, T/binary>>, L) ->
    binary_revers(T, <<H:8, L/binary>>);
binary_revers(<<>>, L) ->
    L.

%%---------------------------------------------------------------------
%% Top-level parsing function.
%%---------------------------------------------------------------------
parse( Parser, Inp )
-> Parser( Inp )
       .



%%---------------------------------------------------------------------
%% Display a debug message.
%%---------------------------------------------------------------------
pDebug( Binarystring )
-> fun( _Inp )
      -> io:format( binary_to_list(Binarystring) )
	     , fail
   end
       .



%%=====================================================================
%% Higher-level data structure parsers.
%%=====================================================================

%%---------------------------------------------------------------------
%% Parse a list of elements.
%%---------------------------------------------------------------------
pList( PBegin, PElem, PSep, PEnd )
-> fun( Inp )
      -> Result = parse( pAnd( [ fun pSpaces/1
				 , PBegin
				 , pMaybe( pAnd( [ fun pSpaces/1
						   , PElem
						   , pMany( pAnd( [ fun pSpaces/1
								    , PSep
								    , fun pSpaces/1
								    , PElem
								  ] ) )
						 ] ) )
				 , fun pSpaces/1
				 , PEnd
			       ] ), Inp )
	     , case Result of
		   fail
		   -> fail
			  ;
		   {[_, _, List, _, _], Rest}
		   -> StripElem
			  = fun( [_, _, _, Elem] ) -> Elem end
			  , case List of
				[]
				-> {[], Rest}
				       ;
				[[_, Elem, Elems] | _]
				-> {[Elem | lists:map( StripElem, Elems )], Rest}
			    end
	       end
   end
       .

%% test expressions for pList
%% O=parser:pChar($[),C=parser:pChar($]),S=parser:pChar($,),A=parser:pChar($A).
%% (parser:pList(O,A,S,C))(" [ A, A, A] ").


%%=====================================================================
%% Special parsers.
%%=====================================================================

%%---------------------------------------------------------------------
%% Check for end of input.
%%---------------------------------------------------------------------
pEoi( <<>> )
-> {eoi, <<>>}
       ;
pEoi( _ )
-> fail
       .



%%---------------------------------------------------------------------
%% Check for end of line.  EOL is either a newline or EOI.
%%---------------------------------------------------------------------
pEol( <<>> )
-> {eol, <<>>}
       ;
pEol( <<C:8, Cs/binary>> )
-> case isNl( C ) of
       true
       -> {C, Cs}
	      ;
       false
       -> fail
   end
       ;
pEol( _ )
-> fail
       .

%%=====================================================================
%% Parser combinators.
%%=====================================================================

%%---------------------------------------------------------------------
%% Return input between elements parsed by P1 and P2.
%%---------------------------------------------------------------------
pBetween( P1, P2 )
-> fun( Inp )
      -> Result = parse( pThen( P1, pUntil( P2 ) ), Inp )
	     , case Result of
		   {[_, {Betw, _}], Rest}
		   -> {Betw, Rest}
			  ;
		   _ -> fail
	       end
   end
       .

%%---------------------------------------------------------------------
%% Return input between elements parsed by P1 and P2.
%%---------------------------------------------------------------------
pBetweenN( P1, P2, N )
-> fun( Inp )
      -> Result = parse( pThen( P1, pUntilN( P2, N ) ), Inp )
	     , case Result of
		   {[_, {Betw, _}], Rest}
		   -> {Betw, Rest}
			  ;
		   _ -> fail
	       end
   end
       .


%%---------------------------------------------------------------------
%% Parse 0 or 1 element.
%%---------------------------------------------------------------------
pMaybe( P )
-> fun( Inp )
      -> case P( Inp ) of
	     fail
	     -> {<<>>, Inp}
		    ;
	     {Result, InpRem}
	     -> {[Result], InpRem}
	 end
   end
       .



%%---------------------------------------------------------------------
%% Parser success inverter.
%%---------------------------------------------------------------------
pNot( P )
-> fun( Inp )
      -> case P( Inp ) of
	     fail
	     -> {ok, Inp}
		    ;
	     _ -> fail
	 end
   end
       .



%%---------------------------------------------------------------------
%% Succeed if P2 does not follow P1.
%%---------------------------------------------------------------------
pNotFollowedBy( P1, P2 )
-> fun( Inp )
      -> case P1( Inp ) of
	     fail
	     -> fail
		    ;
	     {Result, InpRem}
	     -> case P2( InpRem ) of
		    fail
		    -> {Result, InpRem}
			   ;
		    _ -> fail
		end
	 end
   end
       .


%%---------------------------------------------------------------------
%% Succeed if all parsers succeed.  This can be used as a
%% sequencing parser.
%%---------------------------------------------------------------------
pAnd( Parsers )
-> fun( Inp )
      -> all( Parsers, Inp, [] )
   end
       .

all( [], Inp, Accum )
-> {lists:reverse( Accum ), Inp}
       ;
all( [P | Parsers], Inp, Accum )
-> case P( Inp ) of
       fail
       -> fail
	      ;
       {Result, InpRem}
       -> all( Parsers, InpRem, [Result | Accum ] )
   end
       .



%%---------------------------------------------------------------------
%% Succeed if P1 and P2 succeed.
%%---------------------------------------------------------------------
pThen( P1, P2 )
-> fun( Inp )
      -> case P1( Inp ) of
	     {Result1, InpRem1}
	     -> case P2( InpRem1 ) of
		    {Result2, InpRem2}
		    -> {[Result1, Result2], InpRem2}
			   ;
		    fail
		    -> fail
		end
		    ;
	     fail
	     -> fail            
	 end
   end
       .



%%---------------------------------------------------------------------
%% Succeed when one of a list of parsers succeeds.
%%---------------------------------------------------------------------
pOr( Parsers )
-> fun( Inp )
      -> try_( Parsers, Inp )
   end
       .

try_( [], _Inp )
-> fail
       ;
try_( [ P | Parsers ], Inp )
-> case P( Inp ) of
       fail
       -> try_( Parsers, Inp )
	      ;
       Result
       -> Result
   end
       .



%%---------------------------------------------------------------------
%% Parse 0 or more elements.
%%---------------------------------------------------------------------
pMany( P )
-> fun( Inp )
      -> scan( P, Inp, <<>> )
   end
       .



%%---------------------------------------------------------------------
%% Parse 1 or more elements.
%%---------------------------------------------------------------------
pMany1( P )
-> fun( Inp )
      -> Result = scan( P, Inp, <<>> )
	     , case Result of
		   {[_ | _], _}
		   -> Result
			  ;
		   _ -> fail
	       end
   end
       .

%%---------------------------------------------------------------------
%% Skip over 0 or more elements
%%---------------------------------------------------------------------
pSkipMany( P )
-> fun( Inp )
      -> {_, InpRem} = scan( P, Inp, <<>> )
	     , {ok, InpRem}
   end
       .

scan( _, <<>>, Accum )
-> {binary_revers( Accum ), <<>>}
       ;
scan( P, Inp, Accum )
-> case P( Inp ) of
       fail
       -> {binary_revers( Accum ), Inp}
	      ;
       {Result, InpRem}
       -> scan( P, InpRem, <<Result:8, Accum/binary>> )
   end
       .
%%---------------------------------------------------------------------
%% Parse input until parser succeeds.  Do not remove successful
%% element from input stream.
%%---------------------------------------------------------------------
pUntil( P )
-> fun( Inp )
      -> until( P, Inp, <<>> )
   end
       .

until( P, Inp, Accum )
-> case P( Inp ) of
       fail
       -> case Inp of
              <<C:8, Cs/binary>>
	      -> until( P, Cs, <<C:8, Accum>> )
		     ;
              %% delaying test for empty list until here allows a parser
              %% to check for empty input (pEof)
              <<>>
	      -> fail
	  end
	      ;
       {Result, InpRem}
       -> {{binary_revers( Accum ), Result}, InpRem}
   end
       .

%%---------------------------------------------------------------------
%% Parse input until parser succeeds.  Do not remove successful
%% element from input stream.
%%---------------------------------------------------------------------
pUntilN( P, N )
-> fun( Inp )
      -> untilN( P, N, Inp, <<>> )
   end
       .
untilN( P, 0, Inp, Accum )
-> case P( Inp ) of
       fail -> fail;
       {Result, InpRem}
       -> {{binary_revers( Accum ), Result}, InpRem}
   end;

untilN( P, N, Inp, Accum )
-> case P( Inp ) of
       fail
       -> case Inp of
              <<C:8, Cs/binary>>
	      -> untilN( P, N-1, Cs, <<C:8, Accum/binary>> )
		     ;
              %% delaying test for empty list until here allows a parser
              %% to check for empty input (pEof)
              <<>>
	      -> fail
	  end
	      ;
       {Result, InpRem}
       -> {{binary_revers( Accum ), Result}, InpRem}
   end
       .

%%---------------------------------------------------------------------
%% Parse input while parser succeeds.
%%---------------------------------------------------------------------
pWhile( P )
-> fun( Inp )
      -> while( P, Inp, <<>> )
   end
       .

while( _, <<>>, _ )
-> fail
       ;
while( P, Inp = <<_C:8, Cs/binary>>, Accum )
-> case P( Inp ) of
       {Result, _InpRem}
       -> while( P, Cs, <<Result:8, Accum/binary>> )
	      ;
       fail
       -> {binary_revers( Accum ), Inp}
   end
       .



%%=====================================================================
%% Binarystring parsers.
%%=====================================================================

%%---------------------------------------------------------------------
%% Consume any number of spaces.
%%---------------------------------------------------------------------
pSpaces( Inp )
-> (pMany( fun pSpace/1 ))( Inp )
       .



%%---------------------------------------------------------------------
%% Consume at least 1 space.
%%---------------------------------------------------------------------
pSpaces1( Inp )
-> (pMany1( fun pSpace/1 ))( Inp )
       .




%%---------------------------------------------------------------------
%% Ignore N characters.
%%---------------------------------------------------------------------
pIgnoreNChar( N ) -> 
    fun( Inp ) -> 
	    ignoreNChar( N, Inp, <<>> )
    end.

ignoreNChar( 0, Binarystring, Accum ) -> 
    {binary_revers( Accum ), Binarystring};
ignoreNChar( N, <<C2:8, C2s/binary>>, Accum ) ->
    ignoreNChar( N-1, C2s, <<C2:8, Accum/binary>> );
ignoreNChar( _, _, _ ) -> 
    fail.

						%---------------------------------------------------------------------
						% Match a specific Binarystring.
						%---------------------------------------------------------------------
pBinarystring( S )
-> fun( Inp )
      -> match( S, Inp, <<>> )
   end
       .

match( <<>>, Binarystring, Accum )
-> {binary_revers( Accum ), Binarystring}
       ;
match( <<C1:8, C1s/binary>>, <<C2:8, C2s/binary>>, Accum ) when C1 == C2
								-> match( C1s, C2s, <<C1:8,  Accum/binary>> )
								       ;
match( _, _, _ )
-> fail
       .
						%---------------------------------------------------------------------
						% Match a case  insensitive Binarystring.
						%---------------------------------------------------------------------
pBinarystringCaseInsensitive( S ) ->
    fun( Inp ) -> 
	    matchCaseInsensitive( S, Inp, <<>> )
    end.

matchCaseInsensitive( <<>>, Binarystring, Accum ) -> 
    {binary_revers( Accum ), Binarystring};
matchCaseInsensitive( <<C1:8, C1s/binary>>, <<C2:8, C2s/binary>>, Accum ) when C1 == C2 -> 
    matchCaseInsensitive( C1s, C2s, <<C1:8, Accum/binary>> );
matchCaseInsensitive( <<C1:8, C1s/binary>>, <<C2:8, C2s/binary>>, Accum ) when C1 >= $A , C1 =< $Z , C2 >= $a , C2 =< $z , (C1 -$A) == (C2 -$a) -> 
    matchCaseInsensitive( C1s, C2s, <<C1:8, Accum/binary>> );
matchCaseInsensitive( <<C1:8, C1s/binary>>, <<C2:8, C2s/binary>>, Accum ) when C1 >= $a , C1 =< $z , C2 >= $A , C2 =< $Z , (C1 -$a) == (C2 -$A) -> 
    matchCaseInsensitive( C1s, C2s, <<C1:8, Accum/binary>> );

matchCaseInsensitive( _, _, _ ) -> 
    fail.

%%---------------------------------------------------------------------
%% Parse a capitalized (first letter) word.
%%---------------------------------------------------------------------
pCapWord( Inp )
-> Result = (pAnd( [ fun pUpper/1
                     , fun pAWord/1
		   ] ))( Inp )
       , case Result of
	     {[Cap, Word], Rest}
	     -> {[Cap | Word], Rest}
		    ;
	     fail
	     -> fail
	 end
       .



%%---------------------------------------------------------------------
%% Parse a non-capitalized (first letter) word.
%%---------------------------------------------------------------------
pNonCapWord( Inp )
-> Result = (pAnd( [ fun pLower/1
                     , fun pAWord/1
		   ] ))( Inp )
       , case Result of
	     {[Cap, Word], Rest}
	     -> {[Cap | Word], Rest}
		    ;
	     fail
	     -> fail
	 end
       .




%%---------------------------------------------------------------------
%% Parse an upper-case-only word.
%%---------------------------------------------------------------------
%%pUCWord( Inp )

%%---------------------------------------------------------------------
%% Parse a lower-case-only word.
%%---------------------------------------------------------------------
%%pLCWord( Inp )



%%---------------------------------------------------------------------
%% Get the next word from the input.
%%---------------------------------------------------------------------
pAWord( Inp )
-> Result = parse( pUntil( fun pWordSep/1 ), Inp )
       , case Result of
	     fail
	     -> fail
		    ;
	     {{Word, Sep}, Rest}
	     -> {Word, [Sep | Rest]}
	 end
       .



%%---------------------------------------------------------------------
%% Get a specific word from the input.
%%---------------------------------------------------------------------
pTheWord( W )
-> fun( Inp )
      -> Result = pAWord( Inp )
	     , case Result of
		   {W, _Rest}
		   -> Result
			  ;
		   _ -> fail
	       end
   end
       .



%%=====================================================================
%% Character parsers.
%%=====================================================================

%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pChar( C )
-> pSat( fun( C1 ) -> C1 == C end )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pDigit( Inp )
-> (pSat( fun isDigit/1 ))( Inp )
       .

%%---------------------------------------------------------------------
%% Match a specific Binarystring.
%%---------------------------------------------------------------------
pHexCode( HexSequence )
-> fun( Inp )
      -> matchhex( HexSequence, Inp, <<>> )
   end
       .

matchhex( <<>>, Binarystring, Accum )
-> {binary_revers( Accum ), Binarystring}
       ;
matchhex( <<HexCharHigh:8, HexChars/binary>>, Binarystring, Accum ) -> 
    matchhex( HexCharHigh, HexChars, Binarystring, Accum );

matchhex( _, _, _ ) -> 
    fail.

matchhex(HexCharHigh, <<HexCharLow:8, HexChars/binary>>, <<C2:8, C2s/binary>>, Accum ) ->
    HexValueHigh = hexChar2value(HexCharHigh),
    HexValueLow = hexChar2value(HexCharLow),
    HexValue = HexValueHigh * 16 + HexValueLow,
    case (HexValue == C2) of
	true ->
	    matchspace( HexChars, C2s, <<C2:8, Accum/binary>> );
	false ->
	    fail
    end;
matchhex(_, _, <<>>,_) ->
    fail.

matchspace( <<C1:8, C1s/binary>>, Binarystring, Accum ) when C1 == 32 ->
    matchhex( C1s, Binarystring, Accum );

matchspace( <<>>, Binarystring, Accum ) -> 
    {binary_revers( Accum ), Binarystring}.


hexChar2value(HexChar) when (HexChar >= $0) , (HexChar =< $9) ->
    (HexChar - $0);
hexChar2value(HexChar) when (HexChar >= $a) , (HexChar =< $f) ->
    (HexChar - $a + 10);
hexChar2value(HexChar) when (HexChar >= $A) , (HexChar =< $F) ->
    (HexChar - $A + 10).

%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pLower( Inp )
-> (pSat( fun isLower/1 ))( Inp )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pNewline( Inp )
-> (pChar( $\n ))( Inp )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pSpace( Inp )
-> (pSat( fun isSpace/1 ))( Inp )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pUpper( Inp )
-> (pSat( fun isUpper/1 ))( Inp )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pWordSep( Inp )
-> (pOr( [ pSat( fun isWordSep/1 )
           , fun pEoi/1
	 ] ))( Inp )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
pAlphaNum( Inp )
-> (pSat( fun isAlphaNum/1))( Inp )
       .



%%---------------------------------------------------------------------
%% Primitive character predicate satisfier.
%%---------------------------------------------------------------------
pSat( Pred )
-> fun( <<>> )
      -> fail
	     ;
      ( <<C:8, Cs>> )
      -> case Pred( C ) of
	     true
	     -> {C, Cs}
		    ;
	     false
	     -> fail
	 end
   end
       .



%%=====================================================================
%% Various predicates.
%%=====================================================================

%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isAlpha( <<C>> )
-> case isLower( C ) of
       true
       -> true
	      ;
       false
       -> isUpper( C )
   end
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isAlphaNum( <<C>> )
-> case isAlpha( C ) of
       true
       -> true
	      ;
       false
       -> isDigit( C )
   end
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isDigit( <<C>> ) when $0 =< C, C =< $9
		      -> true
			     ;
isDigit( <<_C>> )
-> false
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isHexDigit( <<C>> ) when $0 =< C, C =< $9; $A =< C, C =< $F; $a =< C, C =< $f
			 -> true
				;
isHexDigit( <<_C>> )
-> false
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isLower( <<C>> ) when $a =< C, C =< $z
		      -> true
			     ;
isLower( <<_C>> )
-> false
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isNl( <<C>> )
-> C == $\n
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isWordSep( <<C>> )
-> case isSpace( C ) of
       true
       -> true
	      ;
       false
       -> lists:member( C, ",.:;-+*|=()[]{}" )
   end
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isSpace( <<C>> )
-> lists:member( C, " \t\n\r" )
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
isUpper( <<C>> ) when $A =< C, C =< $Z
		      -> true
			     ;
isUpper( <<_C>> )
-> false
       .



%%---------------------------------------------------------------------
%% 
%%---------------------------------------------------------------------
%% isWordSep( C )
%%   -> case isSpace( C ) of
%%        true
%%          -> true
%%           ;
%%        false
%%          -> isPunct( C )
%%      end
%%    .



%%---------------------------------------------------------------------
%% eof
%%---------------------------------------------------------------------
