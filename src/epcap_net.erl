%% Copyright (c) 2009, Michael Santos <michael.santos@gmail.com>
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
-module(epcap_net).

-include("epcap_net.hrl").

-define(ETHERHDRLEN, 16).
-define(IPV4HDRLEN, 20).
-define(IPV6HDRLEN, 40).
-define(TCPHDRLEN, 20).
-define(UDPHDRLEN, 8).
-define(ICMPHDRLEN, 8).

-export([
        checksum/1,
        decapsulate/1,
        makesum/1,
        valid/1,
        ether/1,
        ether_addr/1,
        ether_type/1,
        icmp/1,
        ipv4/1,
        ipv6/1,
        payload/1,
        proto/1,
        tcp/1,
        tcp_flags/1,
        udp/1
]).

-define(is_print(C), C >= $ , C =< $~).


decapsulate(Data) ->
    decapsulate({ether, Data}, []).

decapsulate(stop, Packet) ->
    lists:reverse(Packet);
decapsulate({unsupported, Data}, Packet) ->
    decapsulate(stop, [{unsupported, Data}|Packet]);
decapsulate({ether, Data}, Packet) when byte_size(Data) >= ?ETHERHDRLEN ->
    {Hdr, Payload} = ether(Data),
    decapsulate({ether_type(Hdr#ether.type), Payload}, [Hdr|Packet]);
decapsulate({ipv4, Data}, Packet) when byte_size(Data) >= ?IPV4HDRLEN ->
    {Hdr, Payload} = ipv4(Data),
    decapsulate({proto(Hdr#ipv4.p), Payload}, [Hdr|Packet]);
decapsulate({ipv6, Data}, Packet) when byte_size(Data) >= ?IPV6HDRLEN ->
    {Hdr, Payload} = ipv6(Data),
    decapsulate({proto(Hdr#ipv6.next), Payload}, [Hdr|Packet]);
decapsulate({tcp, Data}, Packet) when byte_size(Data) >= ?TCPHDRLEN ->
    {Hdr, Payload} = tcp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({udp, Data}, Packet) when byte_size(Data) >= ?UDPHDRLEN ->
    {Hdr, Payload} = udp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({icmp, Data}, Packet) when byte_size(Data) >= ?ICMPHDRLEN ->
    {Hdr, Payload} = icmp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({_, Data}, Packet) ->
    decapsulate(stop, [{truncated, Data}|Packet]).

ether_type(?ETH_P_IP) -> ipv4;
ether_type(?ETH_P_IPV6) -> ipv6;
ether_type(_) -> unsupported.

proto(?IPPROTO_ICMP) -> icmp;
proto(?IPPROTO_TCP) -> tcp;
proto(?IPPROTO_UDP) -> udp;
proto(_) -> unsupported.


%%
%% Ethernet
%%
ether(<<Dhost:6/bytes, Shost:6/bytes, Type:16, Payload/binary>>) ->
%    Len = byte_size(Packet) - 4,
%    <<Payload:Len/bytes, CRC:4/bytes>> = Packet,
    {#ether{
       dhost = Dhost, shost = Shost,
       type = Type
      }, Payload};
ether(#ether{
       dhost = Dhost, shost = Shost,
       type = Type
      }) ->
    <<Dhost:6/bytes, Shost:6/bytes, Type:16>>.


%%
%% IPv4
%%
ipv4(
    <<4:4, HL:4, ToS:8, Len:16,
    Id:16, 0:1, DF:1, MF:1, %% RFC791 states it's a MUST
    Off:13, TTL:8, P:8, Sum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8,
    Payload/binary>>
) ->
    {#ipv4{
        hl = HL, tos = ToS, len = Len,
        id = Id, df = DF, mf = MF,
        off = Off, ttl = TTL, p = P, sum = Sum,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    }, Payload};
ipv4(#ipv4{
        hl = HL, tos = ToS, len = Len,
        id = Id, df = DF, mf = MF,
        off = Off, ttl = TTL, p = P, sum = Sum,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    }) ->
    <<4:4, HL:4, ToS:8, Len:16,
    Id:16, 0:1, DF:1, MF:1, %% RFC791 states it's a MUST
    Off:13, TTL:8, P:8, Sum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8>>.


%%
%% IPv6
%%
ipv6(
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    Src:128,
    Dst:128,
    Payload/binary>>
) ->
    {#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = Src, daddr = Dst
    }, Payload};
ipv6(#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = Src, daddr = Dst
    }) ->
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    Src:128,
    Dst:128>>.


%%
%% TCP
%%
tcp(
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
          PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16,
      Payload/binary>>
) ->
    {Opt, Data} = tcp_options(tcp_offset(Off), Payload),
    {#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
            psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp,
        opt = Opt
    }, Data};
tcp(#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
            psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp
    }) ->
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
          PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16>>.

tcp_offset(N) when N > 5 -> (N - 5) * 4;
tcp_offset(_) -> 0.

tcp_options(Offset, Payload) when Offset > 0 ->
    <<Opt:Offset/bytes, Msg/binary>> = Payload,
    {Opt, Msg};
tcp_options(_, Payload) ->
    {<<>>, Payload}.


%%
%% UDP
%%
udp(<<SPort:16, DPort:16, ULen:16, Sum:16, Payload/binary>>) ->
    {#udp{sport = SPort, dport = DPort, ulen = ULen, sum = Sum}, Payload};
udp(#udp{sport = SPort, dport = DPort, ulen = ULen, sum = Sum}) ->
    <<SPort:16, DPort:16, ULen:16, Sum:16>>.


%%
%% ICMP
%%

% Destination Unreachable Message
icmp(<<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, _Unused:32, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum
    }, Payload};
icmp(#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum
    }) ->
    <<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16>>;

% Time Exceeded Message
icmp(<<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16, _Unused:32, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum
    }, Payload};
icmp(#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum
    }) ->
    <<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16>>;

% Parameter Problem Message
icmp(<<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8, _Unused:24, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer
    }, Payload};
icmp(#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer
    }) ->
    <<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8>>;

% Source Quench Message
icmp(<<?ICMP_SOURCE_QUENCH:8, 0:8, Checksum:16, _Unused:32, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = 0, checksum = Checksum
    }, Payload};
icmp(#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = Code, checksum = Checksum
    }) ->
    <<?ICMP_SOURCE_QUENCH:8, Code:8, Checksum:16>>;

% Redirect Message
icmp(<<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }, Payload};
icmp(#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }) ->
    <<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4>>;

% Echo or Echo Reply Message
icmp(<<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, Payload/binary>>)
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }, Payload};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    })
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Timestamp or Timestamp Reply Message
icmp(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>)
when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }, <<>>};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }) when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>;

% Information Request or Information Reply Message
icmp(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16>>)
when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence
    }, <<>>};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }) when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Catch/build arbitrary types
icmp(<<Type:8, Code:8, Checksum:16, Un:32, Payload/binary>>) ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, un = Un
    }, Payload};
icmp(#icmp{type = Type, code = Code, checksum = Checksum, un = Un}) ->
    <<Type:8, Code:8, Checksum:16, Un:32>>.


%%
%% Utility functions
%%
payload(Payload) ->
    [ to_ascii(C) || <<C:8>> <= Payload ].


% TCP pseudoheader checksum
checksum([#ipv4{
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    },
    #tcp{
        off = Off
    } = TCPhdr,
    Payload
]) ->
    Len = Off * 4,
    TCP = tcp(TCPhdr#tcp{sum = 0}),
    Pad = case Len rem 2 of
        0 -> 0;
        1 -> 8
    end,
    checksum(
        list_to_binary([
                <<SA1,SA2,SA3,SA4,
                DA1,DA2,DA3,DA4,
                0:8,
                ?IPPROTO_TCP:8,
                Len:16>>,
                TCP,
                Payload,
                <<0:Pad>>
            ]));

% UDP pseudoheader checksum
checksum([#ipv4{
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    },
    #udp{
        sport = SPort,
        dport = DPort,
        ulen = Len
    },
    Payload
]) ->
    Pad = case Len rem 2 of
        0 -> 0;
        1 -> 8
    end,
    checksum(
        list_to_binary([
                <<SA1,SA2,SA3,SA4,
                DA1,DA2,DA3,DA4,
                0:8,
                ?IPPROTO_UDP:8,
                Len:16,

                SPort:16,
                DPort:16,
                Len:16,
                0:16,
                Payload/binary,
                0:Pad>>
            ]));

checksum(#ipv4{} = H) ->
    checksum(ipv4(H));
checksum(Hdr) ->
    lists:foldl(fun compl/2, 0, [ W || <<W:16>> <= Hdr ]).

makesum(Hdr) -> 16#FFFF - checksum(Hdr).

compl(N) when N =< 16#FFFF -> N;
compl(N) -> (N band 16#FFFF) + (N bsr 16).
compl(N,S) -> compl(N+S).

valid(16#FFFF) -> true;
valid(_) -> false.

to_ascii(C) when ?is_print(C) -> C;
to_ascii(_) -> $..

ether_addr(B) when is_binary(B) ->
    ether_addr(binary_to_list(B));
ether_addr(L) when is_list(L) ->
    [ hd(io_lib:format("~.16B", [N])) || N <- L ].

tcp_flags(#tcp{cwr = CWR, ece = ECE, urg = URG, ack = ACK,
        psh = PSH, rst = RST, syn = SYN, fin = FIN}) ->
    [ atom_to_list(F) || {F,V} <-
            [{cwr,CWR}, {ece,ECE}, {urg,URG}, {ack,ACK}, {psh,PSH}, {rst,RST}, {syn,SYN}, {fin,FIN}], V =:= 1 ].


