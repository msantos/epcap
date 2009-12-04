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

-export([
        checksum/1,
        checksum/3,
        decapsulate/1,
        makesum/1,
        valid/1,
        ether/1,
        ether_addr/1,
        icmp/1,
        ipv4/1,
        payload/1,
        tcp/1,
        tcp_flags/1,
        udp/1
]).

-define(is_print(C), C >= $ , C =< $~).

decapsulate(P) ->
    {EtherHdr, EtherData} = ether(P),
    {IPHdr, IPData} = ipv4(EtherData),
    Proto = proto(IPHdr#ipv4.p),
    {Hdr, Payload} = ?MODULE:Proto(IPData),
    [EtherHdr, IPHdr, Hdr, Payload].

proto(?IPPROTO_ICMP) -> icmp;
proto(?IPPROTO_TCP) -> tcp;
proto(?IPPROTO_UDP) -> udp.

ether(<<Dhost:6/bytes, Shost:6/bytes, Type:2/bytes, Packet/binary>>) ->
    Len = byte_size(Packet) - 4,
    <<Payload:Len/bytes, CRC:4/bytes>> = Packet,
    {#ether{
        dhost = Dhost, shost = Shost,
        type = Type, crc = CRC
    }, Payload}.

ipv4(
    <<V:4, HL:4, ToS:8, Len:16, 
    Id:16, _RF:1, DF:1, MF:1, 
    Off:13, TTL:8, P:8, Sum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8,
    Payload/binary>> = Raw
) ->
    <<Hdr:160/bitstring, _/binary>> = Raw,
    Valid = case makesum(Hdr) of
        0 -> true;
        _ -> false
    end,

    {#ipv4{
        valid = Valid,
        v = V, hl = HL, tos = ToS, len = Len,
        id = Id, df = DF, mf = MF,
        off = Off, ttl = TTL, p = P, sum = Sum,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    }, Payload}.

tcp(
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
          PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16,
      Payload/binary>>
) ->
    {Opt, Msg} = tcp_options(tcp_offset(Off), Payload),
    {#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
            psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp,
        opt = Opt
    }, Msg}.

tcp_offset(N) when N > 5 -> (N - 5) * 4;
tcp_offset(_) -> 0.

% Appears some optimization is stripping the padding off the options
tcp_options(Offset, Payload) when Offset > byte_size(Payload) ->
    {Payload, <<>>};
tcp_options(Offset, Payload) when Offset > 0 ->
    <<Opt:Offset/bytes, Msg/binary>> = Payload,
    {Opt, Msg};
tcp_options(_, Payload) ->
    {<<>>, Payload}.

udp(<<SPort:16, DPort:16, ULen:16, Sum:16, Payload/binary>>) ->
    {#udp{sport = SPort, dport = DPort, ulen = ULen, sum = Sum}, Payload}.

icmp(<<?ICMP_ECHO:8, Code:8, Checksum:16, Id:16, Sequence:16, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_ECHO, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }, Payload};

% PLACEHOLDER: gateway
icmp(<<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, Gateway:32, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, gateway = Gateway
    }, Payload};

% PLACEHOLDER: frag
icmp(<<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, _Unused:16, MTU:16, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, mtu = MTU
    }, Payload};

% Catch unknown types
icmp(<<Type:8, Code:8, Checksum:16, Un:32, Payload/binary>>) ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, un = Un
    }, Payload}.

payload(Payload) ->
    [ to_ascii(C) || <<C:8>> <= Payload ].

checksum(Hdr) ->
    lists:foldl(fun compl/2, 0, [ W || <<W:16>> <= Hdr ]).

checksum(tcp, #ipv4{saddr = {S1,S2,S3,S4}, daddr = {D1,D2,D3,D4}, p = P},
    <<Head:16/bytes, _:2/bytes, Trailer/binary>> = Payload) ->
    Len = byte_size(Payload),
    PseudoHdr = case Len rem 2 of
        0 -> <<S1,S2,S3,S4,D1,D2,D3,D4,0:8,P,Len:16,Head/bytes,0:16,Trailer/bytes>>;
        1 -> <<S1,S2,S3,S4,D1,D2,D3,D4,0:8,P,Len:16,Head/bytes,0:16,Trailer/bytes,0>>
    end,
    checksum(PseudoHdr).

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



