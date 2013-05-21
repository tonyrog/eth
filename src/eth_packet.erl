%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     General packet 
%%% @end
%%% Created :  2 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_packet).

-include_lib("enet/include/enet_types.hrl").

-export([decode/1, decode/2]).
-export([fmt_json/1, fmt_yang/1]).
-export([dump/1, dump_json/1, dump_yang/1]).
-export([parse_json/1, parse_yang/1]).
-export([ethtoa/1]).

-define(Q, $").

decode(Data) ->
    decode(Data, []).

decode(Data, Opts) ->
    enet_eth:decode(bin_data(Data), Opts).

dump(P) ->
    dump_json(P).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Format values and records in JSON format
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

dump_json(P) ->
    io:format("~s\n", [fmt_json(P)]).

parse_json(_String) ->
    ok.

fmt_json(P) ->
    case is_pkt_record(P) of
	true  -> fmt_json_record(0,P,"\n");
	false -> fmt_json_value(0,P,"\n")
    end.

fmt_json_record(I,P,N)  ->
    fmt_json_record(I,P,pkt_fields(P),N).

fmt_json_record(I,P,Fs,N) ->
    [R|Ds] = tuple_to_list(P),
    [ "{",N,
      fmt_json_fields(I+2, R, [struct|Fs], [R|Ds], N),
      N, indent(I), "}" ].

fmt_json_fields(I,R,[F],[D],N) ->
    [ [indent(I),fmt_json_field(I,R,F,D,N) ] ];
fmt_json_fields(I,R,[F|Fs],[D|Ds],N) ->
    [ [indent(I),fmt_json_field(I,R,F,D,N),",",N] |
      fmt_json_fields(I,R,Fs,Ds,N)];
fmt_json_fields(_I,_R,[],[],_N) ->
    [].

fmt_json_field(I,R,F,D,N) ->
    Fk = atom_to_list(F),
    Dk = fmt_json_value(I,R,F,D,N),
    [Fk,": ",Dk].

fmt_json_value(I,D,N) ->
    fmt_json_value(I,undefined,undefined,D,N).

fmt_json_value(I,R,F,D,N) ->
    if  
	is_boolean(D) -> [atom_to_list(D)];
	is_integer(D) -> [integer_to_list(D)];
	is_atom(D)    -> [?Q,atom_to_list(D),?Q];
	is_binary(D), R =:= ipv4, (F =:= src orelse F =:= dst) ->
	    IPV4 = list_to_tuple([X || <<X:8>> <= D]),
	    [?Q,inet_parse:ntoa(IPV4),?Q];
	is_binary(D), R =:= ipv6, (F =:= src orelse F =:= dst) ->
	    IPV6 = list_to_tuple([X || <<X:16>> <= D]),
	    [?Q,inet_parse:ntoa(IPV6),?Q];
	is_binary(D), R =:= eth, (F =:= src orelse F =:= dst) ->
	    Eth = list_to_tuple([X || <<X:8>> <= D]),
	    [?Q,ethtoa(Eth),?Q];
	is_binary(D) ->		 		     
	    io_lib:format("~p", [D]);
	is_bitstring(D) ->		 		     
	    io_lib:format("~p", [D]);
	is_tuple(D), tuple_size(D) =:= 4, R =:= ipv4,
	(F =:= src orelse F =:= dst) ->
	    [?Q,inet_parse:ntoa(D),?Q];
	is_tuple(D), tuple_size(D) =:= 8, R =:= ipv6,
	(F =:= src orelse F =:= dst) ->
	    [?Q,inet_parse:ntoa(D),?Q];
	is_tuple(D), tuple_size(D) =:= 6, R =:= eth,
	(F =:= src orelse F =:= dst) ->
	    [?Q,ethtoa(D),?Q];

	is_tuple(D), tuple_size(D) =:= 2, R =:= arp,
	(F =:= sender orelse F =:= target) ->
	%% R#arp.htype =:= ethernet, R#arp.ptype =:= ipv4 ->
	    [$[,[?Q,ethtoa(element(1,D)),?Q],$,,
	     [?Q,inet_parse:ntoa(element(2,D)),?Q],$]];

	is_tuple(D) ->
	    case is_pkt_record(D) of
		true ->
		    fmt_json_record(I+2,D,N);
		false ->
		    fmt_json_value(I,R,F,tuple_to_list(D),N)
	    end;
	is_list(D) ->
	    try iolist_size(D) of
		_Sz -> [?Q,D,?Q]
	    catch
		error:_ ->  %% formt as JSON array?
		    fmt_json_array(D)
	    end;
	true ->
	    io:format("DATA=~p\n", [D]),
	    exit(unknown)
    end.

fmt_json_array(Ds) ->
    ["[", fmt_json_elems(Ds), "]"].

fmt_json_elems([D]) ->
    fmt_json_value(0,D,"");
fmt_json_elems([D|Ds]) ->
    [fmt_json_value(0,D,""),"," | fmt_json_elems(Ds)];
fmt_json_elems([]) -> [].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% YANG FORMAT
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

dump_yang(P) ->
    io:format("~s\n", [fmt_yang(P)]).

parse_yang(_String) ->
    ok.

fmt_yang(P) ->
    case is_pkt_record(P) of
	true  -> fmt_yang_record(0,P,"\n");
	false -> fmt_yang_value(0,P,"\n")
    end.

fmt_yang_record(I,P,N)  ->
    fmt_yang_record(I,P,pkt_fields(P),N).

fmt_yang_record(I,P,Fs,N) ->
    [R|Ds] = tuple_to_list(P),
    [ atom_to_list(R), " {", N,
      fmt_yang_fields(I+2, R, Fs, Ds, N),
      indent(I), "}" ].

fmt_yang_fields(I,R,[F|Fs],[D|Ds],N) ->
    [ [indent(I),fmt_yang_field(I,R,F,D,N),separator(D,";"),N] |
      fmt_yang_fields(I,R,Fs,Ds,N)];
fmt_yang_fields(_I,_R,[],[],_N) ->
    [].

fmt_yang_field(I,R,F,D,N) ->
    Fk = atom_to_list(F),
    Dk = fmt_yang_value(I,R,F,D,N),
    [Fk," ",Dk].

fmt_yang_value(I,D,N) ->
    fmt_yang_value(I,undefined,undefined,D,N).

fmt_yang_value(I,R,F,D,N) ->
    if  
	is_boolean(D) -> [atom_to_list(D)];
	is_integer(D) -> [integer_to_list(D)];
	is_atom(D)    -> [atom_to_list(D)];
	is_binary(D), R =:= ipv4, (F =:= src orelse F =:= dst) ->
	    IPV4 = list_to_tuple([X || <<X:8>> <= D]),
	    [?Q,inet_parse:ntoa(IPV4),?Q];
	is_binary(D), R =:= ipv6, (F =:= src orelse F =:= dst) ->
	    IPV6 = list_to_tuple([X || <<X:16>> <= D]),
	    [?Q,inet_parse:ntoa(IPV6),?Q];
	is_binary(D), R =:= eth, (F =:= src orelse F =:= dst) ->
	    Eth = list_to_tuple([X || <<X:8>> <= D]),
	    [?Q,ethtoa(Eth),?Q];
	is_binary(D) -> %% fixme!
	    [?Q,io_lib:format("~p", [D]),?Q];
	is_bitstring(D) -> %% fixme!
	    [?Q,io_lib:format("~p", [D]),?Q];
	is_tuple(D), tuple_size(D) =:= 4, R =:= ipv4,
	(F =:= src orelse F =:= dst) ->
	    [?Q,inet_parse:ntoa(D),?Q];
	is_tuple(D), tuple_size(D) =:= 8, R =:= ipv6,
	(F =:= src orelse F =:= dst) ->
	    [?Q,inet_parse:ntoa(D),?Q];
	is_tuple(D), tuple_size(D) =:= 6, R =:= eth,
	(F =:= src orelse F =:= dst) ->
	    [?Q,ethtoa(D),?Q];
	is_tuple(D) ->
	    case is_pkt_record(D) of
		true ->
		    fmt_yang_record(I+2,D,N);
		false ->
		    fmt_yang_value(I,R,F,tuple_to_list(D),N)
	    end;
	is_list(D) ->
	    try iolist_size(D) of
		_Sz -> [?Q,D,?Q]
	    catch
		error:_ ->  %% formt as YANG array?
		    fmt_yang_array(D)
	    end
    end.

fmt_yang_array(Ds) ->
    fmt_yang_elems(Ds).

fmt_yang_elems([D]) ->
    fmt_yang_value(0,D,"");
fmt_yang_elems([D|Ds]) ->
    [fmt_yang_value(0,D,"")," " | fmt_yang_elems(Ds)];
fmt_yang_elems([]) -> [].

%%    
%% Parse binary data when needed
%%
bin_data(Data) when is_binary(Data) ->
    Data;
bin_data(RawData) when is_list(RawData) ->
    << << H:4 >> || H <- hex_norm_nibbles(RawData) >>.

hex_norm_nibbles([$\s|Cs]) -> hex_norm_nibbles(Cs);
hex_norm_nibbles([$\t|Cs]) -> hex_norm_nibbles(Cs);
hex_norm_nibbles([$\r|Cs]) -> hex_norm_nibbles(Cs);
hex_norm_nibbles([$\n|Cs]) -> hex_norm_nibbles(Cs);
hex_norm_nibbles([C|Cs]) ->
    if C >= $0, C =< $9 -> [C-$0 | hex_norm_nibbles(Cs)];
       C >= $A, C =< $F -> [(C-$A)+10 | hex_norm_nibbles(Cs)];
       C >= $a, C =< $f -> [(C-$A)+10 | hex_norm_nibbles(Cs)]
    end;
hex_norm_nibbles([]) ->
    [].


is_pkt_record(P) ->
    case P of
	#eth{}  -> true;
	#arp{}  -> true;
	#ipv4{} -> true;
	#udp{}  -> true;
	#icmp{}  -> true;
	#tcp{}  -> true;
	#ipv6{} -> true;
	_ -> false
    end.

pkt_fields(P) ->
    case P of
	#eth{} -> record_info(fields,eth);
	#arp{} -> record_info(fields,arp);
	#ipv4{} ->record_info(fields,ipv4);
	#udp{} ->record_info(fields,udp);
	#icmp{} ->record_info(fields,icmp);
	#tcp{} ->record_info(fields,tcp);
	#ipv6{} ->record_info(fields,ipv6);
	_ -> []
    end.
    
separator(D,S) ->
    case is_pkt_record(D) of
	true -> "";
	false -> S
    end.

indent(I) ->
    lists:duplicate(I, $\s).

ethtoa([]) -> "";
ethtoa(L=[_A,_B,_C,_D,_E,_F]) ->
    string:join([tl(erlang:integer_to_list(X+16#100,16)) || X <- L], ":");
ethtoa({A,B,C,D,E,F}) -> ethtoa([A,B,C,D,E,F]);
ethtoa(_) -> "?".

