%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%    BPF machine support
%%% @end
%%% Created :  2 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_bpf).

-include("eth_bpf.hrl").

-export([encode/1]).
-export([decode/1]).
-export([join/1]).
-export([exec/2, exec/6]).

%% bpf program utils
-export([build_program/1, build_programa/1, build_programx/1]).
-export([validate/1, print/1]).

-export([accept/0, 
	 reject/0,
	 return/1, 
	 expr/1,
	 expr/2]).

%% some predefined expressions
-compile(export_all).

-import(lists, [reverse/1, foldl/3]).

%% -define(DEBUG, true).

-ifdef(DEBUG).
-define(debug(F,A),
	 io:format("~s:~w: debug: "++(F), [?FILE,?LINE|(A)])).
-else.
-define(debug(F,A), ok).
-endif.

-define(warning(F,A), 
	io:format("~s:~w: warning: "++(F), [?FILE,?LINE|(A)])).
-define(error(F,A),
	io:format("~s:~w: error: "++(F), [?FILE,?LINE|(A)])).
-define(info(F,A),
	io:format("~s:~w: info: "++(F), [?FILE,?LINE|(A)])).


%% Some optimisations propagate slowly so we must handle this max better!
-define(MAX_OPTIMISE, 100).

-define(uint32(X), ((X) band 16#ffffffff)).

-define(U8,  1).
-define(U16, 2).
-define(U32, 4).
%%
%% Examples (remove soon)
%%
-define(ETHERTYPE_PUP,    16#0200).
-define(ETHERTYPE_IP,     16#0800).
-define(ETHERTYPE_ARP,    16#0806).
-define(ETHERTYPE_REVARP, 16#8035).
-define(ETHERTYPE_VLAN,   16#8100).
-define(ETHERTYPE_IPV6,   16#86dd).


-define(ARPOP_REQUEST,  1).	%% ARP request.
-define(ARPOP_REPLY,    2).	%% ARP reply.
-define(ARPOP_RREQUEST, 3).	%% RARP request.
-define(ARPOP_RREPLY,   4).     %% RARP reply.

-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP,  6).
-define(IPPROTO_UDP,  17).
-define(IPPROTO_SCTP, 132).

-define(OFFS_ETH,        (0)).
-define(OFFS_ETH_DST,    (0)).
-define(OFFS_ETH_SRC,    (6)).
-define(OFFS_ETH_TYPE,   (6+6)).
-define(OFFS_ETH_DATA,   (6+6+2)).

-define(VLAN, 4).

-define(OFFS_VLAN_TPID,  (?OFFS_ETH_DATA)).
-define(OFFS_VLAN_TCI,  (?OFFS_ETH_DATA+2)).

-define(OFFS_ARP_HTYPE,  (?OFFS_ETH_DATA)).
-define(OFFS_ARP_PTYPE,  (?OFFS_ETH_DATA+2)).
-define(OFFS_ARP_HALEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_ARP_PALEN,  (?OFFS_ETH_DATA+5)).
-define(OFFS_ARP_OP,     (?OFFS_ETH_DATA+6)).

-define(OFFS_IPV4,       (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV4_HLEN,  (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV4_DSRV,  (?OFFS_ETH_DATA+1)).
-define(OFFS_IPV4_LEN,   (?OFFS_ETH_DATA+2)).
-define(OFFS_IPV4_ID,    (?OFFS_ETH_DATA+4)).
-define(OFFS_IPV4_FRAG,  (?OFFS_ETH_DATA+6)).
-define(OFFS_IPV4_TTL,   (?OFFS_ETH_DATA+8)).
-define(OFFS_IPV4_PROTO, (?OFFS_ETH_DATA+9)).
-define(OFFS_IPV4_CSUM,  (?OFFS_ETH_DATA+10)).
-define(OFFS_IPV4_SRC,   (?OFFS_ETH_DATA+12)).
-define(OFFS_IPV4_DST,   (?OFFS_ETH_DATA+16)).
-define(OFFS_IPV4_DATA,  (?OFFS_ETH_DATA+20)).

-define(OFFS_IPV6,      (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV6_LEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_IPV6_NEXT, (?OFFS_ETH_DATA+6)).
-define(OFFS_IPV6_HOPC, (?OFFS_ETH_DATA+7)).
-define(OFFS_IPV6_SRC,  (?OFFS_ETH_DATA+8)).
-define(OFFS_IPV6_DST,  (?OFFS_ETH_DATA+24)).
-define(OFFS_IPV6_PAYLOAD, (?OFFS_ETH_DATA+40)).

%% Given that X contains the IP headers length
-define(OFFS_TCP_SRC_PORT, 0).  %% uint16
-define(OFFS_TCP_DST_PORT, 2).  %% uint16
-define(OFFS_TCP_SEQ,      4).  %% uint32
-define(OFFS_TCP_ACK,      8).  %% uint32
-define(OFFS_TCP_FLAGS,    12). %% Offs:4,_:6,UAPRSF:6
-define(OFFS_TCP_WINDOW,   14). %% uint16
-define(OFFS_TCP_CSUM,     16). %% uint16
-define(OFFS_TCP_UPTR,     18). %% uint16

-define(OFFS_UDP_SRC_PORT,  0).  %% uint16
-define(OFFS_UDP_DST_PORT,  2).  %% uint16
-define(OFFS_UDP_LENGTH,    4).  %% uint16
-define(OFFS_UDP_CSUM,      6).  %% uint16
-define(OFFS_UDP_DATA,      8).  


test1() ->
    build_programx({'&&', ["eth.type.ip", "ip.proto.tcp",
			   {'==',"ip.frag",0},
			   "ip.tcp.flag.syn",
			   "ip.tcp.flag.ack"]}).

test2() ->
    build_programx({'||', 
		    {'&&', ["eth.type.ip", "ip.proto.tcp",
			    {'==',"ip.frag",0},
			    "ip.tcp.flag.syn",
			    "ip.tcp.flag.ack"]},
		    {'&&', ["eth.type.ip", "ip.proto.tcp",
			    {'==',"ip.frag",0},
			    "ip.tcp.flag.fin",
			    "ip.tcp.flag.ack"]}}).

test3() ->
    build_program_list(
      [{'&&', ["eth.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 14}
	      ]},
       
       {'&&', ["eth.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 15}
	      ]},

       {'&&', ["eth.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 16}
	      ]},

       {'&&', ["eth.type.ip",
	       {'==', "ip.src[0]", 239},
	       {'==', "ip.src[1]", 17}
	      ]},

       {'&&', ["eth.type.ip",
	       {'==', "ip.src[0]", 235}
	      ]},

       {'&&', ["eth.type.ip", "ip.src.10.13.75.100"]},
       {'&&', ["eth.type.ip", "ip.src.10.13.75.101"]},
       {'&&', ["eth.type.ip", "ip.src.10.13.75.102"]},
       {'&&', ["eth.type.ip6",
	       "ip6.src.fd6b:9860:79f5:ae8c:600b:8ea1:fbf9:807"]},
       {'&&', ["eth.type.ip6",
	       "ip6.src.fd6b:9860:79f5:ae8c:600b:8ea1:fbf9:808"]}
      ]).


test4() ->
    build_programx(
      {'&&',["eth.type.ip",
	     "ip.proto.udp",
	     {'||',
	      ["ip.src.1.2.3.4",
	       "ip.src.1.2.3.12",
	       "ip.src.1.2.3.14",
	       "ip.src.1.2.3.23",
	       "ip.src.1.2.3.100",
	       "ip.src.1.2.3.103",
	       "ip.src.1.2.3.111",
	       "ip.src.1.2.3.115",
	       "ip.src.1.2.3.117",
	       "ip.src.1.2.3.119"
	      ]}]}).

test41() ->
    build_programx(
      {'||',
       [{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.4"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.12"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.14"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.23"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.100"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.103"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.111"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.115"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.117"]},
	{'&&',["eth.type.ip","ip.proto.udp",   "ip.src.1.2.3.119"]}
       ]}).

test51() ->
    build_programx(
      {'&&',
       ["eth.type.ip",
	"ip.src.192.168.1.16..192.168.1.32"
	%% "ip.src.192.168.2.0/24"
       ]}).

test52() ->
    build_programx(	 
      {'&&', 
       ["eth.type.ip6",
	"ip6.src.0:1:0:2:0:3:192.168.1.16..0:1:0:2:0:3:192.168.1.32"
	%% "ip6.src.1::5:6:192.168.2.0/120"
       ]}).

%% should be same as port.53!
test53() ->
    build_programx(
      {'||',
       [{'&&',["eth.type.ip",
	       "ip.proto.tcp",
	       "ip.tcp.src_port.53",
	       "ip.tcp.dst_port.53"]},
	{'&&',["eth.type.ip",
	       "ip.proto.udp",
	       "ip.udp.src_port.53",
	       "ip.udp.dst_port.53"]},
	{'&&',["eth.type.ip6",
	       "ip6.proto.tcp",
	       "ip6.tcp.src_port.53",
	     "ip6.tcp.dst_port.53"]},
	{'&&',["eth.type.ip6",
	       "ip6.proto.udp",
	       "ip6.udp.src_port.53",
	       "ip6.udp.dst_port.53"]}]}).

test6() ->
    build_programx(
      {'&&', ["eth.type.ip",
	      "ip.host.192.168.1.103"]}).

test_http_get() ->
    eth_bpf:build_programx(
      {'&&',
       ["eth.type.ip","ip.proto.tcp", {'==',"ip.frag",0},
	"ip.tcp.flag.psh",
	{memeq, "ip.tcp.data", <<"GET ">>}
       ]}).

test_teclo_profile() ->
    build_program_list(
      [  {'&&', ["vlan", "eth.type.ip", "ip.src.41.0.0.228" ]},
	 {'&&', ["vlan",
		 "eth.type.ip",
		 {'||', ["ip.src.41.185.26.72",
			 "ip.src.117.121.243.78",
			 "ip.src.159.253.209.38",
			 "ip.src.188.40.129.212",

			 "ip.dst.41.185.26.72",
			 "ip.dst.117.121.243.78",
			 "ip.dst.159.253.209.38",
			 "ip.dst.188.40.129.212"

			]}]},
	 {'&&', ["vlan",
		 "eth.type.ip",
		 {'||', ["ip.src.10.188.0.0/18",
			 "ip.src.10.194.0.0/18",

			 "ip.dst.10.188.0.0/18",
			 "ip.dst.10.194.0.0/18"

			]}]},
	 {'||', [ {'&&', ["eth.type.ip", "ip.proto.tcp"]},
		  {'&&', ["vlan",
			  "eth.type.ip", "ip.proto.tcp"]}
		]}
      ]).

test_contrack() ->
    eth_bpf:build_programx(
      {'||', 
       [connect_filter(),
	disconnect_filter(),
	reset_filter()
       ]}).

%% TCP - SYN/ACK => established
connect_filter() ->
    {'&&', ["eth.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.syn", "ip.tcp.flag.ack"
	   ]}.

%% TCP - FIN/ACK => disconnected
disconnect_filter() ->
    {'&&', ["eth.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.fin","ip.tcp.flag.ack"
	   ]}.

reset_filter() ->
    {'&&', ["eth.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.rst"
	   ]}.


test_teclo_optimise() ->
    build_program_list(
      [ 
	%% "vlan and host "41.0.0.228"
	{'&&', ["vlan",
		"eth.type.ip",
		"ip.host.41.0.0.228"]},

	%% "vlan (?tcp) and ((dst port 45373) or (src portrange 50000-59999))",
	{'&&', ["vlan",
		"eth.type.ip",
		"ip.proto.tcp",
		{'||',
		 "ip.tcp.dst_port.45373",
		 "ip.tcp.src_port.50000..59999"}
	       ]},
	%%  (ip[12]+ip[13]+ip[14]+ip[15]) & 1 == ((src rem 255) & 1) ???
	%% "(vlan and ((ip[12]+ip[13]+ip[14]+ip[15]) & 1) == 1) ",
	{'&&', ["vlan",
		"eth.type.ip",
		{'==', 
		 {'&', 
		  {'+', [ "ip[12]", "ip[13]", "ip[14]", "ip[15]" ] }, 1}, 1}
	       ]},
	%% "tcp"
	{'&&', ["eth.type.ip", "ip.proto.tcp"]}
      ]).

%% "compile" the program 
encode(Prog) when is_tuple(Prog) ->
    list_to_binary([ encode_(B) || B <- tuple_to_list(Prog)]).

encode_(#bpf_insn{code=ldaw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_ABS, K);
encode_(#bpf_insn{code=ldah,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_ABS,K);
encode_(#bpf_insn{code=ldab,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_ABS, K);

encode_(#bpf_insn{code=ldiw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_IND,K);
encode_(#bpf_insn{code=ldih,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_IND,K);
encode_(#bpf_insn{code=ldib,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_IND,K);

encode_(#bpf_insn{code=ldl })      -> insn(?BPF_LD + ?BPF_LEN);
encode_(#bpf_insn{code=ldc, k=K})  -> insn(?BPF_LD + ?BPF_IMM, K);
encode_(#bpf_insn{code=lda, k=K})  -> insn(?BPF_LD + ?BPF_MEM, K);

encode_(#bpf_insn{code=ldxc, k=K}) -> insn(?BPF_LDX+?BPF_W+?BPF_IMM, K);
encode_(#bpf_insn{code=ldx, k=K})  -> insn(?BPF_LDX+?BPF_W+?BPF_MEM, K);
encode_(#bpf_insn{code=ldxl })     -> insn(?BPF_LDX+?BPF_W+?BPF_LEN);
encode_(#bpf_insn{code=ldxmsh, k=K}) -> insn(?BPF_LDX+?BPF_B+?BPF_MSH, K);

encode_(#bpf_insn{code=sta,k=K})   -> insn(?BPF_ST, K);
encode_(#bpf_insn{code=stx,k=K})   -> insn(?BPF_STX, K);

encode_(#bpf_insn{code=addk, k=K}) -> insn(?BPF_ALU+?BPF_ADD+?BPF_K, K);
encode_(#bpf_insn{code=subk, k=K}) -> insn(?BPF_ALU+?BPF_SUB+?BPF_K, K);
encode_(#bpf_insn{code=mulk, k=K}) -> insn(?BPF_ALU+?BPF_MUL+?BPF_K, K);
encode_(#bpf_insn{code=divk, k=K}) -> insn(?BPF_ALU+?BPF_DIV+?BPF_K, K);
encode_(#bpf_insn{code=andk, k=K}) -> insn(?BPF_ALU+?BPF_AND+?BPF_K, K);
encode_(#bpf_insn{code=ork,  k=K}) ->  insn(?BPF_ALU+?BPF_OR+?BPF_K, K);
encode_(#bpf_insn{code=lshk, k=K}) -> insn(?BPF_ALU+?BPF_LSH+?BPF_K, K);
encode_(#bpf_insn{code=rshk, k=K}) -> insn(?BPF_ALU+?BPF_RSH+?BPF_K, K);
encode_(#bpf_insn{code=addx}) ->      insn(?BPF_ALU+?BPF_ADD+?BPF_X);
encode_(#bpf_insn{code=subx}) ->      insn(?BPF_ALU+?BPF_SUB+?BPF_X);
encode_(#bpf_insn{code=mulx}) ->      insn(?BPF_ALU+?BPF_MUL+?BPF_X);
encode_(#bpf_insn{code=divx}) ->      insn(?BPF_ALU+?BPF_DIV+?BPF_X);
encode_(#bpf_insn{code=andx}) ->      insn(?BPF_ALU+?BPF_AND+?BPF_X);
encode_(#bpf_insn{code=orx}) ->       insn(?BPF_ALU+?BPF_OR+?BPF_X);
encode_(#bpf_insn{code=lshx}) ->      insn(?BPF_ALU+?BPF_LSH+?BPF_X);
encode_(#bpf_insn{code=rshx}) ->      insn(?BPF_ALU+?BPF_RSH+?BPF_X);
encode_(#bpf_insn{code=neg}) ->       insn(?BPF_ALU+?BPF_NEG);
encode_(#bpf_insn{code=jmp,k=K}) ->   insn(?BPF_JMP+?BPF_JA, K);

encode_(I=#bpf_insn{code=jgtk})  -> jump(?BPF_JMP+?BPF_JGT+?BPF_K, I);
encode_(I=#bpf_insn{code=jgek})  -> jump(?BPF_JMP+?BPF_JGE+?BPF_K, I);
encode_(I=#bpf_insn{code=jeqk})  -> jump(?BPF_JMP+?BPF_JEQ+?BPF_K, I);
encode_(I=#bpf_insn{code=jsetk}) -> jump(?BPF_JMP+?BPF_JSET+?BPF_K, I);
encode_(I=#bpf_insn{code=jgtx})  -> jump(?BPF_JMP+?BPF_JGT+?BPF_X, I);
encode_(I=#bpf_insn{code=jgex})  -> jump(?BPF_JMP+?BPF_JGE+?BPF_X, I);
encode_(I=#bpf_insn{code=jeqx})  -> jump(?BPF_JMP+?BPF_JEQ+?BPF_X, I);
encode_(I=#bpf_insn{code=jsetx}) -> jump(?BPF_JMP+?BPF_JSET+?BPF_X, I);

encode_(#bpf_insn{code=reta})     -> insn(?BPF_RET+?BPF_A);
encode_(#bpf_insn{code=retk,k=K}) -> insn(?BPF_RET+?BPF_K,K);

encode_(#bpf_insn{code=tax}) -> insn(?BPF_MISC+?BPF_TAX);
encode_(#bpf_insn{code=txa}) -> insn(?BPF_MISC+?BPF_TXA).


jump(Code, #bpf_insn{jt=Jt,jf=Jf,k=K}) ->
    <<Code:16, Jt:8, Jf:8, K:32>>.

insn(Code) ->    <<Code:16, 0:8, 0:8, 0:32>>.
insn(Code, K) ->  <<Code:16, 0:8, 0:8, K:32>>.

%%
%% "decompile" a bpf program
%%
decode(Bin) when is_binary(Bin) ->
    list_to_tuple([ decode_(I) || <<I:8/binary>> <= Bin ]).
    
decode_(<<Code:16, Jt:8, Jf:8, K:32>>) ->
    case ?BPF_CLASS(Code) of
	?BPF_LD   -> decode_ld_(Code, K);
	?BPF_LDX  -> decode_ldx_(Code, K);
	?BPF_ST   -> decode_st_(Code, K);
	?BPF_STX  -> decode_stx_(Code, K);
	?BPF_ALU  -> decode_alu_(Code, K);
	?BPF_JMP  -> decode_jmp_(Code, Jt, Jf, K);
	?BPF_RET  -> decode_ret_(Code, K);
	?BPF_MISC -> decode_misc_(Code)
    end.

decode_ld_(Code, K) ->
    case ?BPF_MODE(Code) of
	?BPF_IMM -> #bpf_insn { code=ldc, k=K};
	?BPF_ABS -> 
	    case ?BPF_SIZE(Code) of
		?BPF_W -> #bpf_insn { code=ldaw, k=K};
		?BPF_H -> #bpf_insn { code=ldah, k=K};
		?BPF_B -> #bpf_insn { code=ldab, k=K}
	    end;
	?BPF_IND ->
	    case ?BPF_SIZE(Code) of
		?BPF_W -> #bpf_insn { code=ldiw, k=K};
		?BPF_H -> #bpf_insn { code=ldih, k=K};
		?BPF_B -> #bpf_insn { code=ldib, k=K}
	    end;
	?BPF_MEM -> #bpf_insn { code=lda, k=K};
	?BPF_LEN -> #bpf_insn { code=ldl }
    end.

decode_ldx_(Code, K) ->
    case ?BPF_SIZE(Code) of
	?BPF_W ->
	    case ?BPF_MODE(Code) of
		?BPF_IMM -> #bpf_insn { code=ldxc, k=K};
		?BPF_MEM -> #bpf_insn { code=ldx, k=K};
		?BPF_LEN -> #bpf_insn { code=ldxl }
	    end;
	?BPF_B ->
	    case ?BPF_MODE(Code) of
		?BPF_MSH -> #bpf_insn { code=ldxmsh, k=K}
	    end
    end.

decode_st_(_Code, K) ->
    #bpf_insn { code=sta, k=K }.

decode_stx_(_Code, K) ->
    #bpf_insn { code=stx, k=K }.

decode_alu_(Code, K) ->
    case ?BPF_OP(Code) of
	?BPF_ADD -> #bpf_insn { code=alu_src_(Code,addk,addx), k=K };
	?BPF_SUB -> #bpf_insn { code=alu_src_(Code,subk,subx), k=K };
	?BPF_MUL -> #bpf_insn { code=alu_src_(Code,mulk,mulx), k=K };
	?BPF_DIV -> #bpf_insn { code=alu_src_(Code,divk,divx), k=K };
	?BPF_OR  -> #bpf_insn { code=alu_src_(Code,ork,orx),    k=K };
	?BPF_AND -> #bpf_insn { code=alu_src_(Code,andk,andx), k=K };
	?BPF_LSH -> #bpf_insn { code=alu_src_(Code,lshk,lshx), k=K };
	?BPF_RSH -> #bpf_insn { code=alu_src_(Code,rshk,rshx), k=K };
	?BPF_NEG -> #bpf_insn { code=neg }
    end.

decode_jmp_(Code, Jt, Jf, K) ->
    case ?BPF_OP(Code) of    
	?BPF_JA  -> #bpf_insn { code=jmp, k=K };
	?BPF_JEQ -> #bpf_insn { code=alu_src_(Code,jeqk,jeqx),k=K,jt=Jt,jf=Jf };
	?BPF_JGT -> #bpf_insn { code=alu_src_(Code,jgtk,jgtx),k=K,jt=Jt,jf=Jf };
	?BPF_JGE -> #bpf_insn { code=alu_src_(Code,jgek,jgex),k=K,jt=Jt,jf=Jf };
	?BPF_JSET ->#bpf_insn { code=alu_src_(Code,jsetk,jsetx),
				k=K,jt=Jt,jf=Jf }
    end.

decode_ret_(Code, K) ->
    case ?BPF_RVAL(Code) of
	?BPF_A -> #bpf_insn { code=reta };
	?BPF_K -> #bpf_insn { code=retk, k=K }
    end.

decode_misc_(Code) ->
    case ?BPF_MISCOP(Code) of
	?BPF_TAX -> #bpf_insn { code=tax };
	?BPF_TXA -> #bpf_insn { code=txa }
    end.
	    
alu_src_(Code, K, X) ->
    case ?BPF_SRC(Code) of
	?BPF_K -> K;
	?BPF_X -> X
    end.

%% Join encoded filters into one big filter
join([]) ->
    encode({reject()});
join(Fs) -> 
    join_(Fs, []).

join_([F], Acc) ->
    Prog = if F =:= <<>> -> {accept()};
	      true -> decode(F)
	   end,
    Is = tuple_to_list(Prog),
    Js = lists:flatten(reverse([Is | Acc])),
    Prog1 = list_to_tuple(Js),
    %% optimise ?
    encode(Prog1);
join_([F|Fs], Acc) ->
    Prog = if F =:= <<>> -> {nop()};
	      true -> decode(F)
	   end,
    Is = tuple_to_list(Prog),
    %% translate:
    %%  {ret,0} => {jmp,<next-filter>}
    %% fixme translate:
    %%  reta => jeqk 0 <next-filter> else <reta-label>
    Js = join_rewrite_(Is, tuple_size(Prog)),
    join_(Fs, [Js | Acc]).

join_rewrite_([#bpf_insn {code=retk, k=0}|Is], N) ->
    [#bpf_insn { code=jmp, k=N-1 } | join_rewrite_(Is, N-1)];
join_rewrite_([I|Is], N) ->
    [I | join_rewrite_(Is, N-1)];
join_rewrite_([], _N) ->
    [].


class(I) ->
    K = I#bpf_insn.k,
    case I#bpf_insn.code of
	ldaw  -> {ld,a,{p,K,4}};
	ldah  -> {ld,a,{p,K,2}};
	ldab  -> {ld,a,{p,K,1}};

	ldiw  -> {ld,a,{px,K,4}};
	ldih  -> {ld,a,{px,K,2}};
	ldib  -> {ld,a,{px,K,1}};
	ldl   -> {ld,a,{l,4}};
	ldc   -> {ld,a,{k,K}};
	lda   -> {ld,a,{m,K}};
	ldxc  -> {ld,x,{k,K}};
	ldx   -> {ld,x,{m,K}};
	ldxl  -> {ld,x,{l,4}};
	ldxmsh -> {ld,x,{msh,K}};

	sta    -> {st,a,{m,K}};
	stx    -> {st,x,{m,K}};

	jmp   -> {jmp,true,k};
	jgtk  -> {jmp,'>', k};
	jgek  -> {jmp,'>=',k};
	jeqk  -> {jmp,'==',k};
	jsetk -> {jmp,'&',k};
	jgtx  -> {jmp,'>', x};
	jgex  -> {jmp,'>=',x};
	jeqx  -> {jmp,'==',x};
	jsetx -> {jmp,'&',x};

	addk -> {alu,a,{k,K}};
	subk -> {alu,a,{k,K}};
	mulk -> {alu,a,{k,K}};
	divk -> {alu,a,{k,K}};
	andk -> {alu,a,{k,K}};
	ork  -> {alu,a,{k,K}};
	lshk -> {alu,a,{k,K}};
	rshk -> {alu,a,{k,K}};
	addx -> {alu,a,x};
	subx -> {alu,a,x};
	mulx -> {alu,a,x};
	divx -> {alu,a,x};
	andx -> {alu,a,x};
	orx  -> {alu,a,x};
	lshx -> {alu,a,x};
	rshx -> {alu,a,x};
	neg  -> {alu,a,a};

	reta -> {ret,a};
	retk -> {ret,{k,K}};

	tax ->  {misc,x,a};
	txa ->  {misc,a,x}
    end.

%%
%% Print BPF  (style C/tcpdump)
%%

print_bs(Bs) when is_record(Bs,bpf_bs) ->
    bs_each_block(
      fun(B) ->
	      io:format("L~w:\n", [B#bpf_block.label]),
	      lists:foreach(
		fun(I) ->
			print_insn_c("    ", -1, I)
		end, B#bpf_block.insns),
	      print_insn_c("    ", -1, B#bpf_block.next),
	      io:format("    cond ~w\n", [B#bpf_block.ncond])
      end, Bs),
    Bs.

print(Prog) when is_tuple(Prog) ->
    print_p(Prog, 0).

%%
%% Print in "C" format
%%

print_c(Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    L = io_lib:format("~.3.0w: ", [J]),
    print_insn_c(L, J, I),
    print_c(Prog, J+1);
print_c(Prog, _J) ->
    Prog.

print_insn_c(L, J, I) ->
    case class(I) of
	{jmp,Cond,R} ->
	    print_jmp_c(Cond,R,I,L,J);
	{ld,Dst,Src} ->
	    print_ld_c(Dst,Src,I,L);
	_ ->
	    case I of
		#bpf_insn { code=sta, k=K} ->
		    io:format("~sM[~w] = A;\n", [L,K]);
		#bpf_insn { code=stx, k=K} ->
		    io:format("~sM[~w] = X;\n", [L,K]);
		#bpf_insn { code=addk, k=K } ->
		    io:format("~sA += ~w;\n", [L,K]);
		#bpf_insn { code=subk, k=K } ->
		    io:format("~sA -= ~w;\n", [L,K]);
		#bpf_insn { code=mulk, k=K } ->
		    io:format("~sA *= ~w;\n", [L,K]);
		#bpf_insn { code=divk, k=K } ->
		    io:format("~sA /= ~w;\n", [L,K]);
		#bpf_insn { code=andk, k=K } ->
		    io:format("~sA &= ~w;\n", [L,K]);
		#bpf_insn { code=ork, k=K } ->
		    io:format("~sA |= ~w;\n", [L,K]);
		#bpf_insn { code=lshk, k=K } ->
		    io:format("~sA <<= ~w;\n", [L,K]);
		#bpf_insn { code=rshk, k=K } ->
		    io:format("~sA >>= ~w;\n", [L,K]);
		#bpf_insn { code=addx } ->
		    io:format("~sA += X;\n", [L]);
		#bpf_insn { code=subx } ->
		    io:format("~sA -= X;\n", [L]);
		#bpf_insn { code=mulx } ->
		    io:format("~sA *= X;\n", [L]);
		#bpf_insn { code=divx } ->
		    io:format("~sA /= X;\n", [L]);
		#bpf_insn { code=andx } ->
		    io:format("~sA &= X;\n", [L]);
		#bpf_insn { code=orx } ->
		    io:format("~sA |= X;\n", [L]);
		#bpf_insn { code=lshx } ->
		    io:format("~sA <<= X;\n", [L]);
		#bpf_insn { code=rshx } ->
		    io:format("~sA >>= X;\n", [L]);
		#bpf_insn { code=neg } ->
		    io:format("~sA = -A;\n", [L]);
		#bpf_insn { code=tax } ->
		    io:format("~sX = A;\n", [L]);
		#bpf_insn { code=txa } ->
		    io:format("~sA = X;\n", [L]);
		#bpf_insn { code=reta } ->
		    io:format("~sreturn A;\n", [L]);
		#bpf_insn { code=retk, k=K } ->
		    io:format("~sreturn ~w;\n", [L,K])
	    end
    end.

print_ld_c(Dst,Src,_I,L) ->
    D = if Dst =:= 'a' -> "A";
	   Dst =:= 'x' -> "X"
	end,
    case Src of
	{p,K,S} ->
	    io:format("~s~s = P[~w:~w];\n", [L,D,K,S]);
	{px,K,S} ->
	    io:format("~s~s = P[X+~w:~w];\n", [L,D,K,S]);
	{l,_S} ->
	    io:format("~s~s = len;\n", [L,D]);
	{k,K} ->
	    io:format("~s~s = ~w;\n", [L,D,K]);
	{m,K} ->
	    io:format("~s~s = M[~w];\n", [L,D,K]);
	{msh,K} ->
	    io:format("~s~s = 4*(P[~w:1]&0xF);\n", [L,D,K])
    end.

print_jmp_c(true,k,I,L,J) ->
    if I#bpf_insn.k =:= 0 ->
	    io:format("~snop;\n", [L]);
       true ->
	    io:format("~sgoto L~0w;\n", 
		      [L,J+1+I#bpf_insn.k])
    end;
print_jmp_c(Cond,k,I,L,J) ->
    io:format("~sif (A ~s #0x~.16B) goto L~w; else goto L~w;\n", 
	      [L,Cond,I#bpf_insn.k,
	       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]);
print_jmp_c(Cond,x,I,L,J) ->
    io:format("~sif (A ~s X) goto L~w; else goto L~w;\n", 
	      [L,Cond,
	       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]).

%%
%% Print in pcap format
%%
    
print_p(Prog, J) when J >= 0, J < tuple_size(Prog) ->
    I = element(J+1,Prog),
    print_insn_p(J, I),
    print_p(Prog, J+1);
print_p(Prog, _J) ->
    Prog.

print_insn_p(J,I) ->
    case I of
	#bpf_insn{code=ldaw,k=K}  -> out_p(J,"ld","[~w]", [K]);
	#bpf_insn{code=ldah,k=K}  -> out_p(J,"ldh","[~w]", [K]);
	#bpf_insn{code=ldab,k=K}  -> out_p(J,"ldb","[~w]", [K]);
	#bpf_insn{code=ldiw,k=K}  -> out_p(J,"ld","[x + ~w]", [K]);
	#bpf_insn{code=ldih,k=K}  -> out_p(J,"ldh","[x + ~w]", [K]);
	#bpf_insn{code=ldib,k=K}  -> out_p(J,"ldb","[x + ~w]", [K]); 
	#bpf_insn{code=ldl }      -> out_p(J,"ld", "len", []);
	#bpf_insn{code=ldc, k=K}  -> out_p(J,"ld", "#0x~.16b", [K]);
	#bpf_insn{code=lda, k=K}  -> out_p(J,"ld", "M[~w]", [K]);
	#bpf_insn{code=ldxc, k=K} -> out_p(J,"ldx","#0x~.16b", [K]);
	#bpf_insn{code=ldx, k=K}  -> out_p(J,"ldx", "M[~w]", [K]);
	#bpf_insn{code=ldxl }     -> out_p(J,"ldx", "len", []);
	#bpf_insn{code=ldxmsh, k=K} -> out_p(J,"ldxb","4*([~w]&0xf)",[K]);
	#bpf_insn{code=sta,k=K}   -> out_p(J, "st", "M[~w]", [K]);
	#bpf_insn{code=stx,k=K}   -> out_p(J, "stx", "M[~w]", [K]);
	#bpf_insn{code=addk, k=K} -> out_p(J, "add", "#~w", [K]);
	#bpf_insn{code=subk, k=K} -> out_p(J, "sub", "#~w", [K]);
	#bpf_insn{code=mulk, k=K} -> out_p(J, "mul", "#~w", [K]);
	#bpf_insn{code=divk, k=K} -> out_p(J, "div", "#~w", [K]);
	#bpf_insn{code=andk, k=K} -> out_p(J, "and", "#0x~.16b", [K]);
	#bpf_insn{code=ork,  k=K} -> out_p(J, "or", "#0x~.16b", [K]);
	#bpf_insn{code=lshk, k=K} -> out_p(J, "lsh", "#~w", [K]);
	#bpf_insn{code=rshk, k=K} -> out_p(J, "rsh", "#~w", [K]);
	#bpf_insn{code=addx}      -> out_p(J, "add", "x", []);
	#bpf_insn{code=subx}      -> out_p(J, "sub", "x", []);
	#bpf_insn{code=mulx}      -> out_p(J, "mul", "x", []);
	#bpf_insn{code=divx}      -> out_p(J, "div", "x", []);
	#bpf_insn{code=andx}      -> out_p(J, "and", "x", []);
	#bpf_insn{code=orx}       -> out_p(J, "or", "x", []);
	#bpf_insn{code=lshx}      -> out_p(J, "lsh", "x", []);
	#bpf_insn{code=rshx}      -> out_p(J, "rsh", "x", []);
	#bpf_insn{code=neg}       -> out_p(J, "neg", "", []);
	#bpf_insn{code=jmp,k=K}   -> out_p(J, "jmp", "#0x~.16b", [J+1+K]);
	#bpf_insn{code=jgtk,k=K}  -> out_pj(J, "jgt", "#0x~.16b", [K],I);
	#bpf_insn{code=jgek,k=K}  -> out_pj(J, "jge", "#0x~.16b", [K],I);
	#bpf_insn{code=jeqk,k=K}  -> out_pj(J, "jeq", "#0x~.16b", [K],I);
	#bpf_insn{code=jsetk,k=K} -> out_pj(J, "jset", "#0x~.16b", [K],I);
	#bpf_insn{code=jgtx}      -> out_pj(J, "jgt", "x", [], I);
	#bpf_insn{code=jgex}      -> out_pj(J, "jge", "x", [], I);
	#bpf_insn{code=jeqx}      -> out_pj(J, "jeq", "x", [], I);
	#bpf_insn{code=jsetx}     -> out_pj(J, "jset", "x", [], I);
	#bpf_insn{code=reta}      -> out_p(J, "ret", "", []);
	#bpf_insn{code=retk,k=K}  -> out_p(J, "ret", "#~w", [K]);
	#bpf_insn{code=tax}       -> out_p(J, "tax", "", []);
	#bpf_insn{code=txa}       -> out_p(J, "txa", "", [])
    end.

out_p(J, Mnemonic, Fmt, Args) ->
    A = io_lib:format(Fmt, Args),
    io:format("(~.3.0w) ~-10s~s\n", [J,Mnemonic,A]).

out_pj(J, Mnemonic, Fmt, Args, I) ->
    A = io_lib:format(Fmt, Args),
    io:format("(~.3.0w) ~-10s~-18sjt ~w jf ~w\n", 
	      [J,Mnemonic,A,J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]).
%%
%% Valudate BPF 
%%
validate(Prog) when is_tuple(Prog) ->
    validate_(Prog, 1).

validate_(Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case class(I) of
	{jmp,true,k} ->
	    J1 = J + 1,
	    if I#bpf_insn.jt =/= 0 -> {error, {invalid,J,jt_none_zero}};
	       I#bpf_insn.jf =/= 0 -> {error, {invalid,J,jt_none_zero}};
	       J1 + I#bpf_insn.k > tuple_size(Prog) ->
		    {error, {invalid,J,jump_out_of_range}};
	       true -> validate_(Prog, J1)
	    end;
	{jmp,_Cond,_R}  ->
	    J1 = J+1,
	    if J1+I#bpf_insn.jt > tuple_size(Prog) -> 
		    {error, {invalid,J,jt_out_of_range}};
	       J1+I#bpf_insn.jf > tuple_size(Prog) -> 
		    {error, {invalid,J,jf_out_of_range}};
	       true -> validate_(Prog, J1)
	    end;
	{st,_Src,{m,K}}  -> 
	    if I#bpf_insn.jt =/= 0 -> {error, {invalid,J,jt_none_zero}};
	       I#bpf_insn.jf =/= 0 -> {error, {invalid,J,jf_none_zero}};
	       K < 0    -> {error, {invalid,J,k_out_of_range}};
	       K >= ?BPF_MEMWORDS -> {error,{invalid,J,k_out_of_range}};
	       true -> validate_(Prog, J+1)
	    end;
	{ld,_Dst,{m,K}} -> 
	    if I#bpf_insn.jt =/= 0 -> {error, {invalid,J,jt_none_zero}};
	       I#bpf_insn.jf =/= 0 -> {error, {invalid,J,jf_none_zero}};
	       K < 0    -> {error, {invalid,J,k_out_of_range}};
	       K >= ?BPF_MEMWORDS -> {error,{invalid,J,k_out_of_range}};
	       true -> validate_(Prog, J+1)
	    end;
	_ -> 
	    if I#bpf_insn.jt =/= 0 -> {error, {invalid,J,jt_none_zero}};
	       I#bpf_insn.jf =/= 0 -> {error, {invalid,J,jf_none_zero}};
	       true -> validate_(Prog, J+1)
	    end
    end;
validate_(Prog, J) when J =:= tuple_size(Prog) + 1 ->
    Prog.

%%
%% Optimise basic blocks
%%
optimise_bl(Bs) when is_record(Bs,bpf_bs) ->
    optimise_bl_(Bs, 1).

optimise_bl_(Bs, I) when I>?MAX_OPTIMISE ->
    io:format("Looping optimiser (I>~w)\n", [?MAX_OPTIMISE]),
    print_bs(Bs);
optimise_bl_(Bs, I) ->
    ?info("OPTIMISE: ~w\n", [I]),
    L = [fun remove_ld/1,
	 fun remove_st/1,
	 fun remove_multiple_jmp/1,
	 fun normalise_return/1,
	 fun remove_unreach/1,
	 fun constant_propagation/1,
	 fun bitfield_jmp/1,
	 fun remove_unreach/1,
	 %% fun print_bs/1, 
	 fun constant_path/1
	],
    Bs1 = optimise_list_(L, Bs#bpf_bs { changed = 0 }),
    if Bs1#bpf_bs.changed =:= 0 ->
	    print_bs(Bs1);
       true ->
	    optimise_bl_(Bs1, I+1)
    end.

optimise_list_([F|Fs], Bs) ->
    Bs1 = F(Bs),
    optimise_list_(Fs, Bs1);
optimise_list_([], Bs) ->
    Bs.

%% remove duplicate/unnecessary ld M[K] instructions or a sta
remove_ld(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_ld\n", []),
    bs_map_block(
      fun(B) ->B#bpf_block { insns=remove_ld_bl_(B#bpf_block.insns)} end,
      Bs).

%% M[k] = A, A=M[k]  =>  M[k] = A
remove_ld_bl_([I1=#bpf_insn { code=sta, k=K}, #bpf_insn {code=lda,k=K}|Is]) ->
    remove_ld_bl_([I1|Is]);
%% A=X, M[k]=A  =>  A=X, M[k]=X ; not that A=X must be kept!
remove_ld_bl_([I1=#bpf_insn { code=txa }, #bpf_insn {code=sta,k=K}|Is]) ->
    [I1 | remove_ld_bl_([#bpf_insn {code=stx,k=K}| Is])];

%% M[k]=A,X=M[k] =>  M[k]=A, X=A ; not that A=X must be kept!
remove_ld_bl_([I1=#bpf_insn {code=sta,k=K},_I2=#bpf_insn { code=ldx,k=K}|Is]) ->
    ?debug("REMOVE: ~w\n", [_I2]),
    [I1 | remove_ld_bl_([#bpf_insn {code=tax}| Is])];

%% M[k] = A, <opA>, A=M[k]  => M[k]=A [<opA]
remove_ld_bl_([I1=#bpf_insn{code=sta,k=K},I2,_I3=#bpf_insn{code=lda,k=K}|Is]) ->
    case class(I2) of
	{alu,_,_}    -> %% ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,a,x}   -> %% ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,x,a}   -> %% remove I3 since X is update to A
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{st,a,{k,K}} -> %% I1 = I2 remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,_,_}     -> %% just remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);	    
	{ld,x,_}     ->
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_}     -> %% A=<...>  A is reloaded in I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
%% M[k]=X, INSN, X=M[k]  => M[k]=X, INSN
remove_ld_bl_([I1=#bpf_insn{code=stx,k=K},I2,_I3=#bpf_insn{code=ldx,k=K}|Is]) ->
    case class(I2) of
	{alu,_,_} ->   %% A += <...>  do not update X remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,a,x} ->  %% A=X remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,x,a} ->  %% X=A ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,{k,K}} -> %% I1=I2, duplicate, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,_} ->     %% remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_} ->     %% A=<..>, keep x is not updated
	    remove_ld_bl_([I1,I2|Is]);
	{ld,x,_}     -> %% X=<..>  X is reloaded in I3 
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
remove_ld_bl_([I|Is]) ->
    [I|remove_ld_bl_(Is)];
remove_ld_bl_([]) ->
    [].

%%
%% remove unnecessary sta|stx instructions (see OPTIMISE.md)
%%
remove_st(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_st\n", []),
    bs_map_block(fun(B) -> remove_st_bl_(B, Bs) end, Bs).

remove_st_bl_(B, Bs) ->
    B#bpf_block { insns = remove_st_bl__(B#bpf_block.insns, B, Bs) }.

remove_st_bl__([I | Is], B, Bs) ->
    case is_referenced_st(I, Is, B, Bs) of
	false ->
	    ?debug("REMOVE: ~w\n", [I]),
	    remove_st_bl__(Is, B, Bs);
	true ->
	    [I | remove_st_bl__(Is, B, Bs)]
    end;
remove_st_bl__([], _B, _Bs) ->
    [].

%% check if a st / lda / ldx / tax / txa can be removed
is_referenced_st(I, Is, B, Bs) ->
    case class(I) of
	{st,_,{m,K}} ->
	    is_referenced_mk(K,Is,B,Bs);
	{ld,a,_} ->
	    is_referenced_a(Is,B,Bs);
	{ld,x,_} ->
	    is_referenced_x(Is,B,Bs);
	{alu,_,_} ->
	    is_referenced_a(Is,B,Bs);
	{misc,a,_} -> %% (txa A=X)
	    is_referenced_a(Is,B,Bs);
	{misc,x,_} -> %% (tax X=A)
	    is_referenced_x(Is,B,Bs);
	_ ->
	    true
    end.

%% check if M[K] is referenced (or killed)
is_referenced_mk(K, Is, B, Bs) ->
    loop_insns(
      fun(J,_Acc) ->
	      case class(J) of
		  {ld,_,{m,K}} ->
		      %% reference is found, keep instruction!
		      {ok,true};
		  {st,_,{m,K}} ->
		      %% reference is killed, check backtrack branches
		      {skip,false};
		  _ ->
		      %% move on
		      {next,false}
	      end
      end, false, Is, B, Bs).

%% check if A is referenced (or killed)
is_referenced_aj(As, Bs) ->
    is_referenced_a([], As, undefined, Bs).

is_referenced_a(Is,B,Bs) ->
    is_referenced_a(Is, [], B, Bs).
    
is_referenced_a(Is,As,B,Bs) ->
    loop_insns(
      fun(J,_Acc) ->
	      case class(J) of
		  {alu,_,_} -> %% A is referenced
		      {ok,true};
		  {st,a,_} ->  %% A is referenced
		      {ok,true};
		  {jmp,true,_} ->
		      {next,false};
		  {jmp,_Cmp,_R} -> %% A is referenced
		      {ok,true};
		  {ret,a} ->       %% A is referenced
		      {ok,true};
		  {misc,_,a} ->    %% A is referenced (tax)
		      {ok,true};
		  {misc,a,_} ->    %% A is killed (txa)
		      {skip,false};
		  {ld,a,_} ->
		      %% reference is killed, check backtrack branches
		      {skip,false};
		  _ ->
		      %% move on
		      {next,false}
	      end
      end, false, Is, As, B, Bs).

%% check if X is referenced (or killed)
is_referenced_x(Is,B,Bs) ->
    loop_insns(
      fun(J,_Acc) ->
	      case class(J) of
		  {alu,_,x} -> %% X is referenced
		      {ok,true};
		  {st,x,_} -> %% X is referenced
		      {ok,true};
		  {jmp,true,_} ->
		      {next,false};
		  {jmp,_Cmp,x} -> %% X is referenced
		      {ok,true};
		  {misc,_,x} -> %% X is referenced (txa)
		      {ok,true};
		  {ld,a,{px,_,_}} -> %% X is referenced
		      {ok,true};
		  {misc,x,_} ->    %% X is killed (tax)
		      {skip,false};
		  {ld,x,_} ->
		      %% X is killed, check other branches
		      {skip,false};
		  _ ->
		      %% move on
		      {next,false}
	      end
      end, false, Is, B, Bs).
    
%%
%% iterate through all instructions (including next)
%% tracing the code path (depth first)
%%
loop_insns(Fun, Acc, Is, B, Bs) ->
    loop_insns_(Fun, Acc, Is++[B#bpf_block.next],[],B,Bs,sets:new()).

loop_insns(Fun, Acc, Is, As, undefined, Bs) ->
    loop_insns_(Fun, Acc, Is,As,undefined,Bs,sets:new());
loop_insns(Fun, Acc, Is, As, B, Bs) ->
    loop_insns_(Fun, Acc, Is++[B#bpf_block.next],As,B,Bs,sets:new()).
    

loop_insns_(Fun,Acc,[I|Is],As,B,Bs,Vs) ->
    case Fun(I, Acc) of
	{ok, Acc1} -> 
	    Acc1;
	{skip,Acc1} ->
	    loop_insns_(Fun,Acc1,[],As,undefined,Bs,Vs);
	{next,Acc1} -> 
	    loop_insns_(Fun,Acc1,Is,As,B,Bs,Vs)
    end;
loop_insns_(Fun,Acc,[],As,B,Bs,Vs) ->
    As1 = if B =:= undefined ->
		  As;
	     true -> 
		  As ++ get_fanout(B#bpf_block.next)
	  end,
    case As1 of
	[A|As2] ->
	    case sets:is_element(A, Vs) of
		true ->
		    loop_insns_(Fun,Acc,[],As2,undefined,Bs,Vs);
		false ->
		    B1 = bs_get_block(A,Bs),
		    loop_insns_(Fun, Acc,
				B1#bpf_block.insns++[B1#bpf_block.next],
				As2, B1, Bs, sets:add_element(A,Vs))
	    end;
	[] ->
	    Acc
    end.

%%
%% Find bitfield & optimise jumps: (see OPTIMISE.md)
%%
bitfield_jmp(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: bitfield_jmp\n", []),
    bs_fold_block(fun(B,Bsi) -> bitfield_jmp_bl_(B, Bsi) end, Bs, Bs).

bitfield_jmp_bl_(B, Bs) ->
    case reverse(B#bpf_block.insns) of
	[#bpf_insn{ code=andk, k=1 }, #bpf_insn{ code=rshk, k=K } | Is] ->
	    case B#bpf_block.next of
		N = #bpf_insn { code=jgtk, k=0 } ->
		    ?info("Optimisation bitfield 6.a\n", []),
		    case is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED\n", []),
			    Bs;
			false ->
			    ?debug(" UPDATED\n", []),
			    N1 = N#bpf_insn { code=jsetk, k=(1 bsl K) },
			    B1 = B#bpf_block { insns=reverse(Is),
					       next = N1},
			    bs_set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;
	[#bpf_insn{ code=andk, k=Km } | Is] ->
	    case B#bpf_block.next of
		#bpf_insn { code=jeqk, k=Km, jt=L1, jf=L3 } ->
		    Bt = bs_get_block(L1,Bs),
		    case {Bt#bpf_block.insns,Bt#bpf_block.next} of
			{[],N1=#bpf_insn { code=jsetk, k=Kl, jt=L2, jf=L3} } ->
			    ?info("Optimisation bitfield 6.f\n", []),
			    case is_referenced_aj([L2,L3],Bs) of
				true ->
				    ?debug(" REFERENCED\n",[]),
				    Bs;
				false ->
				    ?debug(" UPDATED\n",[]),
				    Kn = Km bor Kl,
				    I1=#bpf_insn {code=andk, k=Kn},
				    N2 = N1#bpf_insn { code=jeqk, k=Kn },
				    B1 = B#bpf_block { insns=reverse([I1|Is]),
						       next = N2},
				    bs_set_block(B1, Bs)
			    end;
			_ ->
			    Bs
		    end;

		N = #bpf_insn { code=jgtk, k=0 } ->
		    ?info("Optimisation bitfield 6.b\n", []),
		    case is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED\n",[]),
			    Bs;
			false ->
			    ?debug(" UPDATED\n",[]),
			    N1 = N#bpf_insn { code=jsetk, k=Km },
			    B1 = B#bpf_block { insns=reverse(Is),
					       next = N1},
			    bs_set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;

	[#bpf_insn{ code=rshk, k=K } | Is] ->
	    case B#bpf_block.next of
		N = #bpf_insn { code=jsetk, k=1 } ->
		    ?info("Optimisation bitfield 6.c\n", []),
		    case is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED\n",[]),
			    Bs;
			false ->
			    ?debug(" UPDATED\n",[]),
			    N1 = N#bpf_insn { code=jsetk, k=(1 bsl K) },
			    B1 = B#bpf_block { insns=reverse(Is),
					       next = N1},
			    bs_set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;
	Is ->
	    case B#bpf_block.next of
		#bpf_insn { code=jsetk,k=Km,jt=L2,jf=L1} ->
		    Bf = bs_get_block(L1,Bs),
		    Bt = bs_get_block(L2,Bs),
		    case {Bf#bpf_block.insns,Bf#bpf_block.next} of
			{[],#bpf_insn { code=jsetk,k=Kl,jt=L2,jf=L3} } ->
			    ?info("Optimisation bitfield 6.d\n", []),
			    Kn = Km bor Kl,
			    N=#bpf_insn { code=jsetk,jt=L2,jf=L3,k=Kn},
			    bs_set_next(B#bpf_block.label, N, Bs);
			_ ->
			    case {Bt#bpf_block.insns,Bt#bpf_block.next} of
				{[],#bpf_insn {code=jsetk,k=Kl,jt=L3,jf=L1} } ->
				    ?info("Optimisation bitfield 6.e\n", []),
				    Kn = Km bor Kl,
				    I=#bpf_insn { code=andk,k=Kn},
				    N=#bpf_insn { code=jeqk,jt=L3,jf=L1,k=Kn},
				    B1=B#bpf_block { insns=reverse([I|Is]),
						     next=N },
				    bs_set_block(B1, Bs);
				_ ->
				    Bs
			    end
		    end;
		_ ->
		    Bs
	    end
    end.

%%
%% remove multiple unconditional jumps 
%%
remove_multiple_jmp(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_multiple_jmp\n", []),
    bs_fold_block(fun(B,BsI) -> remove_multiple_jmp_bl_(B, BsI) end, Bs, Bs).

%% 1 - fanout is unconditional jump 
%%     there are no instructions in the target block, move
%%     the next instruction (and fanout) to B  (unlink)
%% 2 - conditional Tf or Tf labels jump to an empty block
%%     with unconditional jump, then jump to that block
remove_multiple_jmp_bl_(B, Bs) ->
    case get_fanout(B#bpf_block.next) of
	[J] ->
	    Bj = bs_get_block(J, Bs),
	    if Bj#bpf_block.insns =:= [] ->
		    ?debug("REPLACE: ~w with ~w\n",
			   [B#bpf_block.next,Bj#bpf_block.next]),
		    bs_set_next(B#bpf_block.label, Bj#bpf_block.next, Bs);
	       true ->
		    Bs
	    end;
	[Jt,Jf] ->
	    Bt = bs_get_block(Jt, Bs),
	    Jt2 = case {Bt#bpf_block.insns, get_fanout(Bt#bpf_block.next)} of
		      {[], [Jt1]} -> Jt1;
		      {[],[Jt1,_Jf1]} ->
			  %% Same condition on the landing site?
			  case {B#bpf_block.next,Bt#bpf_block.next} of
			      {#bpf_insn { code=jgtk, k=0},
			       #bpf_insn { code=jgtk, k=0}} -> Jt1;
			      _ -> Jt
			  end;
		      _ -> Jt
		  end,
	    Bf = bs_get_block(Jf, Bs),
	    Jf2 = case {Bf#bpf_block.insns, get_fanout(Bf#bpf_block.next)} of
		      {[], [Jf1]} -> Jf1;
		      {[],[_Jt1,Jf1]} ->
			  %% Same condition on the landing site?
			  case {B#bpf_block.next,Bf#bpf_block.next} of
			      {#bpf_insn { code=jgtk, k=0},
			       #bpf_insn { code=jgtk, k=0}} -> Jf1;
			      _ -> Jf
			  end;
		      _ -> Jf
		  end,
	    if Jt =/= Jt2; Jf =/= Jf2 ->
		    Next = B#bpf_block.next,
		    Next1 = Next#bpf_insn { jt=Jt2, jf=Jf2 },
		    ?debug("REPLACE: ~w with ~w\n", [Next,Next1]),
		    bs_set_next(B#bpf_block.label, Next1, Bs);
	       true ->
		    Bs
	    end;
	_ ->
	    Bs
    end.

%%
%% Normalize return blocks (block with only a return statement)
%%
normalise_return(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: normalise_return\n", []),
    LKs0 =
	bs_fold_block(
	  fun(B,Acc) when B#bpf_block.insns =:= [] ->
		  N = B#bpf_block.next,
		  case N#bpf_insn.code of
		      retk -> [{N#bpf_insn.k,B#bpf_block.label} | Acc];
		      reta -> [{a,B#bpf_block.label} | Acc];
		      _ -> Acc
		  end;
	     (_, Acc) ->
		  Acc
	  end, [], Bs),
    LKs = lists:reverse(lists:keysort(2, LKs0)),
    bs_map_block(
	fun(B) ->
		N = B#bpf_block.next,
		N1 =
		    case class(N) of
			{jmp,true,_} ->
			    J = find_normal_label(N#bpf_insn.k,LKs),
			    N#bpf_insn { k = J };
			{jmp,_Cond,_} ->
			    Jt = find_normal_label(N#bpf_insn.jt,LKs),
			    Jf = find_normal_label(N#bpf_insn.jf,LKs),
			    N#bpf_insn { jt=Jt, jf=Jf };
			{ret,_} ->
			    N
		    end,
		B#bpf_block { next=N1 }
	end, Bs).
		
    
find_normal_label(K, LKs) ->
    case lists:keyfind(K, 2, LKs) of
	false -> K;
	{V,K} ->
	    {V,K1} =lists:keyfind(V,1,LKs),  %% find first
	    K1
    end.

%%
%% Remove unreachable blocks
%%
remove_unreach(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_unreach\n", []),
    remove_unreach_([Bs#bpf_bs.init], Bs, sets:new()).

remove_unreach_([I|Is], Bs, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    remove_unreach_(Is, Bs, Vs);
	false ->
	    B = bs_get_block(I, Bs),
	    remove_unreach_(Is++get_fanout(B#bpf_block.next), 
			    Bs, sets:add_element(I,Vs))
    end;
remove_unreach_([], Bs, Vs) ->
    %% Remove blocks not visited
    All = bs_get_labels(Bs),
    Remove = All -- sets:to_list(Vs),
    lists:foldl(fun(I,Bsi) -> 
			?debug("REMOVE BLOCK: ~w\n", [I]),
			bs_del_block(I, Bsi) end, 
		Bs, Remove).

%%
%% Constant propagation
%%     for each node 
%%     recursive calculate the constants for all
%%     fan in. 
%%     Calculate the union of all constants
%%     and then proceed to calculate the block 
%%
constant_propagation(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: constant_propagation\n", []),
    Ls = bs_get_labels(Bs),
    {Bs1,_,_} = constant_propagation_(Ls, Bs, dict:new(), sets:new()),
    Bs1.

%% Ds is dict of dicts of block calculations, Vs is set of visited nodes
constant_propagation_([I|Is], Bs, Ds, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    constant_propagation_(Is,Bs,Ds,Vs);
	false ->
	    B0 = bs_get_block(I, Bs),
	    FanIn = bs_get_fanin(I, Bs),
	    Vs1 = sets:add_element(I,Vs),
	    {Bs1,Ds1,Vs2} = constant_propagation_(FanIn,Bs,Ds,Vs1),
	    D0 = constant_intersect_(FanIn,Ds1),
	    {B1,D1} = constant_eval_(B0,D0),
	    Ds2 = dict:store(I,D1,Ds1),
	    constant_propagation_(Is, bs_set_block(B1,Bs1),Ds2,Vs2)
    end;
constant_propagation_([],Bs,Ds,Vs) ->
    {Bs,Ds,Vs}.

%% constant propagate instructions in block B given values in
%% dictionary D
constant_eval_(B, D) ->
    ?debug("EVAL: ~w D=~w\n", [B#bpf_block.label, dict:to_list(D)]),
    {Is,D1} = constant_ev_(B#bpf_block.insns,[],D),
    {Next,NCond} = constant_ev_jmp_(B#bpf_block.next, D1),
    if Next =/= B#bpf_block.next ->
	    ?debug("Replaced: ~w with ~w\n", [B#bpf_block.next, Next]);
       true -> ok
    end,
    {B#bpf_block { insns = Is, next=Next, ncond=NCond }, D1}.

%%
%% Constant path
%%
constant_path(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: constant_path\n", []),
    Ls = bs_get_labels(Bs),
    {Bs1,_} = constant_path_(Ls, Bs, sets:new()),
    Bs1.

%% Ds is dict of dicts of block calculations, Vs is set of visited nodes
constant_path_([I|Is], Bs, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    constant_path_(Is,Bs,Vs);
	false ->
	    B0 = bs_get_block(I, Bs),
	    FanIn = bs_get_fanin(I, Bs),
	    Vs1 = sets:add_element(I,Vs),
	    {Bs1,Vs2} = constant_path_(FanIn,Bs,Vs1),
	    {B1,Bs2} = constant_block_(B0,Bs1),
	    constant_path_(Is, bs_set_block(B1,Bs2),Vs2)
    end;
constant_path_([],Bs,Vs) ->
    {Bs,Vs}.

constant_block_(B, Bs) ->
    %% check all paths to this block to see if they may be patched
    Next = B#bpf_block.next,
    case class(Next) of
	{jmp,true,_} ->
	    {B, Bs};
	{jmp,_,_} ->
	    %% check if ncond is patch among parents and update
	    L = B#bpf_block.label,
	    Cond = B#bpf_block.ncond,
	    case compare_all_conds_(bs_get_fanin(L, Bs), L, Cond, Bs) of
		undefined ->
		    %% try forward patch
		    Bf = bs_get_block(Next#bpf_insn.jf, Bs),
		    case compare_cond(Cond, Bf#bpf_block.ncond) of
			true ->
			    Nf = Bf#bpf_block.next,
			    Next1 = Next#bpf_insn { jf=Nf#bpf_insn.jf },
			    B1 = B#bpf_block { next = Next1 },
			    {B1, Bs};
			false ->
			    {B,Bs};  %% hmm?
			undefined ->
			    Bt = bs_get_block(Next#bpf_insn.jt, Bs),
			    case compare_cond(Cond, Bt#bpf_block.ncond) of
				true ->
				    Nt = Bt#bpf_block.next,
				    Next1 = Next#bpf_insn { jt=Nt#bpf_insn.jt },
				    B1 = B#bpf_block { next = Next1 },
				    {B1, Bs};
				false ->
				    {B,Bs};  %% hmm?
				undefined ->
				    {B,Bs}
			    end
		    end;
		true ->
		    Next1 = #bpf_insn { code=jmp, k = Next#bpf_insn.jt },
		    B1 = B#bpf_block { next = Next1, ncond = true },
		    {B1, Bs};
		false ->
		    Next1 = #bpf_insn { code=jmp, k = Next#bpf_insn.jf },
		    B1 = B#bpf_block { next = Next1, ncond = true },
		    {B1, Bs}
	    end;
	_ ->
	    {B, Bs}
    end.
		    
%%
%% given label L check generate a list of all parent paths
%% to check if Cond is true or false or undefined
%% Cond must either be true in all parent or false in all parents
%% or it is undefined
compare_cond_(L, L0, Cond, Bs) ->
    B = bs_get_block(L, Bs),
    %% first seach grand parents
    case compare_all_conds_(bs_get_fanin(B#bpf_block.label, Bs), L, Cond, Bs) of
	undefined ->
	    Next = B#bpf_block.next,
	    Negate = (Next#bpf_insn.jf == L0),
	    compare_cond(Cond, B#bpf_block.ncond, Negate);
	true  -> true;
	false -> false
    end.

compare_all_conds_([], _L0, _Cond, _Bs) ->
    undefined;
compare_all_conds_([L|Ls], L0, Cond, Bs) ->
    case compare_cond_(L, L0, Cond, Bs) of
	true -> compare_all_conds_(Ls, L0, Cond, true, Bs);
	false -> compare_all_conds_(Ls, L0, Cond, false, Bs);
	undefined -> undefined
    end.

compare_all_conds_([], _L0, _Cond,  Value, _Bs) ->
    Value;
compare_all_conds_([L|Ls], L0, Cond, Value, Bs) ->
    case compare_cond_(L, L0, Cond, Bs) of
	Value -> compare_all_conds_(Ls, L0, Cond, Value, Bs);
	_ -> undefined
    end.

compare_cond(A, B, true) ->
    case compare_cond(A, B) of
	true -> false;
	false -> true;
	undefined -> undefined
    end;
compare_cond(A, B, false) ->
    compare_cond(A, B).

compare_cond(true, _A) -> undefined;
compare_cond(_A, true) -> undefined;
compare_cond(A, A) -> true;
compare_cond({'>',A,B}, {'>',B,A}) -> false;
compare_cond(_, _) -> undefined.
    

constant_ev_([I|Is],Js,D) ->
    K = I#bpf_insn.k,
    case I#bpf_insn.code of
	ldaw ->
	    constant_set_(I, Is, Js, a, {p,K,4}, D);
	ldah ->
	    constant_set_(I, Is, Js, a, {p,K,2}, D);
	ldab ->
	    constant_set_(I, Is, Js, a, {p,K,1}, D);
	ldiw ->
	    case get_pind(K,4,D) of
		{p,X,K,N} when is_integer(X) ->
		    K1 = X+K,
		    I1 = I#bpf_insn{code=ldaw, k=K1},
		    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_set_(I1,Is,Js,a,{p,K1,N},D);
		P ->
		    constant_set_(I, Is, Js, a, P, D)
	    end;
	ldih ->
	    case get_pind(K,2,D) of
		{p,X,K,N} when is_integer(X) ->
		    K1 = X+K,
		    I1 = I#bpf_insn{code=ldah, k=K1},
		    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_set_(I1,Is,Js,a,{p,K1,N},D);
		P ->
		    constant_set_(I, Is, Js, a, P, D)
	    end;
	ldib ->
	    case get_pind(K,1,D) of
		{p,X,K,N} when is_integer(X) ->
		    K1 = X+K,
		    I1 = I#bpf_insn{code=ldab, k=K1},
		    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_set_(I1,Is,Js,a,{p,K1,N},D);
		P ->
		    constant_set_(I, Is, Js, a, P, D)
	    end;
	ldl  ->
	    constant_set_(I, Is, Js, a, {l,4}, D);
	ldc  ->
	    constant_set_(I, Is, Js, a, K, D);
	lda  ->
	    case get_reg({m,K},D) of
		K1 when is_integer(K1) ->
		    I1 = I#bpf_insn{code=ldc,k=K1},
		    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_ev_(Is,[I1|Js],set_reg(a,K1,D));
		R ->
		    constant_ev_(Is,[I|Js], set_reg(a,R,D))
	    end;
	ldxc -> 
	    constant_set_(I, Is, Js, x, K, D);
	ldx ->
	    %% fixme check if x already is loaded with the value
	    case get_reg({m,K}, D) of
		K1 when is_integer(K1) ->
		    I1 = I#bpf_insn{code=ldxc,k=K1},
		    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_ev_(Is,[I1|Js], set_reg(x,K1,D));
		R ->
		    constant_ev_(Is,[I|Js], set_reg(x,R,D))
	    end;
	ldxl ->
	    constant_set_(I, Is, Js, x, {l,4}, D);
	ldxmsh -> 
	    Msh = {'*',4,{'&',{p,K,1},15}},
	    constant_set_(I, Is, Js, x, Msh, D);
	sta  ->
	    constant_ev_(Is, [I|Js], set_reg({m,K},get_reg(a,D),D));
	stx  ->
	    constant_ev_(Is, [I|Js], set_reg({m,K},get_reg(x,D),D));
	addk -> eval_op_(I, Is, Js, D, '+',  a, K, ldc, addk);
	subk -> eval_op_(I, Is, Js, D, '-',  a, K, ldc, subk);
	mulk -> eval_op_(I, Is, Js, D, '*',  a, K, ldc, mulk);
	divk -> eval_op_(I, Is, Js, D, '/',  a, K, ldc, divk);
	andk -> eval_op_(I, Is, Js, D, '&',  a, K, ldc, andk);
	ork  -> eval_op_(I, Is, Js, D, '|',  a, K, ldc, ork);
	lshk -> eval_op_(I, Is, Js, D, '<<',  a, K, ldc, lshk);
	rshk -> eval_op_(I, Is, Js, D, '>>',  a, K, ldc, rshk); 
	addx -> eval_op_(I, Is, Js, D, '+',  a, x, ldc, addk);
	subx -> eval_op_(I, Is, Js, D, '-',  a, x, ldc, subk);
	mulx -> eval_op_(I, Is, Js, D, '*',  a, x, ldc, mulk);
	divx -> eval_op_(I, Is, Js, D, '/',  a, x, ldc, divk);
	andx -> eval_op_(I, Is, Js, D, '&',  a, x, ldc, andk);
	orx  -> eval_op_(I, Is, Js, D, '|',  a, x, ldc, ork);
	lshx -> eval_op_(I, Is, Js, D, '<<', a, x, ldc, lshk);
	rshx -> eval_op_(I, Is, Js, D, '>>', a, x, ldc, rshk);
	neg  -> eval_op_(I, Is, Js, D, '-',  a, ldc);
	tax  -> eval_op_(I, Is, Js, D, '=',  x, a, ldxc, ldxc);
	txa  -> eval_op_(I, Is, Js, D, '=',  a, x, ldc, ldc)
    end;
constant_ev_([], Js, D) ->
    {reverse(Js), D}.

%% set register to value if not already set, then remove the instruction
constant_set_(I, Is, Js, R, V, D) ->
    case get_ureg(R, D) of
	undefined -> %% no value defined
	    constant_ev_(Is,[I|Js], set_reg(R, V, D));
	V -> %% value already loaded
	    ?debug("REMOVE: ~w, value ~w already set\n", [I,V]),
	    constant_ev_(Is,Js,D);
	_ ->
	    constant_ev_(Is,[I|Js], set_reg(R, V, D))
    end.

constant_ev_jmp_(I, D) ->
    case I#bpf_insn.code of
	retk -> {I,true};
	reta -> {I,true};
	jmp  -> {I,true};
	jgtk  -> constant_ev_jmpk_(I,'>',D);
	jgek  -> constant_ev_jmpk_(I,'>=',D);
	jeqk  -> constant_ev_jmpk_(I,'==',D);
	jsetk -> constant_ev_jmpk_(I,'&',D);
	jgtx  -> constant_ev_jmpx_(I,'>', jgtk,D);
	jgex  -> constant_ev_jmpx_(I,'>=',jgek,D);
	jeqx  -> constant_ev_jmpx_(I,'==',jeqk,D);
	jsetx -> constant_ev_jmpx_(I,'&',jsetk,D)
    end.

comp_('>',A,B) when is_integer(A), is_integer(B) -> A > B;
comp_('>=',A,B) when is_integer(A), is_integer(B) -> A >= B;
comp_('==',A,B) when is_integer(A), is_integer(B) -> A =:= B;
comp_('==',A,B) -> match_(A,B);
comp_('&',A,B) when is_integer(A), is_integer(B) -> (A band B) =/= 0;
comp_(_,_,_) -> false.

match_(A,B) ->
    match_(A,B,"").

match_(A,B,I) ->
    ?debug("~sMATCH ~w, ~w\n", [I,A,B]),
    R = match__(A,B,["  ",I]),
    ?debug("~s=~w\n", [I,R]),
    R.

match__(undefined,_,_) -> false;
match__(_,undefined,_) -> false;
match__(A,A,_) -> true;
match__({'+',A,B},{'+',C,D},I) ->
    (match_(A,C,I) andalso match_(B,D,I)) 
	orelse
	  (match_(A,D,I) andalso match_(B,C,I));
match__({'*',A,B},{'*',C,D},I) ->
    (match_(A,C,I) andalso match_(B,D,I)) 
	orelse
	  (match_(A,D,I) andalso match_(B,C,I));
match__(_, _,_) ->
    false.

constant_ev_jmpk_(I=#bpf_insn { jt=Jt, jf=Jf, k=K },Op,D) ->
    A = get_reg(a, D),
    case comp_(Op,A,K) of
	true  -> 
	    {#bpf_insn { code=jmp, k=Jt }, true};
	false ->
	    if is_integer(A) ->
		    {#bpf_insn { code=jmp, k=Jf }, true};
	       true ->
		    {I, {Op,A,K}}
	    end
    end.

constant_ev_jmpx_(I=#bpf_insn { jt=Jt, jf=Jf },Op,JmpK,D) ->
    A = get_reg(a, D),
    X = get_reg(x, D),
    case comp_(Op,A,X) of
	true ->
	    {#bpf_insn { code=jmp, k=Jt },true};
	false ->
	    if is_integer(A), is_integer(X) ->
		    {#bpf_insn { code=jmp, k=Jf },true};
	       is_integer(X) ->
		    {I#bpf_insn { code=JmpK, k=X },true};
	       true ->
		    {I,{Op,A,X}}
	    end
    end.


%% translate operation depending on outcome of calculation
eval_op_(I, Is, Js, D, Op, R, A, Op1, Op2) ->
    case eval_reg(Op,R,A,D) of
	K1 when is_integer(K1) ->
	    D1 = set_reg(R,K1,D),
	    I1 = I#bpf_insn { code=Op1, k=K1},
	    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
	    constant_ev_(Is, [I1|Js], D1);
	V1 ->
	    D1 = set_reg(R,V1,D),
	    case get_reg(A, D1) of
		K0 when is_integer(K0) ->
		    I1 = I#bpf_insn { code=Op2, k=K0},
		    %% Try remove noops, more?
		    case Op2 of
			subk when K0 =:= 0 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			addk when K0 =:= 0 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			mulk when K0 =:= 1 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			divk when K0 =:= 1 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			lshk when K0 =:= 0 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			rshk when K0 =:= 0 ->
			    ?debug("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			_ ->
			    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
			    constant_ev_(Is, [I1|Js], D1)
		    end;
		_ ->
		    constant_ev_(Is, [I|Js], D1)
	    end
    end.

eval_op_(I, Is, Js, D, Op, R, OpK) ->
    case eval_reg(Op,R,D) of
	K1 when is_integer(K1) ->
	    D1 = set_reg(R,K1,D),
	    I1 = I#bpf_insn { code=OpK, k=K1},
	    ?debug("CHANGE: ~w TO ~w\n", [I, I1]),
	    constant_ev_(Is, [I1|Js], D1);
	V1 ->
	    D1 = set_reg(R,V1,D),
	    constant_ev_(Is, [I|Js], D1)
    end.


set_reg(R, undefined, D) ->
    dict:erase(R, D);
set_reg(R, V, D) ->
    %% io:format("set_reg: ~w = ~w\n", [R, V]),
    dict:store(R, V, D).

%% get the value of {p,X,K,N}  (K is constant, N=1,2|4)
get_pind(K,N,D) ->
    case get_ureg(x,D) of
	undefined ->
	    ?warning("get_reg: ~w = undefined!!\n", [x]),
	    undefined;
	X -> {p,X,K,N}
    end.

get_reg(R, D) ->
    case get_ureg(R, D) of
	undefined ->
	    ?warning("get_reg: ~w = undefined!!\n", [R]),
	    undefined;
	V -> V
    end.

%% caller knows that R may be undefined, 
get_ureg(R, _D) when is_integer(R) -> R;
get_ureg(R, D) ->
    case dict:find(R, D) of
	{ok,V} ->  V;
	error -> undefined
    end.
    
    

eval_reg(Op,A,B,D) ->
    V = eval_reg_(Op, get_reg(A,D), get_reg(B,D)),
    V.

eval_reg(Op,A,D) ->
    V = eval_reg_(Op, get_reg(A,D)),
    V.    

eval_reg_('*', 0, _) -> 0;
eval_reg_('*', _, 0) -> 0;
eval_reg_('*', 1, X) -> X;
eval_reg_('*', X, 1) -> X;
eval_reg_('+', 0, X) -> X;
eval_reg_('+', X, 0) -> X;
eval_reg_('/', _, 0) -> undefined;
eval_reg_('/', X, 1) -> X;
eval_reg_('-', X, 0) -> X;
eval_reg_('=', _, X) -> X;
%% add some more here
eval_reg_('-', 0, X) when is_integer(X) -> ?uint32(-X);
%% regular calculation
eval_reg_(_Op, undefined, _) -> undefined;
eval_reg_(_Op, _, undefined) -> undefined;

eval_reg_('+', A, B) when is_integer(A), is_integer(B) -> ?uint32(A+B);
eval_reg_('+', A, B) -> {'+',A,B};
eval_reg_('-', A, B) when is_integer(A), is_integer(B) -> ?uint32(A-B);
eval_reg_('-', A, B) -> {'-',A,B};
eval_reg_('*', A, B) when is_integer(A), is_integer(B) -> ?uint32(A*B);
eval_reg_('*', A, B) -> {'*',A,B};
eval_reg_('/', A, B) when is_integer(A), is_integer(B) ->  A div B;
eval_reg_('/', A, B) -> {'/',A,B};
eval_reg_('&', A, B) when is_integer(A), is_integer(B) -> A band B;
eval_reg_('&', A, B) -> {'&',A,B};
eval_reg_('|', A, B) when is_integer(A), is_integer(B) -> A bor B;
eval_reg_('|', A, B) -> {'|',A,B};
eval_reg_('<<', A, B) when is_integer(A), is_integer(B) -> ?uint32(A bsl B);
eval_reg_('<<', A, B) -> {'<<',A,B};
eval_reg_('>>', A, B) when is_integer(A), is_integer(B) -> A bsr B;
eval_reg_('>>', A, B) -> {'>>',A,B}.

eval_reg_('-', A) when is_integer(A) -> ?uint32(-A);
eval_reg_('-', undefined) -> undefined;
eval_reg_('-', A) -> {'-', A}.

constant_intersect_([I], Ds) ->
    dict:fetch(I, Ds);
constant_intersect_([I|Is], Ds) ->
    Di = constant_intersect_(Is, Ds),
    dict_intersect(dict:fetch(I, Ds), Di);
constant_intersect_([], _) ->
    dict:new().
    
%% all keys present in both A and B are 
dict_intersect(A, B) ->
    dict:fold(
      fun(K,Va,C) ->
	      case dict:is_key(K,B) of
		  true ->
		      Vb = dict:fetch(K,B),
		      Vc = merge_value(Va,Vb),
		      dict:store(K, Vc, C);
		  false ->
		      C
	      end
      end, dict:new(), A).

merge_value({union,As},{union,Bs}) ->
    {union,As++Bs};
merge_value({union,As}, B) ->
    {union,As++[B]};
merge_value(A, {union,Bs}) ->
    {union,[A]++Bs};
merge_value(A, B) ->
    case match_(A,B) of
	true  -> A;
	false -> {union,[A,B]}
    end.
	    
%%
%% Create basic block representation from tuple program.
%% The labels will initially be the address of the first
%% instruction in the block.
%% Label 1 must always be present and represent the first
%% instruction.
%%
prog_to_bs(Prog) when is_tuple(Prog) ->
    Map = build_target_map_(Prog),
    prog_to_bs_(Prog, 1, Map, 1, [], bs_new(1)).

prog_to_bs_(Prog, J, Map, A, Acc, Bs) when J =< tuple_size(Prog) ->
    I = element(J, Prog),
    case class(I) of
	{jmp,true,_} ->
	    L = J+1+I#bpf_insn.k, %% absolute jump address!
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = I#bpf_insn { k = L }},
	    prog_to_bs_(Prog,J+1,Map,J+1,[],bs_add_block(B,Bs));
	{jmp,_,_} ->
	    Lt = J+1+I#bpf_insn.jt,
	    Lf = J+1+I#bpf_insn.jf,
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I#bpf_insn { jt=Lt, jf=Lf }},
	    prog_to_bs_(Prog,J+1,Map,J+1,[],bs_add_block(B,Bs));
	{ret,_} ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I},
	    prog_to_bs_(Prog,J+1,Map,J+1,[],bs_add_block(B,Bs));
	_ ->
	    case element(J,Map) of
		true ->
		    if A =:= J ->
			    prog_to_bs_(Prog,J+1,Map,A,[I|Acc],Bs);
		       true ->
			    B = #bpf_block { label = A,
					     insns = reverse(Acc),
					     next = #bpf_insn { code=jmp,
								k=J }},
			    prog_to_bs_(Prog,J+1,Map,J,[I],bs_add_block(B,Bs))
		    end;
		false ->
		    prog_to_bs_(Prog,J+1,Map,A,[I|Acc],Bs)
	    end
    end;
prog_to_bs_(_Prog, _J, _Map, A, Acc, Bs) ->
    if Acc =:= [] ->
	    Bs;
       true ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = reject()
			   },
	    bs_add_block(B, Bs)
    end.

%%
%% Convert a basic block representation into a program
%%
%% topological sort, 1 must be present and be less than all other nodes
%%
bs_to_prog(Bs) when is_record(Bs,bpf_bs) ->
    Bs1 = topsort(Bs),
    to_prog_(Bs1,1,[],[]).

%% first map blocks into positions
to_prog_([B|Bs], Pos, Ins, Map) ->
    N = length(B#bpf_block.insns),
    case get_fanout(B#bpf_block.next) of
	[L1] when (hd(Bs))#bpf_block.label =:= L1 ->
	    %% do not add dummy jump
	    to_prog_(Bs, Pos+N,
		     [B#bpf_block.insns | Ins],
		     [{B#bpf_block.label,Pos}|Map]);
	_ ->
	    to_prog_(Bs, Pos+N+1,
			[B#bpf_block.next, B#bpf_block.insns | Ins],
			[{B#bpf_block.label,Pos}|Map])
    end;
to_prog_([],_Pos,Ins,Map) ->
    Ins1 = lists:flatten(reverse(Ins)),
    list_to_tuple(prog_map_(Ins1, 1, Map)).

%% now assign the relative jumps
prog_map_([I|Is], J, Map) ->
    case class(I) of
	{jmp,true,_} ->
	    {_,A} = lists:keyfind(I#bpf_insn.k, 1, Map),
	    [I#bpf_insn { k=A-J-1 } | prog_map_(Is, J+1, Map)];
	{jmp,_,_} ->
	    {_,At} = lists:keyfind(I#bpf_insn.jt, 1, Map),
	    {_,Af} = lists:keyfind(I#bpf_insn.jf, 1, Map),
	    [I#bpf_insn { jt=At-J-1, jf=Af-J-1 } | prog_map_(Is, J+1, Map)];
	_ ->
	    [I|prog_map_(Is,J+1,Map)]
    end;
prog_map_([], _J, _Map) ->
    [].

%%
%% Topological sort the basic block DAG.
%% return a list of topsorted blocks
%%
-spec topsort(Bs::#bpf_bs{}) -> [#bpf_block{}].

topsort(Bs) when is_record(Bs,bpf_bs) ->
    topsort_([Bs#bpf_bs.init], Bs, [], sets:new()).

topsort_([{add,N,Bn}|Q], Bs, L, Vs) ->
    topsort_(Q, Bs, [Bn|L], sets:add_element(N,Vs));
topsort_([N|Q], Bs, L, Vs) ->
    case sets:is_element(N, Vs) of
	true ->
	    topsort_(Q, Bs, L, Vs);
	false ->
	    Bn = bs_get_block(N,Bs),
	    topsort_(get_fanout(Bn#bpf_block.next) ++
			 [{add,N,Bn}]++Q, Bs, L, Vs)
    end;
topsort_([], _Bs, L, _Vs) ->
    L.


%%
%% Create a map of positions that are reachable from a jump
%% Map[J] == true iff instruction at position J can be
%% reached directly through a jump instruction
%%
build_target_map_(Prog) ->
    build_target_map_(Prog,1,[]).

%% build a map of instruction numbers
build_target_map_(Prog,J,Acc) when J =< tuple_size(Prog) ->
    I = element(J, Prog),
    case class(I) of
	{jmp,true,k} ->
	    J1 = J+1+I#bpf_insn.k,  %% jump destination
	    build_target_map_(Prog,J+1,[J1|Acc]);
	{jmp,_Cond,_R} ->
	    J1 = J+1+I#bpf_insn.jt,
	    J2 = J+1+I#bpf_insn.jf,
	    build_target_map_(Prog,J+1,[J1,J2|Acc]);
	_ ->
	    build_target_map_(Prog,J+1,Acc)
    end;
build_target_map_(Prog,_J,Acc) ->
    S = sets:from_list(Acc),
    list_to_tuple([ sets:is_element(I,S) || 
		      I <- lists:seq(1, tuple_size(Prog))]).

%%
%% Execute BPF (debugging and runtime support when missing in kernel or library)
%%
exec(Prog, P) when is_tuple(Prog), is_binary(P) ->
    exec0(Prog, 1, 0, 0, P, erlang:make_tuple(?BPF_MEMWORDS, 0)).

exec(Prog,Pc,A,X,P,M) when is_tuple(Prog),
			   is_integer(Pc), Pc >= 1, Pc =< tuple_size(Prog),
			   is_integer(A), is_integer(X),
			   is_binary(P),
			   is_tuple(M) ->
    exec0(Prog,Pc,A,X,P,M).

exec0(Prog,_Pc,_A,_X,_P,_M) when tuple_size(Prog) =:= 0 ->
    0;
exec0(Prog,Pc,A,X,P,M) ->
    try exec_(Prog,Pc,A,X,P,M) of
	V -> V
    catch
	throw:packet_index -> 0;
	throw:mem_index -> 0
    end.



-define(ldmem(K,M),
	if (K) >= 0, (K) < tuple_size((M)) ->
		element((K)+1, (M));
	   true -> 
		?error("mem index out of bounds, ~w\n", [(K)]),
		throw(mem_index)
	end).

-define(stmem(K,V,M),
	if (K) >= 0, K < tuple_size((M)) ->
		setelement((K)+1,(M),?uint32((V)));
	   true -> 
		?error("mem index out of bounds, ~w\n", [(K)]),
		throw(mem_index)
	end).


exec_(Prog,Pc,A,X,P,M) ->
    #bpf_insn{code=Code,k=K} = I = element(Pc,Prog),
    ?debug("~w: ~p, A=~w,X=~w,M=~w\n", [Pc, I,A,X,M]),
    Pc1 = Pc+1,
    case Code of
	ldaw -> exec_(Prog, Pc1, ld_(P,K,32), X, P, M);
	ldah -> exec_(Prog, Pc1, ld_(P,K,16), X, P, M);
	ldab -> exec_(Prog, Pc1, ld_(P,K,8), X, P, M);
	ldiw -> exec_(Prog, Pc1, ld_(P,X+K,32), X, P, M);
	ldih -> exec_(Prog, Pc1, ld_(P,X+K,16), X, P, M);
	ldib -> exec_(Prog, Pc1, ld_(P,X+K,8), X, P, M);
	ldl  -> exec_(Prog, Pc1, byte_size(P), X, P, M);
	ldc  -> exec_(Prog, Pc1, K, X, P, M);
	lda  -> exec_(Prog, Pc1, ?ldmem(K,M), X, P, M);
	ldxc  -> exec_(Prog, Pc1, A, K, P, M);
	ldx   -> exec_(Prog, Pc1, A, ?ldmem(K,M), P, M);
	ldxl  -> exec_(Prog, Pc1, A, byte_size(P), P, M);
	ldxmsh -> exec_(Prog, Pc1, A, 4*(ld_(P,K,8) band 16#f),P,M);
	sta  -> exec_(Prog, Pc1, A, X, P, ?stmem(K,A,M));
	stx  -> exec_(Prog, Pc1, A, X, P, ?stmem(K,X,M));
	addk -> exec_(Prog, Pc1, ?uint32(A + K), X, P, M);
	subk -> exec_(Prog, Pc1, ?uint32(A - K), X, P, M);
	mulk -> exec_(Prog, Pc1, ?uint32(A * K), X, P, M);
	divk -> exec_(Prog, Pc1, A div K, X, P, M);
	andk -> exec_(Prog, Pc1, A band K, X, P, M);
	ork  -> exec_(Prog, Pc1, A bor K, X, P, M);
	lshk -> exec_(Prog, Pc1, ?uint32(A bsl K), X, P, M);
	rshk -> exec_(Prog, Pc1, A bsr K, X, P, M);
	addx -> exec_(Prog, Pc1, ?uint32(A + X), X, P, M);
	subx -> exec_(Prog, Pc1, ?uint32(A - X), X, P, M);
	mulx -> exec_(Prog, Pc1, ?uint32(A * X), X, P, M);
	divx -> exec_(Prog, Pc1, A div X, X, P, M);
	andx -> exec_(Prog, Pc1, A band X, X, P, M);
	orx  -> exec_(Prog, Pc1, A bor X, X, P, M);
	lshx -> exec_(Prog, Pc1, ?uint32(A bsl X), X, P, M);
	rshx -> exec_(Prog, Pc1, A bsr X, X, P, M);
	neg  -> exec_(Prog, Pc1, ?uint32(-A), X, P, M);
	
	jmp  -> exec_(Prog, Pc1+K, A, X, P, M);
	jgtk -> jump_(Prog, Pc1, (A > K), I, A, X, P, M);
	jgek -> jump_(Prog, Pc1, (A >= K), I, A, X, P, M);
	jeqk -> jump_(Prog, Pc1, (A =:= K), I, A, X, P, M);
	jsetk -> jump_(Prog, Pc1, (A band K) =/= 0, I, A, X, P, M);
	jgtx -> jump_(Prog, Pc1, (A > X), I, A, X, P, M);
	jgex -> jump_(Prog, Pc1, (A >= X), I, A, X, P, M);
	jeqx -> jump_(Prog, Pc1, (A =:= X), I, A, X, P, M);
	jsetx -> jump_(Prog, Pc1, (A band X) =/= 0, I, A, X, P, M);
	reta -> A;
	retk -> K;
	tax -> exec_(Prog, Pc1, A, A, P, M);
	txa -> exec_(Prog, Pc1, X, X, P, M)
    end.

jump_(Prog, Pc, true, I, A, X, P, M) ->
    exec_(Prog, Pc+I#bpf_insn.jt, A, X, P, M);
jump_(Prog, Pc, false, I, A, X, P, M) ->
    exec_(Prog, Pc+I#bpf_insn.jf, A, X, P, M).


ld_(P,K,Size) ->
    case P of
	<<_:K/binary, LDV:Size, _/binary>> ->
	    LDV;
	_ ->
	    ?error("packet offset ~w:~w out of bounds, len=~w\n", 
		   [(K),(Size),byte_size((P))]),
	    throw(packet_index)
    end.


%% (nested) list of code, default to reject
build_program(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,reject()])),
    build_(Prog).

%% (nested) list of code returning ackumulator value
build_programa(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,return()])),
    build_(Prog).

%% build expression, A>0 => accept, A=0 => reject
build_programx(Expr) ->
    X = expr(Expr, 0),
    Prog = list_to_tuple(lists:flatten([X,
					#bpf_insn { code=jgtk, k=0,
						    jt=0, jf=1 },
					accept(),
					reject()])),
    build_(Prog).

%% build expression list return the number of the expression
%% that match or 0 if no match
build_program_list(ExprList) ->
    Prog = lists:flatten(make_program_list(ExprList,0,1)),
    build_(list_to_tuple(Prog)).

make_program_list([Expr],Offs,I) ->
    [expr(Expr,Offs),
     #bpf_insn { code=jgtk, k=0, jt=0, jf=1 },
     return(I),
     reject()];
make_program_list([Expr|ExprList],Offs,I) ->
    Prog1 = make_program_list(ExprList,Offs,I+1),
    [expr(Expr,Offs),
     #bpf_insn { code=jgtk, k=0, jt=0, jf=1 },
     return(I),
     Prog1].


build_(Prog0) ->
    io:format("program 0\n"),
    io:format("---------\n"),
    Bs0 = prog_to_bs(Prog0),
    print_bs(Bs0),
    case validate(Prog0) of
	E={error,_} -> E;
	_ ->
	    Bs1 = optimise_bl(Bs0),
	    Prog1 = bs_to_prog(Bs1),
	    io:format("the program\n"),
	    io:format("-----------\n"),
	    print(Prog1),
	    case validate(Prog1) of
		E={error,_} -> E;
		_ -> Prog1
	    end
    end.

accept() ->
    #bpf_insn{code=retk, k=?uint32(-1) }.

reject() ->
    #bpf_insn{code=retk, k=?uint32(0) }.

return(K) ->
    #bpf_insn{code=retk, k=?uint32(K) }.

return() ->
    #bpf_insn{code=reta }.

nop() ->
    #bpf_insn{code=jmp,k=0}.

%% expression support:
%% calculate the expression into accumulator
%% use memory as a stack, then optimise stack use

expr(Expr) -> expr(Expr, 0).
    
expr(Expr,Offs) ->
    {_Sp,X} = expr_(Expr,Offs,?BPF_MEMWORDS),
    X.

expr_(Attr,Offs,Sp) when is_atom(Attr) -> attr(atom_to_list(Attr),Offs,Sp);
expr_(Attr,Offs,Sp) when is_list(Attr) -> attr(Attr,Offs,Sp);
expr_(K,_Offs,Sp) when is_integer(K) -> iexpr(K,0,Sp);
expr_({p,K,4},Offs,Sp)    -> pexpr(ldaw,K,Offs,Sp);
expr_({p,K,2},Offs,Sp)    -> pexpr(ldah,K,Offs,Sp);
expr_({p,K,1},Offs,Sp)    -> pexpr(ldab,K,Offs,Sp);
expr_({p,0,K,4},Offs,Sp)  -> pexpr(ldaw,K,Offs,Sp);
expr_({p,0,K,2},Offs,Sp)  -> pexpr(ldah,K,Offs,Sp);
expr_({p,0,K,1},Offs,Sp)  -> pexpr(ldab,K,Offs,Sp);
expr_({p,X,K,4},Offs,Sp)  -> pexpr(ldiw,X,K,Offs,Sp);
expr_({p,X,K,2},Offs,Sp)  -> pexpr(ldih,X,K,Offs,Sp);
expr_({p,X,K,1},Offs,Sp)  -> pexpr(ldib,X,K,Offs,Sp);

expr_({'+',Ax,Bx},Offs,Sp) -> bop(addx,Ax,Bx,Offs,Sp);
expr_({'+',[]},Offs,Sp)    -> expr_(0,Offs,Sp);
expr_({'+',As},Offs,Sp) when is_list(As) -> 
    expr_(expr_rs('+',lists:reverse(As)),Offs,Sp);

expr_({'-',Ax,Bx},Offs,Sp) -> bop(subx,Ax,Bx,Offs,Sp);
expr_({'*',Ax,Bx},Offs,Sp) -> bop(mulx,Ax,Bx,Offs,Sp);
expr_({'/',Ax,Bx},Offs,Sp) -> bop(divx,Ax,Bx,Offs,Sp);
expr_({'&',Ax,Bx},Offs,Sp) -> bop(andx,Ax,Bx,Offs,Sp);
expr_({'|',Ax,Bx},Offs,Sp) -> bop(orx,Ax,Bx,Offs,Sp);
expr_({'<<',Ax,Bx},Offs,Sp) -> bop(lshx,Ax,Bx,Offs,Sp);
expr_({'>>',Ax,Bx},Offs,Sp) -> bop(rshx,Ax,Bx,Offs,Sp);
expr_({'-',Ax},Offs,Sp)    -> uop(neg,Ax,Offs,Sp);
expr_({'>',Ax,Bx},Offs,Sp)  -> rop(jgtx,Ax,Bx,Offs,Sp);
expr_({'>=',Ax,Bx},Offs,Sp) -> rop(jgex,Ax,Bx,Offs,Sp);
expr_({'==',Ax,Bx},Offs,Sp) -> rop(jeqx,Ax,Bx,Offs,Sp);
expr_({'<',Ax,Bx},Offs,Sp)  -> rop(jgtx,Bx,Ax,Offs,Sp);
expr_({'<=',Ax,Bx},Offs,Sp) -> rop(jgex,Bx,Ax,Offs,Sp);
expr_({'!=',Ax,Bx},Offs,Sp) -> lbool({'-',Ax,Bx},Offs,Sp);
expr_({'!',Ax},Offs,Sp)     -> lnot(Ax,Offs,Sp);
expr_({'&&',Ax,Bx},Offs,Sp) -> land(Ax,Bx,Offs,Sp);
expr_({'&&',[]},Offs,Sp)    -> expr_(true,Offs,Sp);
expr_({'&&',As},Offs,Sp) when is_list(As) -> expr_(expr_rs('&&',As),Offs,Sp);

expr_({'||',Ax,Bx},Offs,Sp) -> lor(Ax,Bx,Offs,Sp);
expr_({'||',[]},Offs,Sp)    -> expr_(false,Offs,Sp);
expr_({'||',As},Offs,Sp) when is_list(As) -> expr_(expr_rs('||',As),Offs,Sp);

expr_({'memeq',Ax,Data},Offs,Sp) when is_binary(Data) ->
    expr_memeq(Ax, Data, Offs, Sp);
expr_({'memeq',Ax,Mask,Data},Offs,Sp) when is_binary(Data) ->
    expr_memeq(Ax, Mask, Data, Offs, Sp);
expr_({'memge',Ax,Data},Offs,Sp) when is_binary(Data) ->
    expr_memge(Ax, Data, Offs, Sp);
expr_({'memle',Ax,Data},Offs,Sp) when is_binary(Data) ->
    expr_memle(Ax, Data, Offs, Sp).

expr_memeq(Ax,Data,Offs,Sp) ->
    %% Ax is an index expression
    {Sp1,Ac} = expr_(Ax,Offs,Sp),
    %% Move A to X
    J = 2*((byte_size(Data)+3) div 4),  %% number of instructions (memeq)
    {Sp1,
     [ Ac,    %% A = index
       #bpf_insn { code=tax },          %% X=A index register
       memeq(Data, 0, J),               %% Compare bytes P[X+0...X+N-1]
       #bpf_insn { code=ldc, k=1 },     %% Jt: A=1
       #bpf_insn { code=jmp, k=1 },     %% skip
       #bpf_insn { code=ldc, k=0 },     %% Jf: A=0
       #bpf_insn { code=sta, k=Sp1 }    %% Store bool value
     ]}.

%% memeq with mask
expr_memeq(Ax,Mask,Data,Offs,Sp) ->
    {Sp1,Ac} = expr_(Ax,Offs,Sp),
    %% Move A to X
    J = 3*((byte_size(Data)+3) div 4),  %% number of instructions in memeq
    {Sp1,
     [ Ac,    %% A = index
       #bpf_insn { code=tax },          %% X=A index register
       memeq(Data, Mask, 0, J-1),       %% Compare bytes P[X+0...X+N-1]
       #bpf_insn { code=ldc, k=1 },     %% Jt: A=1
       #bpf_insn { code=jmp, k=1 },     %% skip
       #bpf_insn { code=ldc, k=0 },     %% Jf: A=0
       #bpf_insn { code=sta, k=Sp1 }    %% Store bool value
     ]}.

expr_memge(Ax,Data,Offs,Sp) ->    
    %% Ax is an index expression
    {Sp1,Ac} = expr_(Ax,Offs,Sp),
    %% Move A to X
    J = 3*((byte_size(Data)+3) div 4),  %% number of instructions (memge)
    {Sp1,
     [ Ac,    %% A = index
       #bpf_insn { code=tax },          %% X=A index register
       memge(Data, 0, J-3, J-1),        %% Compare bytes P[X+0...X+N-1]
       #bpf_insn { code=ldc, k=1 },     %% Jt: A=1
       #bpf_insn { code=jmp, k=1 },     %% skip
       #bpf_insn { code=ldc, k=0 },     %% Jf: A=0
       #bpf_insn { code=sta, k=Sp1 }    %% Store bool value
     ]}.

expr_memle(Ax,Data,Offs,Sp) ->    
    %% Ax is an index expression
    {Sp1,Ac} = expr_(Ax,Offs,Sp),
    %% Move A to X
    J = 3*((byte_size(Data)+3) div 4),  %% number of instructions (memge)
    {Sp1,
     [ Ac,    %% A = index
       #bpf_insn { code=tax },          %% X=A index register
       memle(Data, 0, J-3, J-1),        %% Compare bytes P[X+0...X+N-1]
       #bpf_insn { code=ldc, k=1 },     %% Jt: A=1
       #bpf_insn { code=jmp, k=1 },     %% skip
       #bpf_insn { code=ldc, k=0 },     %% Jf: A=0
       #bpf_insn { code=sta, k=Sp1 }    %% Store bool value
     ]}.

%% compare binary data Bin[i] == P[x+i]
memeq(<<X:32,Rest/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldiw, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memeq(Rest, I+4, Jf-2)];
memeq(<<X:16,Rest/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldih, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memeq(Rest, I+2, Jf-2)];
memeq(<<X:8>>, I, Jf) ->
    [ #bpf_insn { code=ldib, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf }];
memeq(<<>>, _I, _Jf) ->
    [].

%% memeq with mask: Bin[i] = P[x+i] & Mask[i]
memeq(<<X:32,Bin/binary>>,<<M:32,Mask/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldiw, k=I },
      #bpf_insn { code=andk, k=M },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memeq(Bin, Mask, I+4, Jf-3)];
memeq(<<X:16,Bin/binary>>,<<M:16,Mask/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldih, k=I },
      #bpf_insn { code=andk, k=M },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memeq(Bin, Mask, I+2, Jf-3)];
memeq(<<X:8>>,<<M:8>>, I, Jf) ->
    [ #bpf_insn { code=ldib, k=I },
      #bpf_insn { code=andk, k=M },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf }];
memeq(<<>>, <<>>, _I, _Jf) ->
    [].

%% compare binary data Bin[i] >= P[x+i]
memge(<<X:32,Rest/binary>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldiw, k=I },
      #bpf_insn { code=jgtk, k=X, jt=Jt+1, jf=0 },
      #bpf_insn { code=jeqk, k=X, jt=0,  jf=Jf } |
      memge(Rest, I+4, Jt-3, Jf-3)];
memge(<<X:16,Rest/binary>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldih, k=I },
      #bpf_insn { code=jgtk, k=X, jt=Jt+1, jf=0 },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memge(Rest, I+2, Jt-3, Jf-3)];
memge(<<X:8>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldib, k=I },
      #bpf_insn { code=jgtk, k=X, jt=Jt+1, jf=0 },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf }];
memge(<<>>, _I, _Jt, _Jf) ->
    [].

%% compare binary data Bin[i] <= P[x+i]
memle(<<X:32,Rest/binary>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldiw, k=I },
      #bpf_insn { code=jgek, k=X, jt=0, jf=Jt+1 }, %% jlt!!
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memle(Rest, I+4, Jt-3, Jf-3)];
memle(<<X:16,Rest/binary>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldih, k=I },
      #bpf_insn { code=jgek, k=X, jt=0, jf=Jt+1 }, %% jlt!!
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      memle(Rest, I+2, Jt-3, Jf-3)];
memle(<<X:8>>, I, Jt, Jf) ->
    [ #bpf_insn { code=ldib, k=I },
      #bpf_insn { code=jgek, k=X, jt=0, jf=Jt+1 }, %% jlt!!
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf }];
memle(<<>>, _I, _Jt, _Jf) ->
    [].



expr_rs(_Op,[A]) -> A;
expr_rs(Op,[A|As]) -> {Op,A,expr_rs(Op,As)}.

expr_ls(Op, [A|As]) -> expr_ls(Op, As, A).

expr_ls(_Op, [], A) -> A;
expr_ls(Op, [B|As], A) -> expr_ls(Op, As, {Op,A,B}).

    
%% test if "true" == (jgtk > 0)

%% Ax && Bx
land("vlan",Bx,Offs,Sp0) ->
    land("eth.type.vlan", Bx, Offs, Offs+?VLAN,Sp0);
land(Ax,Bx,Offs,Sp0) ->
    land(Ax,Bx,Offs,Offs,Sp0).

land(Ax,Bx,OffsA,OffsB,Sp0) ->
    {Sp1,Ac} = expr_(Ax,OffsA,Sp0),
    {Sp1,Bc} = expr_(Bx,OffsB,Sp0),
    LBc = code_length(Bc),
    {Sp1,
     [Ac,
      #bpf_insn { code=lda, k=Sp1 },  %% A = exp(Ax)
      #bpf_insn { code=jgtk, k=0, jt=0, jf=LBc+5 },
      Bc,
      #bpf_insn { code=lda, k=Sp1 },  %% A = exp(Bx)
      #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
      #bpf_insn { code=ldc, k=1 },        %% Jt: A=1
      #bpf_insn { code=jmp, k=1 },        %% skip
      #bpf_insn { code=ldc, k=0 },        %% Jf: A=0
      #bpf_insn { code=sta, k=Sp1 }]}.

%% Ax || Bx
lor(Ax,Bx,Offs,Sp0) ->
    {Sp1,Ac} = expr_(Ax,Offs,Sp0),
    {Sp1,Bc} = expr_(Bx,Offs,Sp0),
    LBc = code_length(Bc),
    {Sp1,
     [Ac,
      #bpf_insn { code=lda, k=Sp1 },      %% A = exp(Ax)
      #bpf_insn { code=jgtk, k=0, jt=LBc+5, jf=0 },
      Bc,
      #bpf_insn { code=lda, k=Sp1 },      %% A = exp(Bx)
      #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
      #bpf_insn { code=ldc, k=1 },        %% true value A=1
      #bpf_insn { code=jmp, k=1 },        %% skip
      #bpf_insn { code=ldc, k=0 },        %% true value A=0
      #bpf_insn { code=sta, k=Sp1 }]}.

%% !Ax
lnot(Ax,Offs,Sp0) ->
    {Sp1,Ac} = expr_(Ax,Offs,Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },     %% A = exp(Ax)
	   #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
	   #bpf_insn { code=ldc, k=0 },        %% A=false
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=1 },        %% A=false
	   #bpf_insn { code=sta, k=Sp1 }]}.

%% !!Ax convert integer to boolean
lbool(Ax,Offs,Sp0) ->
    {Sp1,Ac} = expr_(Ax,Offs,Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },     %% A = exp(Ax)
	   #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
	   #bpf_insn { code=ldc, k=1 },        %% A=true
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=0 },        %% A=false
	   #bpf_insn { code=sta, k=Sp1 }]}.

rop(Jop,Ax,Bx,Offs,Sp0) ->
    {Sp1,Bc} = expr_(Bx,Offs,Sp0),
    {Sp2,Ac} = expr_(Ax,Offs,Sp1),
    {Sp1, [Bc,Ac,
	   #bpf_insn { code=ldx, k=Sp1 },  %% X = exp(Bx)
	   #bpf_insn { code=lda, k=Sp2 },  %% A = exp(Ax)
	   #bpf_insn { code=Jop, jt=0, jf=2 }, %% A <jop> X
	   #bpf_insn { code=ldc, k=1 },        %% true value A=1
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=0 },        %% true value A=0
	   #bpf_insn { code=sta, k=Sp1 }]}.

bop(Bop,Ax,Bx,Offs,Sp0) ->
    {Sp1,Bc} = expr_(Bx,Offs,Sp0),
    {Sp2,Ac} = expr_(Ax,Offs,Sp1),
    {Sp1, [Bc,Ac,
	   #bpf_insn { code=ldx, k=Sp1 },  %% X = exp(Bx)
	   #bpf_insn { code=lda, k=Sp2 },  %% A = exp(Ax)
	   #bpf_insn { code=Bop },        %% A = A <bop> X
	   #bpf_insn { code=sta, k=Sp1 }]}.

uop(Uop,Ax,Offs,Sp0) ->
    {Sp1,Ac} = expr_(Ax,Offs,Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },  %% A = exp(Ax)
	   #bpf_insn { code=Uop },         %% A = <uop> A
	   #bpf_insn { code=sta, k=Sp1 }]}.

iexpr(K,Offs,Sp0) when is_integer(K) ->
    Sp1 = Sp0-1,
    {Sp1, [#bpf_insn {code=ldc, k=K+Offs},
	   #bpf_insn {code=sta, k=Sp1}]}.

%% attribute expression
attr(Attr,Offs,Sp) ->
    case Attr of
	%% ethernet
	"eth["++Elem      -> vexpr_(Elem, ?OFFS_ETH, Offs, Sp);
	"eth.dst."++Addr  -> eth_address(Addr,?OFFS_ETH_DST,Offs,Sp);
	"eth.src."++Addr  -> eth_address(Addr,?OFFS_ETH_SRC,Offs,Sp);
	"eth.dst["++Elem  -> vexpr_(Elem,?OFFS_ETH_DST,Offs,Sp);
	"eth.src["++Elem  -> vexpr_(Elem,?OFFS_ETH_SRC,Offs,Sp);
	"eth.type"        -> expr_({p,?OFFS_ETH_TYPE,2},Offs,Sp);
	"eth.type."++Type -> eth_type(Type, Offs, Sp);
	"eth.data"        -> iexpr(?OFFS_ETH_DATA,Offs,Sp);
	"eth.data["++Elem -> vexpr_(Elem, ?OFFS_ETH_DATA, Offs, Sp);

	%% vlan
	"vlan.tpid" -> expr_({p,?OFFS_VLAN_TPID,2},Offs,Sp);
	"vlan.tci"  -> expr_({p,?OFFS_VLAN_TCI,2},Offs,Sp);
	"vlan.pcp"  -> expr_({'&',{'>>',{p,?OFFS_VLAN_TCI,2},13},7},Offs,Sp);
	"vlan.dei"  -> expr_({'&',{'>>',{p,?OFFS_VLAN_TCI,2},12},1},Offs,Sp);
	"vlan.vid"  -> expr_({'&',{p,?OFFS_VLAN_TCI,2}, 16#fff},Offs,Sp);
	"vlan."++Num when hd(Num)>=$0,hd(Num)=<$9 ->
	    expr_({'==', "vlan.vid", list_to_integer(Num)}, Offs, Sp);

	%% arp
	"arp.htype"   -> expr_({p,?OFFS_ARP_HTYPE,2},Offs,Sp);
	"arp.ptype"   -> expr_({p,?OFFS_ARP_PTYPE,2},Offs,Sp);
	"arp.halen"   -> expr_({p,?OFFS_ARP_HALEN,1},Offs,Sp);
	"arp.palen"   -> expr_({p,?OFFS_ARP_PALEN,1},Offs,Sp);
	"arp.op"      -> expr_({p,?OFFS_ARP_OP,2},Offs,Sp);

	"port."++PortStr -> %% currently ip/ipv6 other?
	    expr_({'||',
		   [{'&&',["eth.type.ip","ip.port."++PortStr]},
		    {'&&',["eth.type.ip6","ip6.port."++PortStr]}
		   ]}, Offs, Sp);

	%% ip
	"ip["++Elem  -> vexpr_(Elem, ?OFFS_IPV4, Offs, Sp);
	"ip.hlen"    -> pexpr(txa,{msh,?OFFS_IPV4_HLEN},0,Offs,Sp);
	"ip.diffsrv" -> expr_({p,?OFFS_IPV4_DSRV,1},Offs,Sp);
	"ip.len"     -> expr_({p,?OFFS_IPV4_LEN,2},Offs,Sp);
	"ip.id"      -> expr_({p,?OFFS_IPV4_ID,2},Offs,Sp);
	"ip.flag.df" -> expr_({'&',{'>>',{p,?OFFS_IPV4_FRAG,2},14},16#1},Offs,Sp);
	"ip.flag.mf" -> expr_({'&',{'>>',{p,?OFFS_IPV4_FRAG,2}, 13},16#1},Offs,Sp);
	"ip.frag" -> expr_({'&',{p,?OFFS_IPV4_FRAG,2},16#1FFF},Offs,Sp);
	"ip.ttl" -> expr_({p,?OFFS_IPV4_TTL,2},Offs,Sp);
	"ip.proto" -> expr_({p,?OFFS_IPV4_PROTO,1},Offs,Sp);
	"ip.proto."++Name -> ipv4_proto(Name,Offs,Sp);

	"ip.dst"   -> iexpr(?OFFS_IPV4_DST,Offs,Sp);
	"ip.src"   -> iexpr(?OFFS_IPV4_SRC,Offs,Sp);
	"ip.dst["++Elem -> vexpr_(Elem, ?OFFS_IPV4_DST, Offs, Sp);
	"ip.src["++Elem -> vexpr_(Elem, ?OFFS_IPV4_SRC, Offs, Sp);
	"ip.dst."++Addr -> ipv4_address(Addr,?OFFS_IPV4_DST,Offs,Sp);
	"ip.src."++Addr -> ipv4_address(Addr,?OFFS_IPV4_SRC,Offs,Sp);
	"ip.host."++Addr ->
	    expr_({'||', "ip.src."++Addr, "ip.dst."++Addr},Offs,Sp);
	"ip.port."++PortStr -> %% currently udp/tcp (add stcp)
	    expr_({'&&',
		   [{'||',["ip.proto.tcp","ip.proto.udp"]},
		    "ip.udp.port."++PortStr  %% udp & tcp has same offset
		   ]}, Offs, Sp);
	"ip.options" -> iexpr(?OFFS_IPV4_DATA,Offs,Sp);
	"ip.data"  -> expr_({'+',?OFFS_ETH_DATA,"ip.hlen"},Offs,Sp);
	"ip.data["++Elem -> xvexpr_(Elem, "ip.data", Offs, Sp);
	    
	%% ip6
	"ip6["++Elem  -> vexpr_(Elem, ?OFFS_IPV6, Offs, Sp);	
	"ip6.len"      -> expr_({p,?OFFS_IPV6_LEN,2},Offs,Sp);
	"ip6.next"     -> expr_({p,?OFFS_IPV6_NEXT,1},Offs,Sp);
	"ip6.proto"    -> expr_({p,?OFFS_IPV6_NEXT,1},Offs,Sp);
	"ip6.proto."++Name -> ipv6_proto(Name,Offs,Sp);
	"ip6.hopc"     -> expr_({p,?OFFS_IPV6_HOPC,1},Offs,Sp);
	"ip6.payload"  -> iexpr(?OFFS_IPV6_PAYLOAD,Offs,Sp);
	"ip6.data["++Elem -> vexpr_(Elem, ?OFFS_IPV6_PAYLOAD, Offs, Sp);

	%% different from ip since addresses do not fit in 32 bit
	"ip6.dst"      -> iexpr(?OFFS_IPV6_DST,Offs,Sp);
	"ip6.src"      -> iexpr(?OFFS_IPV6_SRC,Offs,Sp);
	"ip6.dst["++Elem -> vexpr_(Elem, ?OFFS_IPV6_DST, Offs, Sp);
	"ip6.src["++Elem -> vexpr_(Elem, ?OFFS_IPV6_SRC, Offs, Sp);
	"ip6.dst."++Addr -> ipv6_address(Addr,?OFFS_IPV6_DST,Offs,Sp);
	"ip6.src."++Addr -> ipv6_address(Addr,?OFFS_IPV6_SRC,Offs,Sp);
	"ip6.host."++Addr ->
	    expr_({'||', "ip6.src."++Addr, "ip6.dst."++Addr},Offs,Sp);
	"ip6.port."++PortStr -> %% currently udp/tcp (add stcp)
	    expr_({'&&',
		   [{'||',["ip6.proto.tcp","ip6.proto.udp"]},
		    "ip6.udp.port."++PortStr  %% udp & tcp has same offset
		   ]}, Offs, Sp);
	%% tcp/ip
	"ip.tcp" -> expr_("ip.data",Offs,Sp);
	"ip.tcp."++TcpAttr ->
	    tcp_attr("ip.data",
		     fun(Field,Size) ->
			     {p,{msh,?OFFS_IPV4_HLEN},?OFFS_ETH_DATA+Field,Size}
		     end,TcpAttr,Offs,Sp);
	
	%%  udp/ip
	"ip.udp" -> expr_("ip.data",Offs,Sp);
	"ip.udp."++UdpAttr ->
	    udp_attr("ip.data",
		     fun(Field,Size) ->
			     {p,{msh,?OFFS_IPV4_HLEN},?OFFS_ETH_DATA+Field,Size}
		     end,UdpAttr,Offs,Sp);

	%% tcp/ipv6
	"ip6.tcp" -> expr_("ip6.payload",Offs,Sp);
	"ip6.tcp."++TcpAttr ->
	    tcp_attr("ip6.tcp",
		     fun(Field,Size) ->
			     {p,?OFFS_IPV6_PAYLOAD+Field,Size}
		     end,TcpAttr,Offs,Sp);

	%% udp/ipv6
	"ip6.udp" -> expr_("ip6.payload",Offs,Sp);
	"ip6.udp."++UdpAttr ->
	    udp_attr("ip6.udp",
		     fun(Field,Size) ->
			     {p,?OFFS_IPV6_PAYLOAD+Field,Size}
		     end,UdpAttr,Offs,Sp)
    end.

%%
%% Handle name[  <num>|<expr>[:1|2|4]  ']'
%%
vexpr_(StrExpr, POffs, Offs, Sp) ->
    case string_split(StrExpr, ":") of
	[IExpr,NExpr] when NExpr=:="1]"; NExpr=:="2]"; NExpr=:="4]" ->
	    N = hd(NExpr)-$0,
	    I = list_to_integer(IExpr),
	    expr_({p,I,POffs,N}, Offs, Sp);
	[IExpr1] ->
	    [$]|IExpr2] = lists:reverse(IExpr1),
	    I = list_to_integer(lists:reverse(IExpr2)),
	    expr_({p,I,POffs,1}, Offs, Sp)
    end.

xvexpr_(StrExpr, XOffs, Offs, Sp) ->
    case string_split(StrExpr, ":") of
	[IExpr,NExpr] when NExpr=:="1]"; NExpr=:="2]"; NExpr=:="4]" ->
	    N = hd(NExpr)-$0,
	    I = list_to_integer(IExpr),
	    expr_({p,XOffs,I,N}, Offs, Sp);
	[IExpr1] ->
	    [$]|IExpr2] = lists:reverse(IExpr1),
	    I = list_to_integer(lists:reverse(IExpr2)),
	    expr_({p,XOffs,I,1}, Offs, Sp)
    end.

eth_type(Name, Offs, Sp) when is_list(Name) ->
    Type = 
	case Name of
	    "ip" -> ?ETHERTYPE_IP;
	    "ip6" -> ?ETHERTYPE_IPV6;
	    "arp"  -> ?ETHERTYPE_ARP;
	    "revarp" ->?ETHERTYPE_REVARP;
	    "vlan" -> ?ETHERTYPE_VLAN
	end,
    expr_({'==',{p,?OFFS_ETH_TYPE,2},Type},Offs,Sp).

ipv4_proto(Name,Offs,Sp) when is_list(Name) ->
    Proto = case Name of
		"tcp" -> ?IPPROTO_TCP;
		"udp" -> ?IPPROTO_UDP;
		"sctp" -> ?IPPROTO_SCTP;
		"icmp" -> ?IPPROTO_ICMP
	    end,
    expr_({'==',"ip.proto",Proto},Offs,Sp).

ipv6_proto(Name,Offs,Sp) when is_list(Name) ->
    Proto = case Name of
		"tcp" -> ?IPPROTO_TCP;
		"udp" -> ?IPPROTO_UDP;
		"sctp" -> ?IPPROTO_SCTP
	    end,
    expr_({'==',"ip6.proto",Proto},Offs,Sp).
%%
%% 11:22:33:44:55:66 
%% 11:22:33:44:55:66/16
%% 11:22:00:00:00:01..11:22:00:00:00:ff
%%
eth_address(Addr,IpOffs,Offs,Sp) ->
    case string_split(Addr, "..") of
	[A,B] ->
	    {ok,IA} = eth_address(A),
	    {ok,IB} = eth_address(B),
	    expr_({'&&',
		   {memge,IpOffs,eth(IA)},
		   {memle,IpOffs,eth(IB)}},Offs,Sp);
	_ ->
	    case string_split(Addr,"/") of
		[A,N] ->
		    {ok,IA} = eth_address(A),
		    Net = list_to_integer(N),
		    Mask = <<-1:Net,0:(48-Net)>>,
		    expr_({memeq,IpOffs,Mask,eth(IA)},Offs,Sp);
		[A] ->
		    {ok,IA} = eth_address(A),
		    expr_({memeq,IpOffs,eth(IA)},Offs,Sp)
	    end
    end.
	
%%
%%  1.2.3.4
%%  192.168.0.0/24
%%  192.168.0.2..192.168.0.10
%%
ipv4_address(Addr,IpOffs,Offs,Sp) ->
    case string_split(Addr, "..") of
	[A,B] ->
	    {ok,IA} = inet_parse:ipv4_address(A),
	    {ok,IB} = inet_parse:ipv4_address(B),
	    expr_({'&&',
		   {memge,IpOffs,ipv4(IA)},
		   {memle,IpOffs,ipv4(IB)}},Offs,Sp);
	_ ->
	    case string_split(Addr,"/") of
		[A,N] ->
		    {ok,IA} = inet_parse:ipv4_address(A),
		    Net = list_to_integer(N),
		    Mask = <<-1:Net,0:(32-Net)>>,
		    expr_({memeq,IpOffs,Mask,ipv4(IA)},Offs,Sp);
		[A] ->
		    {ok,IA} = inet_parse:ipv4_address(A),
		    expr_({memeq,IpOffs,ipv4(IA)},Offs,Sp)
	    end
    end.

%%
%% 1:2:3:4:5:6:7:8
%% 1:2:3:4:5:6:7:8..1:2:3:4:5:6:7:1000
%% 1:2:3:4:0:0:0:0/64
%%
ipv6_address(Addr,IpOffs,Offs,Sp) ->
    case string_split(Addr, "..") of
	[A,B] ->
	    {ok,IA} = inet_parse:ipv6_address(A),
	    {ok,IB} = inet_parse:ipv6_address(B),
	    expr_({'&&',
		   {memge,IpOffs,ipv6(IA)},
		   {memle,IpOffs,ipv6(IB)}},Offs,Sp);
	_ ->
	    case string_split(Addr,"/") of
		[A,N] ->
		    {ok,IA} = inet_parse:ipv6_address(A),
		    Net = list_to_integer(N),
		    Mask = <<-1:Net,0:(128-Net)>>,
		    expr_({memeq,IpOffs,Mask,ipv6(IA)},Offs,Sp);
		[A] ->
		    {ok,IA} = inet_parse:ipv6_address(A),
		    expr_({memeq,IpOffs,ipv6(IA)},Offs,Sp)
	    end
    end.

%% parse an ethernet address
%% 
eth_address(String) ->
    case string_split_all(String, ":") of
	[A,B,C,D,E,F] ->
	    try {x8(A),x8(B),x8(C),x8(D),x8(E),x8(F)} of
		Mac -> {ok,Mac}
	    catch
		error:_ ->
		    {error, einval}
	    end;
	_ ->
	    {error, einval}
    end.

x8("") -> 0;
x8(String) -> list_to_integer(String,16) band 16#ff.

%% recursivly split the string in parts

string_split_all(String, SubStr) ->
    string_split_all(String, SubStr, []).

string_split_all(String, SubStr, Acc) ->
    case string_split(String, SubStr) of
	[Part] ->
	    lists:reverse([Part | Acc]);
	[Part,Parts] ->
	    string_split_all(Parts,SubStr,[Part|Acc])
    end.

string_split(String, SubStr) ->
    case string:str(String, SubStr) of
	0 -> [String];
	I -> 
	    {A,B} = lists:split(I-1,String),
	    [A, lists:nthtail(length(SubStr), B)]
    end.
    

udp_attr(Start,Fld,Attr,Offs,Sp) ->
    case Attr of
	"dst_port" -> 
	    expr_(Fld(?OFFS_UDP_DST_PORT,?U16), Offs,Sp);
	"dst_port."++PortStr ->
	    expr_(port_expr(PortStr,Fld,?OFFS_UDP_DST_PORT),Offs,Sp);
	"src_port" ->
	    expr_(Fld(?OFFS_UDP_SRC_PORT,?U16), Offs,Sp);
	"src_port."++PortStr ->
	    expr_(port_expr(PortStr,Fld,?OFFS_UDP_SRC_PORT),Offs,Sp);
	"port."++PortStr ->
	    Dst = port_expr(PortStr,Fld,?OFFS_UDP_DST_PORT),
	    Src = port_expr(PortStr,Fld,?OFFS_UDP_SRC_PORT),
	    expr_({'||', Dst, Src}, Offs, Sp);
	"length"   -> expr_(Fld(?OFFS_UDP_LENGTH,?U16), Offs,Sp);
	"csum"     -> expr_(Fld(?OFFS_UDP_CSUM,?U16), Offs,Sp);
	"data"     -> expr_(udp_data_offs(Start),Offs,Sp);
	"data["++Elem -> xvexpr_(Elem, udp_data_offs(Start), Offs, Sp)
    end.

udp_data_offs(Start) ->
    {'+',Start,?OFFS_UDP_DATA}.


tcp_attr(Start,Fld,Attr,Offs,Sp) ->
    case Attr of
	"dst_port" ->
	    expr_(Fld(?OFFS_TCP_DST_PORT,?U16), Offs, Sp);
	"dst_port."++PortStr ->
	    expr_(port_expr(PortStr,Fld,?OFFS_TCP_DST_PORT),Offs,Sp);
	"src_port" -> 
	    expr_(Fld(?OFFS_TCP_SRC_PORT,?U16), Offs, Sp);
	"src_port."++PortStr ->
	    expr_(port_expr(PortStr,Fld,?OFFS_TCP_SRC_PORT),Offs,Sp);
	"port."++PortStr ->
	    Dst = port_expr(PortStr,Fld,?OFFS_TCP_DST_PORT),
	    Src = port_expr(PortStr,Fld,?OFFS_TCP_SRC_PORT),
	    expr_({'||', Dst, Src}, Offs, Sp);
	"seq"      -> expr_(Fld(?OFFS_TCP_SEQ,?U32), Offs,Sp);
	"ack"      -> expr_(Fld(?OFFS_TCP_ACK,?U32), Offs,Sp);
	"flags"    -> expr_(Fld(?OFFS_TCP_FLAGS,?U16), Offs,Sp);
	"window"   -> expr_(Fld(?OFFS_TCP_WINDOW,?U16), Offs,Sp);
	"csum"     -> expr_(Fld(?OFFS_TCP_CSUM,?U16), Offs,Sp);
	"uptr"     -> expr_(Fld(?OFFS_TCP_UPTR,?U16),Offs,Sp);
	"flag.fin" -> tcp_flag_expr(Fld,0,Offs,Sp);
	"flag.syn" -> tcp_flag_expr(Fld,1,Offs,Sp);
	"flag.rst" -> tcp_flag_expr(Fld,2,Offs,Sp);
	"flag.psh" -> tcp_flag_expr(Fld,3,Offs,Sp);
	"flag.ack" -> tcp_flag_expr(Fld,4,Offs,Sp);
	"flag.urg" -> tcp_flag_expr(Fld,5,Offs,Sp);
	"data_offset" ->
	    expr_(tcp_data_offs_expr(Fld),Offs,Sp);
	"data" ->
	    expr_(tcp_data_expr(Fld,Start), Offs, Sp);
	"data["++Elem ->
	    xvexpr_(Elem, tcp_data_expr(Fld,Start), Offs, Sp)
    end.

tcp_data_expr(Fld,Start) ->
    {'+',tcp_data_offs_expr(Fld),Start}.

tcp_data_offs_expr(Fld) ->
    {'>>',{'&',Fld(?OFFS_TCP_FLAGS,?U8),16#f0},2}.

%% handle port expressions num | num..num
port_expr(PortStr,Fld,FOffs) ->
    case string_split(PortStr,"..") of
	[A,B] ->
	    Ap = list_to_integer(A),
	    Bp = list_to_integer(B),
	    {'&&', {'>=',Fld(FOffs,?U16),Ap},{'<=',Fld(FOffs,?U16),Bp}};
	[A] ->
	    Ap = list_to_integer(A),
	    {'==',Fld(FOffs,?U16),Ap}
    end.
	

tcp_flag_expr(Fld, Num, Offs, Sp) ->
    expr_({'&', {'>>',Fld(?OFFS_TCP_FLAGS,?U16), Num}, 1}, Offs, Sp).


pexpr(Code,K0,Offs,Sp0) ->
    %% io:format("pexpr: ~w\n", [{Code,K0,Offs,Sp0}]),
    K = pexpr_k(K0)+Offs,
    Sp1 = Sp0-1,
    {Sp1, 
     [#bpf_insn { code=Code, k=K },
      #bpf_insn { code=sta, k=Sp1 }]}.

pexpr(Code,Ax,K0,Offs,Sp0) ->  %% indexed expression
    K = pexpr_k(K0),
    {SpX,AcX} = case Ax of
		    {msh,Kx} -> 
			{Sp0-1,[#bpf_insn{code=ldxmsh,k=Kx+Offs}]};
		    _ ->
			{Sp1,Ac} = expr_(Ax,Offs,Sp0),
			{Sp1,[Ac,#bpf_insn { code=ldx, k=Sp1}]}
		end,
    {SpX, [AcX,
	   #bpf_insn { code=Code, k=K }, 
	   #bpf_insn { code=sta,  k=SpX }
	  ]}.

pexpr_k(K) when is_integer(K) ->
    K;
pexpr_k(K) when is_atom(K) ->
    pexpr_k(atom_to_list(K));
pexpr_k(K) when is_list(K) ->
    case K of
	%% eth offsets
	"eth.dst"    -> ?OFFS_ETH_DST;
	"eth.src"    -> ?OFFS_ETH_SRC;
	"eth.type"   -> ?OFFS_ETH_TYPE;
	"eth.data"   -> ?OFFS_ETH_DATA;

	%% arp offsets
	"arp.htype"   -> ?OFFS_ARP_HTYPE;
	"arp.ptype"   -> ?OFFS_ARP_PTYPE;
	"arp.halen"   -> ?OFFS_ARP_HALEN;
	"arp.palen"   -> ?OFFS_ARP_PALEN;
	"arp.op"      -> ?OFFS_ARP_OP;

	%% ipv4 offsets
	"ip.hlen"  -> ?OFFS_IPV4_HLEN;
	"ip.dsrv"  -> ?OFFS_IPV4_DSRV;
	"ip.len"   -> ?OFFS_IPV4_LEN;
	"ip.id"    -> ?OFFS_IPV4_ID;
	"ip.frag"  -> ?OFFS_IPV4_FRAG;
	"ip.ttl"   -> ?OFFS_IPV4_TTL;
	"ip.proto" -> ?OFFS_IPV4_PROTO;
	"ip.dst"   -> ?OFFS_IPV4_DST;
	"ip.src"   -> ?OFFS_IPV4_SRC;

	%% ipv6 offsets
	"ip6.len"   -> ?OFFS_IPV6_LEN;
	"ip6.next"  -> ?OFFS_IPV6_NEXT;
	"ip6.hopc"  -> ?OFFS_IPV6_HOPC;
	"ip6.dst"   -> ?OFFS_IPV6_DST;
	"ip6.src"   -> ?OFFS_IPV6_SRC
    end.

%% convert ipv4 address to binary format
ipv4({A,B,C,D}) ->
    <<A,B,C,D>>;
ipv4(IPV4) when is_integer(IPV4) ->
    <<IPV4:32>>;
ipv4(String) when is_list(String) ->
    {ok,IP} = inet_parse:ipv4_address(String),
    ipv4(IP).

%% convert ipv6 address to binary format
ipv6({A,B,C,D,E,F,G,H}) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>;
ipv6(String) when is_list(String) ->
    {ok,IP} = inet_parse:ipv6_address(String),
    ipv6(IP).

eth({A,B,C,D,E,F}) ->
    <<A,B,C,D,E,F>>;
eth(String) when is_list(String) ->
    {ok,Mac} = eth_address(String),
    eth(Mac).


code_length(Code) ->
    lists:flatlength(Code).

%%
%% Basic block representation
%%  bpf_bprog {
%%     fanout:  dict L -> [L]
%%     fanin:   dict L -> [L]
%%     block:   dict L -> #bpf_block
%%  }
%%

bs_new(Init) ->
    #bpf_bs {
       init = Init,
       changed = 0,
       block  = dict:new(),
       fanin  = dict:new(),
       fanout = dict:new()
      }.

bs_map_block(Fun, Bs) when is_record(Bs,bpf_bs) ->
    Ls = [L || {L,_B} <- dict:to_list(Bs#bpf_bs.block)],
    bs_map_(Fun, Bs, Ls).

bs_map_(Fun, Bs, [I|Is]) ->
    B = bs_get_block(I, Bs),
    case Fun(B) of
	B  -> bs_map_(Fun, Bs, Is);
	B1 -> bs_map_(Fun, bs_set_block(B1,Bs),Is)
    end;
bs_map_(_Fun,Bs,[]) ->
    Bs.

bs_each_block(Fun, Bs) when is_record(Bs,bpf_bs) ->
    Ls = [B || {_L,B} <- dict:to_list(Bs#bpf_bs.block)],
    lists:foreach(Fun, lists:keysort(#bpf_block.label, Ls)).

bs_fold_block(Fun, Acc, Bs) when is_record(Bs,bpf_bs) ->
    dict:fold(fun(_K,B,AccIn) -> Fun(B,AccIn) end, Acc, Bs#bpf_bs.block).

bs_set_block(B, Bs) when is_record(B,bpf_block), is_record(Bs,bpf_bs) ->
    case dict:fetch(B#bpf_block.label, Bs#bpf_bs.block) of
	B -> Bs;  %% no changed
	_ ->
	    Bs1 = bs_del_block(B#bpf_block.label, Bs),
	    bs_add_block(B, Bs1)
    end.
    
bs_add_block(B, Bs) when is_record(B,bpf_block), is_record(Bs,bpf_bs) ->
    La = B#bpf_block.label,
    Block = dict:store(La, B, Bs#bpf_bs.block),
    Bs1 = Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 },
    foldl(fun(Lb,Bsi) -> bs_add_edge(La, Lb, Bsi) end, Bs1,
	  get_fanout(B#bpf_block.next)).

bs_del_block(La, Bs) when is_record(Bs,bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Block = dict:erase(La, Bs#bpf_bs.block),
    Bs1 = Bs#bpf_bs { block=Block, changed=Bs#bpf_bs.changed+1 },
    foldl(fun(Lb,Bsi) -> bs_del_edge(La, Lb, Bsi) end, Bs1,
	  get_fanout(B#bpf_block.next)).
    
bs_set_next(La, Next, Bs) when is_record(Next,bpf_insn), is_record(Bs,bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Next0 = B#bpf_block.next,
    if Next =:= Next0 ->
	    Bs;
       true ->
	    Ldel = get_fanout(Next0),
	    Ladd = get_fanout(Next),
	    B1 = B#bpf_block { next = Next },
	    Block = dict:store(La, B1, Bs#bpf_bs.block),
	    Bs1 = Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 },
	    Bs2 = foldl(fun(Lb,Bsi) -> bs_add_edge(La, Lb, Bsi) end, Bs1, Ladd),
	    Bs3 = foldl(fun(Lb,Bsi) -> bs_del_edge(La, Lb, Bsi) end, Bs2, Ldel),
	    Bs3
    end.

bs_set_insns(La, Insns, Bs) when is_list(Insns), is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Insns0 = B#bpf_block.insns,
    if Insns0 =:= Insns ->
	    Bs;
       true ->
	    B1 = B#bpf_block { insns = Insns },
	    Block = dict:store(La, B1, Bs#bpf_bs.block),
	    Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 }
    end.

bs_get_block(La, Bs) when is_record(Bs, bpf_bs) ->
    dict:fetch(La, Bs#bpf_bs.block).

bs_get_labels(Bs) when is_record(Bs, bpf_bs) ->
    dict:fold(fun(K,_,Acc) -> [K|Acc] end, [], Bs#bpf_bs.block).

bs_get_next(La, Bs) when is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    B#bpf_block.next.

bs_get_insns(La, Bs) when is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    B#bpf_block.insns.    

bs_get_fanout(L, Bs) when is_record(Bs, bpf_bs) ->
    case dict:find(L, Bs#bpf_bs.fanout) of
	error -> [];
	{ok,Ls} -> Ls
    end.

bs_get_fanin(L, Bs) when is_record(Bs, bpf_bs) ->
    case dict:find(L, Bs#bpf_bs.fanin) of
	error -> [];
	{ok,Ls} -> Ls
    end.

%% add edge La -> Lb
bs_add_edge(La,Lb,Bs) ->
    Fo = dict:append(La, Lb, Bs#bpf_bs.fanout),   %% La -> Lb
    Fi = dict:append(Lb, La, Bs#bpf_bs.fanin),    %% Lb <- La
    Bs#bpf_bs { fanout = Fo, fanin = Fi }.

%% del edge La -> Lb
bs_del_edge(La,Lb,Bs) ->
    Fo = dict_subtract(La, Lb, Bs#bpf_bs.fanout),   %% La -> Lb
    Fi = dict_subtract(Lb, La, Bs#bpf_bs.fanin),    %% Lb <- La
    Bs#bpf_bs { fanout = Fo, fanin = Fi }.

%% subtract V from list in key K
dict_subtract(K,V,D) ->
    case dict:find(K, D) of
	error -> D;
	{ok,L} when is_list(L) ->
	    case L -- [V] of
		[] -> dict:erase(K,D);
		L1 -> dict:store(K,L1,D)
	    end
    end.

%% return a list of output labels.
%% #bpf_insn{} => [label()]
%%
get_fanout(I=#bpf_insn { jt=Jt, jf=Jf, k=K }) ->
    case class(I) of
	{jmp,true,_} -> [K];
	{jmp,_Cond,_R} -> [Jt,Jf];
	_ -> []
    end;
get_fanout(undefined) ->
    [].

	    
