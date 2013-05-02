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
-export([exec/2, exec/5]).

%% debug/test
-export([run_is_rarp/1, is_rarp/0]).
-export([is_src_dst/0, is_src_dst/2, is_tcp_finger/0, is_host/1]).

encode(Bs) when is_list(Bs) ->
    list_to_binary([ encode_(B) || B <- Bs ]);
encode(B) when is_record(B, bpf_insn) ->
    encode_(B).

encode_(#bpf_insn{code=ldaw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_ABS, K);
encode_(#bpf_insn{code=ldah,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_ABS,K);
encode_(#bpf_insn{code=ldab,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_ABS, K);

encode_(#bpf_insn{code=ldiw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_IND,K);
encode_(#bpf_insn{code=ldih,k=K}) -> insn(?BPF_LD+?BPF_H +?BPF_IND,K);
encode_(#bpf_insn{code=ldib,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_IND,K);

encode_(#bpf_insn{code=ldl })   -> insn(?BPF_LD + ?BPF_LEN);
encode_(#bpf_insn{code=ldc, k=K})    -> insn(?BPF_LD + ?BPF_IMM, K);
encode_(#bpf_insn{code=ldm, k=K})    -> insn(?BPF_LD + ?BPF_MEM, K);

encode_(#bpf_insn{code=ldxc, k=K})   -> insn(?BPF_LDX+?BPF_W+?BPF_IMM, K);
encode_(#bpf_insn{code=ldxm, k=K})   -> insn(?BPF_LDX+?BPF_W+?BPF_MEM, K);
encode_(#bpf_insn{code=ldxl })  -> insn(?BPF_LDX+?BPF_W+?BPF_LEN);
encode_(#bpf_insn{code=ldxmsh, k=K}) -> insn(?BPF_LDX+?BPF_B+?BPF_MSH, K);

encode_(#bpf_insn{code=st, k=K}) ->   insn(?BPF_ST, K);
encode_(#bpf_insn{code=stx,k=K}) ->  insn(?BPF_STX, K);

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


decode(<<Insn:8/binary, Bpf/binary>>) ->
    [ decode_(Insn) | decode(Bpf) ];
decode(<<>>) ->
    [].

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
	?BPF_MEM -> #bpf_insn { code=ldm, k=K};
	?BPF_LEN -> #bpf_insn { code=ldl }
    end.

decode_ldx_(Code, K) ->
    case ?BPF_SIZE(Code) of
	?BPF_W ->
	    case ?BPF_MODE(Code) of
		?BPF_IMM -> #bpf_insn { code=ldxc, k=K};
		?BPF_MEM -> #bpf_insn { code=ldxm, k=K};
		?BPF_LEN -> #bpf_insn { code=ldxl }
	    end;
	?BPF_B ->
	    case ?BPF_MODE(Code) of
		?BPF_MSH -> #bpf_insn { code=ldxmsh, k=K}
	    end
    end.

decode_st_(_Code, K) ->
    #bpf_insn { code=st, k=K }.

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
	?BPF_JA  -> #bpf_insn { code=jmp };
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

%%
%% Execute BPF (debugging and runtime support when missing in kernel or library)
%%
exec(Is, P) when is_list(Is), is_binary(P) ->
    exec_(Is, 0, 0, P, lists:duplicate(?BPF_MEMWORDS, 0)).

exec(Is,A,X,P,M) when is_binary(P), is_tuple(M) ->
    exec_(Is,A,X,P,M).
    

exec_([I=#bpf_insn{code=Code,k=K}|Is],A,X,P,M) ->
    case Code of
	ldaw -> exec_(Is, load_(P,K, 32), X, P, M);
	ldah -> exec_(Is, load_(P,K, 16), X, P, M);
	ldab -> exec_(Is, load_(P,K, 8), X, P, M);
	ldiw -> exec_(Is, load_(P,X+K, 32), X, P, M);
	ldih -> exec_(Is, load_(P,X+K, 16), X, P, M);
	ldib -> exec_(Is, load_(P,X+K, 8), X, P, M);
	ldl  -> exec_(Is, byte_size(P), X, P, M);
	ldc  -> exec_(Is, K, X, P, M);
	ldm  -> exec_(Is, element(K+1,M), X, P, M);
	ldxc  -> exec_(Is, A, K, P, M);
	ldxm  -> exec_(Is, A, element(K+1,M), P, M);
	ldxl  -> exec_(Is, A, byte_size(P), P, M);
	ldxmsh -> exec_(Is, A, 4*(load_(P,K, 8) band 16#f), P, M);
	st -> exec_(Is, A, X, P, setelement(K+1,A,M));
	stx -> exec_(Is, A, X, P, setelement(K+1,X,M));
	addk -> exec_(Is, A + K, X, P, M);
	subk -> exec_(Is, A - K, X, P, M);
	mulk -> exec_(Is, A * K, X, P, M);
	divk -> exec_(Is, A div K, X, P, M);
	andk -> exec_(Is, A band K, X, P, M);
	ork -> exec_(Is, A bor K, X, P, M);
	lshk -> exec_(Is, A bsl K, X, P, M);
	rshk -> exec_(Is, A bsr K, X, P, M);
	addx -> exec_(Is, A + X, X, P, M);
	subx -> exec_(Is, A - X, X, P, M);
	mulx -> exec_(Is, A * X, X, P, M);
	divx -> exec_(Is, A div X, X, P, M);
	andx -> exec_(Is, A band X, X, P, M);
	orx  -> exec_(Is, A bor X, X, P, M);
	lshx -> exec_(Is, A bsl X, X, P, M);
	rshx -> exec_(Is, A bsr X, X, P, M);
	neg  -> exec_(Is, -A, X, P, M);
	
	jmp  -> jump_(Is, true, K, 0, A, X, P, M);
	jgtk -> jump_(Is, (A > K), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jgek -> jump_(Is, (A >= K), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jeqk -> jump_(Is, (A =:= K), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jsetk -> jump_(Is, (A band K) =/= 0, I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jgtx -> jump_(Is, (A > X), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jgex -> jump_(Is, (A >= X), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jeqx -> jump_(Is, (A =:= X), I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	jsetx -> jump_(Is, (A band X) =/= 0, I#bpf_insn.jt,I#bpf_insn.jf, A, X, P, M);
	reta -> A;
	retk -> K;
	tax -> exec_(Is, X, X, P, M);
	txa -> exec_(Is, A, A, P, M)
    end.

jump_(Is, true, Jt, _Jf, A, X, P, M) ->
    exec_(lists:nthtail(Jt, Is), A, X, P, M);
jump_(Is, false, _Jt, Jf, A, X, P, M) ->
    exec_(lists:nthtail(Jf, Is), A, X, P, M).

load_(P, K, Size) ->
    case P of
	<<_:K/binary, A:Size, _/binary>> ->
	    A
    end.

%%
%% Examples (remove soon)
%%
-define(ETHERTYPE_IP,     16#0800).
-define(ETHERTYPE_REVARP, 16#8035).

-define(ARPOP_REVREQUEST, 3).

-define(IPPROTO_TCP,  6).
-define(IPPROTO_ICMP,  1).
-define(IPPROTO_UDP,  17).

is_rarp() ->
    [#bpf_insn{code=ldah, k=12},
     #bpf_insn{code=jeqk, k=?ETHERTYPE_REVARP, jt=0, jf=3 },
     #bpf_insn{code=ldah, k=20},
     #bpf_insn{code=jeqk, k=?ARPOP_REVREQUEST, jt=0, jf=1 },
     #bpf_insn{code=retk, k=14+12 },
     #bpf_insn{code=retk, k=0}].

run_is_rarp(P) when is_binary(P) ->
    exec(is_rarp(), P).

is_src_dst() ->
    is_src_dst(16#8003700f, 16#80037023).

is_src_dst(Src, Dst) ->
    [#bpf_insn{code=ldah, k=12},
     #bpf_insn{code=jeqk, k=?ETHERTYPE_IP, jt=0, jf=8},
     #bpf_insn{code=ldaw, k=26},
     #bpf_insn{code=jeqk, k=Src, jt=0, jf=2},
     #bpf_insn{code=ldaw, k=30},
     #bpf_insn{code=jeqk, k=Dst, jt=3, jf=4},
     #bpf_insn{code=jeqk, k=Dst, jt=0, jf=3},
     #bpf_insn{code=ldaw, k=30},
     #bpf_insn{code=jeqk, k=Src, jt=1, jf=1},
     #bpf_insn{code=retk, k=16#ffffffff},
     #bpf_insn{code=retk, k=0}].

%% IP A.B.C.D must be src or dst
is_host({A,B,C,D}) ->
    IP = (A bsl 24) + (B bsl 16) + (C bsl 8) + D,
    [#bpf_insn{code=ldah, k=12},
     #bpf_insn{code=jeqk, k=?ETHERTYPE_IP, jt=0, jf=5},
     #bpf_insn{code=ldaw, k=26},
     #bpf_insn{code=jeqk, k=IP, jt=2, jf=0},
     #bpf_insn{code=ldaw, k=30},
     #bpf_insn{code=jeqk, k=IP, jt=0, jf=1},
     #bpf_insn{code=retk, k=16#ffffffff},
     #bpf_insn{code=retk, k=0}].
    

is_tcp_finger() ->
    [#bpf_insn{code=ldah, k=12},
     #bpf_insn{code=jeqk, k=?ETHERTYPE_IP, jt=0, jf=10},
     #bpf_insn{code=ldab, k=23 },
     #bpf_insn{code=jeqk, k=?IPPROTO_TCP, jt=0, jf=8},
     #bpf_insn{code=ldah, k=20 },
     #bpf_insn{code=jsetk, k=16#1fff, jt=6, jf=0},
     #bpf_insn{code=ldxbmsh, k=14 },
     #bpf_insn{code=ldih, k=13 },
     #bpf_insn{code=jeqk, k=79, jt=2, jf=0},
     #bpf_insn{code=ldih, k=16 },
     #bpf_insn{code=jeqk, k=79, jt=0, jf=1},
     #bpf_insn{code=retk, k=16#ffffffff },
     #bpf_insn{code=retk, k=0 }].
