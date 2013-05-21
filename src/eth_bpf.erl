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
	 expr/1]).
%% some predefined expressions
-export([is_arp/0, is_revarp/0, is_ipv4/0, is_ipv6/0, is_ip/0,
	 is_ipv4_proto/1, is_ipv6_proto/1, 
	 is_icmp/0,
	 is_tcp/0, is_udp/0,
	 is_ipv4_tcp_src/1, is_ipv4_tcp_dst/1,
	 is_ipv4_tcp_dst_port/1, is_ipv4_tcp_src_port/1,
	 is_ipv6_tcp_dst_port/1, is_ipv6_tcp_src_port/1,
	 is_tcp_dst_port/1, is_tcp_src_port/1,
	 is_tcp_syn/0, is_tcp_ack/0, is_tcp_fin/0, is_tcp_psh/0]).

-compile(export_all).

-import(lists, [reverse/1, foldl/3]).

-define(MAX_OPTIMISE, 10).

-define(uint32(X), ((X) band 16#ffffffff)).

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
	      print_insn_c("    ", -1, B#bpf_block.next)
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
	    io:format("~sgoto L~.3.0w;\n", 
		      [L,J+1+I#bpf_insn.k])
    end;
print_jmp_c(Cond,k,I,L,J) ->
    io:format("~sif (A ~s #0x~.16B) goto L~.3.0w; else goto L~.3.0w;\n", 
	      [L,Cond,I#bpf_insn.k,
	       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]);
print_jmp_c(Cond,x,I,L,J) ->
    io:format("~sif (A ~s X) goto L~.3.0w; else goto L~.3.0w;\n", 
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
    io:format("OPTIMISE: ~w\n", [I]),
    L = [fun remove_ld/1,
	 fun remove_st/1,
	 fun remove_multiple_jmp/1,
	 fun remove_unreach/1,
	 fun constant_propagation/1,
	 fun bitfield_jmp/1,
	 fun remove_unreach/1],
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
    io:format("REMOVE: ~w\n", [_I2]),
    [I1 | remove_ld_bl_([#bpf_insn {code=tax}| Is])];

%% M[k] = A, <opA>, A=M[k]  => M[k]=A [<opA]
remove_ld_bl_([I1=#bpf_insn{code=sta,k=K},I2,_I3=#bpf_insn{code=lda,k=K}|Is]) ->
    case class(I2) of
	{alu,_,_}    -> %% ineffective, remove I2,I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,a,x}   -> %% ineffective, remove I2,I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,x,a}   -> %% remove I3 since X is update to A
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{st,a,{k,K}} -> %% I1 = I2 remove I2,I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,_,_}     -> %% just remove I3
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);	    
	{ld,x,_}     ->
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_}     -> %% A=<...>  A is reloaded in I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
%% M[k]=X, INSN, X=M[k]  => M[k]=X, INSN
remove_ld_bl_([I1=#bpf_insn{code=stx,k=K},I2,_I3=#bpf_insn{code=ldx,k=K}|Is]) ->
    case class(I2) of
	{alu,_,_} ->   %% A += <...>  do not update X remove I3
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,a,x} ->  %% A=X remove I3
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,x,a} ->  %% X=A ineffective, remove I2,I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,{k,K}} -> %% I1=I2, duplicate, remove I2,I3
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,_} ->     %% remove I3
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_} ->     %% A=<..>, keep x is not updated
	    remove_ld_bl_([I1,I2|Is]);
	{ld,x,_}     -> %% X=<..>  X is reloaded in I3 
	    io:format("REMOVE: ~w\n", [I2]),
	    io:format("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
remove_ld_bl_([I|Is]) ->
    [I|remove_ld_bl_(Is)];
remove_ld_bl_([]) ->
    [].


%% remove unnecessary sta|stx instructions ( M[K]=A|X )
%% remove:
%%    M[k]=A     sta, if M[k] is never referenced (before killed)
%%    M[k]=X     stx, if M[k] is never referenced (before killed)
%%    A=X        txa  if A is never reference (before killed)
%%    A=<const>  ldc, if A is never reference (before killed)
%%    X=A        tax, if X is never reference (before killed)
%%    X=<const>  ldx, if X is never reference (before killed)
%%
remove_st(Bs) when is_record(Bs,bpf_bs) ->
    bs_map_block(fun(B) -> remove_st_bl_(B, Bs) end, Bs).

remove_st_bl_(B, Bs) ->
    B#bpf_block { insns = remove_st_bl__(B#bpf_block.insns, B, Bs) }.

remove_st_bl__([I | Is], B, Bs) ->
    case is_referenced_st(I, Is, B, Bs) of
	false ->
	    io:format("REMOVE: ~w\n", [I]),
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
%% Find bitfield & optimise jumps:
%% A)
%%    A >>= 0x1;
%%    A &= 0x1;
%%    if (A > 0x0) goto L1; else goto L2;
%% ==>
%%    if (A & 0x02) goto L1; else goto L2;  (if A is not referenced in L1/L2)
%% B)
%%    A &= 0x10;
%%    if (A > 0x0) goto L1; else goto L2;
%% ==>    
%%    if (A > 0x10) goto L1; else goto L2;
%%
bitfield_jmp(Bs) when is_record(Bs,bpf_bs) ->
    bs_fold_block(fun(B,Bsi) -> bitfield_jmp_bl_(B, Bsi) end, Bs, Bs).

bitfield_jmp_bl_(B, Bs) ->
    case reverse(B#bpf_block.insns) of
	[#bpf_insn{ code=andk, k=1 }, #bpf_insn{ code=rshk, k=K } | Is] ->
	    case B#bpf_block.next of
		N = #bpf_insn { code=jgtk, k=0 } ->
		    io:format("BITFIELD 1\n"),
		    case is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    io:format(" REFERENCED\n"),
			    Bs;
			false ->
			    io:format(" UPDATED\n"),
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
		N = #bpf_insn { code=jgtk, k=0 } ->
		    io:format("BITFIELD 1\n"),
		    case is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    io:format(" REFERENCED\n"),
			    Bs;
			false ->
			    io:format(" UPDATED\n"),
			    N1 = N#bpf_insn { code=jsetk, k=Km },
			    B1 = B#bpf_block { insns=reverse(Is),
					       next = N1},
			    bs_set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;
	_ ->
	    Bs
    end.

%%
%% remove multiple unconditional jumps 
%%
remove_multiple_jmp(Bs) when is_record(Bs,bpf_bs) ->
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
		    io:format("REPLACE: ~w with ~w\n",
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
		    io:format("REPLACE: ~w with ~w\n", [Next,Next1]),
		    bs_set_next(B#bpf_block.label, Next1, Bs);
	       true ->
		    Bs
	    end;
	_ ->
	    Bs
    end.

%%
%% Remove unreachable blocks
%%
remove_unreach(Bs) when is_record(Bs,bpf_bs) ->
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
			io:format("REMOVE BLOCK: ~w\n", [I]),
			bs_del_block(I, Bsi) end, 
		Bs, Remove).

%%
%% Constant propagation
%%     for each node 
%%     recursive calculate the constants for all
%%     fan in. 
%%     calculate the union of all constants
%%     and proceed then do the block 
%%
constant_propagation(Bs) when is_record(Bs,bpf_bs) ->
    Ls = bs_get_labels(Bs),
    {Bs1,_,_} = constant_propagation_(Ls, Bs, dict:new(), sets:new()),
    Bs1.

%% Ds is dict of dicts of block calculations, Vs is set of visited nodes
constant_propagation_([I|Is], Bs, Ds, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    constant_propagation_(Is,Bs,Ds,Vs);
	false ->
	    %% io:format("find label = ~w\n", [I]),
	    B0 = bs_get_block(I, Bs),
	    FanIn = bs_get_fanin(I, Bs),
	    %% io:format("I=~w fanin=~w\n", [I, FanIn]),
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
    io:format("EVAL: ~w\n", [B#bpf_block.label]),
    {Is,D1} = constant_ev_(B#bpf_block.insns,[],D),
    Next = constant_ev_jmp_(B#bpf_block.next, D1),
    if Next =/= B#bpf_block.next ->
	    io:format("Replace: ~w with ~w\n", [B#bpf_block.next, Next]);
       true -> ok
    end,
    {B#bpf_block { insns = Is, next=Next }, D1}.


constant_ev_([I|Is],Js,D) ->
    %% io:format("  EV: ~w in dict=~w\n", [I, dict:to_list(D)]),
    K = I#bpf_insn.k,
    case I#bpf_insn.code of
	ldaw ->
	    constant_set_(I, Is, Js, a, {p,K,4}, D);
	ldah ->
	    constant_set_(I, Is, Js, a, {p,K,2}, D);
	ldab ->
	    constant_set_(I, Is, Js, a, {p,K,1}, D);
	ldiw ->
	    constant_set_(I, Is, Js, a, {p,get_reg(x,D),K,4}, D);
	ldih ->
	    constant_set_(I, Is, Js, a, {p,get_reg(x,D),K,2}, D);
	ldib ->
	    constant_set_(I, Is, Js, a, {p,get_reg(x,D),K,1}, D);
	ldl  ->
	    constant_set_(I, Is, Js, a, {l,4}, D);
	ldc  ->
	    constant_set_(I, Is, Js, a, K, D);
	lda  ->
	    case get_reg({m,K},D) of
		K1 when is_integer(K1) ->
		    I1 = I#bpf_insn{code=ldc,k=K1},
		    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
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
		    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
		    constant_ev_(Is,[I1|Js], set_reg(x,K1,D));
		R ->
		    constant_ev_(Is,[I|Js], set_reg(x,R,D))
	    end;
	ldxl ->
	    constant_set_(I, Is, Js, x, {l,4}, D);
	ldxmsh -> 
	    constant_set_(I, Is, Js, x, {msh,K}, D);
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
    case get_reg(R, D) of
	undefined -> %% no value defined
	    constant_ev_(Is,[I|Js], set_reg(R, V, D));
	V -> %% value already loaded
	    io:format("REMOVE: ~w, value ~w already set\n", [I,V]),
	    constant_ev_(Is,Js,D);
	_ ->
	    constant_ev_(Is,[I|Js], set_reg(R, V, D))
    end.

constant_ev_jmp_(I, D) ->
    %% io:format("  EV_JMP: ~w in dict=~w\n", [I, dict:to_list(D)]),
    case I#bpf_insn.code of
	retk -> I;
	reta -> I;
	jmp  -> I;
	jgtk  -> constant_ev_jmpk_(I,fun(A,K) -> A > K end,D);
	jgek  -> constant_ev_jmpk_(I,fun(A,K) -> A >= K end,D);
	jeqk  -> constant_ev_jmpk_(I,fun(A,K) -> A =:= K end,D);
	jsetk -> constant_ev_jmpk_(I,fun(A,K) -> (A band K) =/= 0 end,D);
	jgtx  -> constant_ev_jmpx_(I,fun(A,X) -> A > X end, jgtk,D);
	jgex  -> constant_ev_jmpx_(I,fun(A,X) -> A >= X end, jgek,D);
	jeqx  -> constant_ev_jmpx_(I,fun(A,X) -> A =:= X end, jeqk,D);
	jsetx -> constant_ev_jmpx_(I,fun(A,X) -> (A band X) =/= 0 end,jsetk,D)
    end.

constant_ev_jmpk_(I=#bpf_insn { jt=Jt, jf=Jf, k=K }, Cmp, D) ->
    case get_reg(a, D) of
	A when is_integer(A) ->
	    I1 = case Cmp(A,K) of
		     true  -> #bpf_insn { code=jmp, k=Jt };
		     false -> #bpf_insn { code=jmp, k=Jf }
		 end,
	    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
	    I1;
	_R -> I
    end.

constant_ev_jmpx_(I=#bpf_insn { jt=Jt, jf=Jf },Cmp,JmpK,D) ->
    case get_reg(a, D) of
	A when is_integer(A) ->
	    case get_reg(x, D) of
		X when is_integer(X) ->
		    I1 = case Cmp(A,X) of
			     true  -> #bpf_insn { code=jmp, k=Jt };
			     false -> #bpf_insn { code=jmp, k=Jf }
			 end,
		    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
		    I1;
		_ -> 
		    I
	    end;
	_ ->
	    case get_reg(x, D) of
		X when is_integer(X) -> 
		    I1 = I#bpf_insn { code=JmpK, k=X },
		    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
		    I1;
		_ ->
		    I
	    end
    end.

%% translate operation depending on outcome of calculation
eval_op_(I, Is, Js, D, Op, R, A, Op1, Op2) ->
    case eval_reg(Op,R,A,D) of
	K1 when is_integer(K1) ->
	    D1 = set_reg(R,K1,D),
	    I1 = I#bpf_insn { code=Op1, k=K1},
	    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
	    constant_ev_(Is, [I1|Js], D1);
	V1 ->
	    D1 = set_reg(R,V1,D),
	    case get_reg(A, D1) of
		K0 when is_integer(K0) ->
		    I1 = I#bpf_insn { code=Op2, k=K0},
		    %% Try remove noops, more?
		    case Op2 of
			subk when K0 =:= 0 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			addk when K0 =:= 0 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			mulk when K0 =:= 1 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			divk when K0 =:= 1 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			lshk when K0 =:= 0 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			rshk when K0 =:= 0 ->
			    io:format("REMOVE: ~w\n", [I1]),
			    constant_ev_(Is, Js, D1);
			_ ->
			    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
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
	    io:format("CHANGE: ~w TO ~w\n", [I, I1]),
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

get_reg(R, _D) when is_integer(R) ->
    %% io:format("get_reg: ~w\n", [R]),
    R;
get_reg(R, D) ->
    case dict:find(R, D) of
	{ok,V} -> 
	    %% io:format("get_reg: ~w = ~w\n", [R,V]),
	    V;
	error ->
	    %% io:format("get_reg: ~w = undefined\n", [R]),
	    undefined
    end.

eval_reg(Op,A,B,D) ->
    V = eval_reg_(Op, get_reg(A,D), get_reg(B,D)),
    %% io:format("eval_reg: (~w ~s ~w) = ~w\n", [Op,A,B,V]),
    V.

eval_reg(Op,A,D) ->
    V = eval_reg_(Op, get_reg(A,D)),
    %% io:format("eval_reg: ~s ~w = ~w\n", [Op,A,V]),
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
		      case intersect_value(Va,Vb) of
			  {true,Vc} ->
			      dict:store(K, Vc, C);
			  false ->
			      C
		      end;
		  false ->
		      C
	      end
      end, dict:new(), A).

%% simple version true only if values are identical
intersect_value(X, X) ->    
    {true,X};
intersect_value(X,Y) ->	
    io:format("intersect: ~w ~w => false\n", [X,Y]),
    false.

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
		io:format("mem index out of bounds, ~w\n", [(K)]),
		throw(mem_index)
	end).

-define(stmem(K,V,M),
	if (K) >= 0, K < tuple_size((M)) ->
		setelement((K)+1,(M),?uint32((V)));
	   true -> 
		io:format("mem index out of bounds, ~w\n", [(K)]),
		throw(mem_index)
	end).


exec_(Prog,Pc,A,X,P,M) ->
    #bpf_insn{code=Code,k=K} = I = element(Pc,Prog),
    io:format("~w: ~p, A=~w,X=~w,M=~w\n", [Pc, I,A,X,M]),
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
	    io:format("packet offset ~w:~w out of bounds, len=~w\n", 
		      [(K),(Size),byte_size((P))]),
	    throw(packet_index)
    end.

%%
%% Examples (remove soon)
%%
-define(ETHERTYPE_IP,     16#0800).
-define(ETHERTYPE_IPV6,   16#86dd).
-define(ETHERTYPE_ARP,    16#0806).
-define(ETHERTYPE_REVARP, 16#8035).

-define(ARPOP_REQUEST,  1).	%% ARP request.
-define(ARPOP_REPLY,    2).	%% ARP reply.
-define(ARPOP_RREQUEST, 3).	%% RARP request.
-define(ARPOP_RREPLY,   4).     %% RARP reply.

-define(IPPROTO_TCP,  6).
-define(IPPROTO_ICMP,  1).
-define(IPPROTO_UDP,  17).

-define(OFFS_ETH_DST,    (0)).
-define(OFFS_ETH_SRC,    (6)).
-define(OFFS_ETH_TYPE,   (6+6)).
-define(OFFS_ETH_DATA,   (6+6+2)).

-define(OFFS_ARP_HTYPE,  (?OFFS_ETH_DATA)).
-define(OFFS_ARP_PTYPE,  (?OFFS_ETH_DATA+2)).
-define(OFFS_ARP_HALEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_ARP_PALEN,  (?OFFS_ETH_DATA+5)).
-define(OFFS_ARP_OP,     (?OFFS_ETH_DATA+6)).

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

-define(OFFS_IPV6_LEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_IPV6_NEXT, (?OFFS_ETH_DATA+6)).
-define(OFFS_IPV6_HOPC, (?OFFS_ETH_DATA+7)).
-define(OFFS_IPV6_SRC,  (?OFFS_ETH_DATA+8)).
-define(OFFS_IPV6_DST,  (?OFFS_ETH_DATA+24)).
-define(OFFS_IPV6_PAYLOAD, (?OFFS_ETH_DATA+40)).

%% Given that X contains the IP headers length
-define(OFFS_TCP_SRC_PORT, 0).   %% uint16
-define(OFFS_TCP_DST_PORT, 2). %% uint16
-define(OFFS_TCP_SEQ,      4). %% uint32
-define(OFFS_TCP_ACK,      8). %% uint32
-define(OFFS_TCP_FLAGS,    12). %% Offs:4,_:6,UAPRSF:6
-define(OFFS_TCP_WINDOW,   14). %% uint16
-define(OFFS_TCP_CSUM,     16). %% uint16
-define(OFFS_TCP_UPTR,     18). %% uint16

-define(XOFFS_TCP_SRC_PORT, (?OFFS_ETH_DATA+?OFFS_TCP_SRC_PORT)).
-define(XOFFS_TCP_DST_PORT, (?OFFS_ETH_DATA+?OFFS_TCP_DST_PORT)).
-define(XOFFS_TCP_SEQ,      (?OFFS_ETH_DATA+?OFFS_TCP_SEQ)).
-define(XOFFS_TCP_ACK,      (?OFFS_ETH_DATA+?OFFS_TCP_ACK)).
-define(XOFFS_TCP_FLAGS,    (?OFFS_ETH_DATA+?OFFS_TCP_FLAGS)).
-define(XOFFS_TCP_WINDOW,   (?OFFS_ETH_DATA+?OFFS_TCP_WINDOW)).
-define(XOFFS_TCP_CSUM,     (?OFFS_ETH_DATA+?OFFS_TCP_CSUM)).
-define(XOFFS_TCP_UPTR,     (?OFFS_ETH_DATA+?OFFS_TCP_UPTR)).

-define(OFFS_UDP_SRC_PORT,  0).  %% uint16
-define(OFFS_UDP_DST_PORT,  2).  %% uint16
-define(OFFS_UDP_LENGTH,    4).  %% uint16
-define(OFFS_UDP_CSUM,      6).  %% uint16
-define(OFFS_UDP_DATA,      8).  

-define(XOFFS_UDP_SRC_PORT, ?OFFS_ETH_DATA+?OFFS_UDP_SRC_PORT).
-define(XOFFS_UDP_DST_PORT, ?OFFS_ETH_DATA+?OFFS_UDP_DST_PORT).
-define(XOFFS_UDP_LENGTH,   ?OFFS_ETH_DATA+?OFFS_UDP_LENGTH).
-define(XOFFS_UDP_CSUM,     ?OFFS_ETH_DATA+?OFFS_UDP_CSUM).
-define(XOFFS_UDP_DATA,     ?OFFS_ETH_DATA+?OFFS_UDP_DATA).

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
    X = expr(Expr),
    Prog = list_to_tuple(lists:flatten([X,
					if_gtk(0, [accept()], [reject()]),
					reject()])),
    build_(Prog).


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


prog_if_ipv4(True,False) ->
    if_ethertype(?ETHERTYPE_IP, True, False).

prog_if_ipv6(True,False) ->
    if_ethertype(?ETHERTYPE_IPV6, True, False).

prog_if_rarp(True,False) ->
    if_ethertype(?ETHERTYPE_REVARP, True, False).

prog_if_arp(True,False) ->
    if_ethertype(?ETHERTYPE_ARP, True, False).

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

expr(Expr) ->
    {_Sp,X} = expr(Expr, ?BPF_MEMWORDS),
    X.

expr(A, Sp) when is_atom(A) -> aexpr(A,Sp);
expr(K, Sp) when is_integer(K) -> iexpr(K,Sp);
expr({p,K,4},Sp)    -> pexpr(ldaw,K,Sp);
expr({p,K,2},Sp)    -> pexpr(ldah,K,Sp);
expr({p,K,1},Sp)    -> pexpr(ldab,K,Sp);
expr({p,0,K,4},Sp)  -> pexpr(ldaw,K,Sp);
expr({p,0,K,2},Sp)  -> pexpr(ldah,K,Sp);
expr({p,0,K,1},Sp)  -> pexpr(ldab,K,Sp);
expr({p,X,K,4},Sp)  -> pexpr(ldiw,X,K,Sp);
expr({p,X,K,2},Sp)  -> pexpr(ldih,X,K,Sp);
expr({p,X,K,1},Sp)  -> pexpr(ldib,X,K,Sp);

expr({'+',Ax,Bx},Sp) -> bop(addx,Ax,Bx,Sp);
expr({'-',Ax,Bx},Sp) -> bop(subx,Ax,Bx,Sp);
expr({'*',Ax,Bx},Sp) -> bop(mulx,Ax,Bx,Sp);
expr({'/',Ax,Bx},Sp) -> bop(divx,Ax,Bx,Sp);
expr({'&',Ax,Bx},Sp) -> bop(andx,Ax,Bx,Sp);
expr({'|',Ax,Bx},Sp) -> bop(orx,Ax,Bx,Sp);
expr({'<<',Ax,Bx},Sp) -> bop(lshx,Ax,Bx,Sp);
expr({'>>',Ax,Bx},Sp) -> bop(rshx,Ax,Bx,Sp);
expr({'-',Ax}, Sp)    -> uop(neg, Ax, Sp);
expr({'>',Ax,Bx},Sp)  -> rop(jgtx,Ax,Bx,Sp);
expr({'>=',Ax,Bx},Sp) -> rop(jgex,Ax,Bx,Sp);
expr({'==',Ax,Bx},Sp) -> rop(jeqx,Ax,Bx,Sp);
expr({'<',Ax,Bx},Sp)  -> rop(jgtx,Bx,Ax,Sp);
expr({'<=',Ax,Bx},Sp) -> rop(jgex,Bx,Ax,Sp);
expr({'!=',Ax,Bx},Sp) -> lbool({'-',Ax,Bx},Sp);
expr({'!',Ax},Sp)     -> lnot(Ax,Sp);
expr({'&&',Ax,Bx},Sp) -> land(Ax,Bx,Sp);
expr({'&&',[]},Sp)    -> expr(true,Sp);
expr({'&&',As},Sp) when is_list(As) -> expr(expr_list('&&',As), Sp);
expr({'||',Ax,Bx},Sp) -> lor(Ax,Bx,Sp);
expr({'||',[]},Sp)    -> expr(false,Sp);
expr({'||',As},Sp) when is_list(As) -> expr(expr_list('||',As), Sp);
expr({'memeq',Ax,Data},Sp) when is_binary(Data) ->
    %% Ax is an index expression
    {Sp1,Ac} = expr(Ax,Sp),
    %% Move A to X
    Jf = 2*((byte_size(Data)+3) div 4),  %% number of instructions
    {Sp1,
     [ Ac,    %% A = index
       #bpf_insn { code=tax },          %% X=A index register
       expr_memcmp(Data, 0, Jf),        %% Compare bytes P[X+0...X+N-1]
       #bpf_insn { code=ldc, k=1 },     %% Jt: A=1
       #bpf_insn { code=jmp, k=1 },     %% skip
       #bpf_insn { code=ldc, k=0 },     %% Jf: A=0
       #bpf_insn { code=sta, k=Sp1 }    %% Store bool value
     ]}.  

%% compare 
expr_memcmp(<<X:32,Rest/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldiw, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      expr_memcmp(Rest, I+4, Jf-2)];
expr_memcmp(<<X:16,Rest/binary>>, I, Jf) ->
    [ #bpf_insn { code=ldih, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf } |
      expr_memcmp(Rest, I+2, Jf-2)];
expr_memcmp(<<X:8>>, I, Jf) ->
    [ #bpf_insn { code=ldib, k=I },
      #bpf_insn { code=jeqk, k=X, jt=0, jf=Jf }];
expr_memcmp(<<>>, _I, _Jf) ->
    [].


expr_list(_Op, [A]) -> A;
expr_list(Op, [A|As]) -> {Op, A, expr_list(Op,As)}.
    
%% test if "true" == (jgtk > 0)

%% Ax && Bx
land(Ax,Bx,Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1,Bc} = expr(Bx, Sp0),
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
lor(Ax,Bx,Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1,Bc} = expr(Bx, Sp0),
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
lnot(Ax, Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },     %% A = exp(Ax)
	   #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
	   #bpf_insn { code=ldc, k=0 },        %% A=false
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=1 },        %% A=false
	   #bpf_insn { code=sta, k=Sp1 }]}.

%% !!Ax convert integer to boolean
lbool(Ax,Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },     %% A = exp(Ax)
	   #bpf_insn { code=jgtk, k=0, jt=0, jf=2 },
	   #bpf_insn { code=ldc, k=1 },        %% A=true
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=0 },        %% A=false
	   #bpf_insn { code=sta, k=Sp1 }]}.

rop(Jop, Ax, Bx, Sp0) ->
    {Sp1,Bc} = expr(Bx, Sp0),
    {Sp2,Ac} = expr(Ax, Sp1),
    {Sp1, [Bc,Ac,
	   #bpf_insn { code=ldx, k=Sp1 },  %% X = exp(Bx)
	   #bpf_insn { code=lda, k=Sp2 },  %% A = exp(Ax)
	   #bpf_insn { code=Jop, jt=0, jf=2 }, %% A <jop> X
	   #bpf_insn { code=ldc, k=1 },        %% true value A=1
	   #bpf_insn { code=jmp, k=1 },        %% skip
	   #bpf_insn { code=ldc, k=0 },        %% true value A=0
	   #bpf_insn { code=sta, k=Sp1 }]}.

bop(Bop, Ax, Bx, Sp0) ->
    {Sp1,Bc} = expr(Bx, Sp0),
    {Sp2,Ac} = expr(Ax, Sp1),
    {Sp1, [Bc,Ac,
	   #bpf_insn { code=ldx, k=Sp1 },  %% X = exp(Bx)
	   #bpf_insn { code=lda, k=Sp2 },  %% A = exp(Ax)
	   #bpf_insn { code=Bop },        %% A = A <bop> X
	   #bpf_insn { code=sta, k=Sp1 }]}.

uop(Uop, Ax, Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1, [Ac,
	   #bpf_insn { code=lda, k=Sp1 },  %% A = exp(Ax)
	   #bpf_insn { code=Uop },         %% A = <uop> A
	   #bpf_insn { code=sta, k=Sp1 }]}.

iexpr(K,Sp0) when is_integer(K) ->
    Sp1 = Sp0-1,
    {Sp1, [#bpf_insn {code=ldc, k=K},
	   #bpf_insn {code=sta, k=Sp1}]}.

%% atom expression
aexpr(A, Sp0) ->
    case A of
	false        -> iexpr(0, Sp0);
	true         -> iexpr(1, Sp0);
	'tcp'        -> iexpr(?IPPROTO_TCP,Sp0);
	'udp'        -> iexpr(?IPPROTO_UDP,Sp0);
	'icmp'       -> iexpr(?IPPROTO_ICMP,Sp0);
	'ipv4'       -> iexpr(?ETHERTYPE_IP,Sp0);
	'ipv6'       -> iexpr(?ETHERTYPE_IPV6,Sp0);
	'arp'        -> iexpr(?ETHERTYPE_ARP,Sp0);
	'revarp'     -> iexpr(?ETHERTYPE_REVARP,Sp0);

	%% ethernet
	'eth.type'   -> expr({p,?OFFS_ETH_TYPE,2},Sp0);
	'eth.type.ipv4' -> expr({'==','eth.type', 'ipv4'},Sp0);
	'eth.type.ipv6' -> expr({'==','eth.type', 'ipv6'},Sp0);
	'eth.type.arp'  -> expr({'==','eth.type', 'arp'},Sp0);
	'eth.type.revarp' -> expr({'==','eth.type', 'revarp'},Sp0);
	'eth.data'        -> iexpr(?OFFS_ETH_DATA,Sp0); %% (offset)
	    
	%% arp
	'arp.htype'   -> expr({p,?OFFS_ARP_HTYPE,2},Sp0);
	'arp.ptype'   -> expr({p,?OFFS_ARP_PTYPE,2},Sp0);
	'arp.halen'   -> expr({p,?OFFS_ARP_HALEN,1},Sp0);
	'arp.palen'   -> expr({p,?OFFS_ARP_PALEN,1},Sp0);
	'arp.op'      -> expr({p,?OFFS_ARP_OP,2},Sp0);

	%% ipv4
	'ipv4.hlen'   -> pexpr(txa,{msh,?OFFS_IPV4_HLEN},0,Sp0);
	'ipv4.diffsrv'  -> expr({p,?OFFS_IPV4_DSRV,1},Sp0);
	'ipv4.len'      -> expr({p,?OFFS_IPV4_LEN,2},Sp0);
	'ipv4.id'       -> expr({p,?OFFS_IPV4_ID,2},Sp0);
	'ipv4.flag.df'  -> expr({'&',{'>>',{p,?OFFS_IPV4_FRAG,2},14},16#1},Sp0);
	'ipv4.flag.mf' -> expr({'&',{'>>',{p,?OFFS_IPV4_FRAG,2}, 13},16#1},Sp0);
	'ipv4.frag' ->  expr({'&',{p,?OFFS_IPV4_FRAG,2},16#1FFF},Sp0);
	'ipv4.ttl'   -> expr({p,?OFFS_IPV4_TTL,2},Sp0);
	'ipv4.proto' -> expr({p,?OFFS_IPV4_PROTO,1},Sp0);
	'ipv4.proto.tcp' -> expr({'==','ipv4.proto','tcp'},Sp0);
	'ipv4.proto.udp' -> expr({'==','ipv4.proto','udp'},Sp0);
	'ipv4.proto.icmp' -> expr({'==','ipv4.proto','icmp'},Sp0);
	'ipv4.dst'   -> expr({p,?OFFS_IPV4_DST,4},Sp0);
	'ipv4.src'   -> expr({p,?OFFS_IPV4_SRC,4},Sp0);
	'ipv4.options' -> iexpr(?OFFS_IPV4_DATA, Sp0); %% (offset)
	'ipv4.data'  -> expr({'+','eth.data','ipv4.hlen'}, Sp0);  %% (offset)

	%% ipv6
	'ipv6.len'   -> expr({p,?OFFS_IPV6_LEN,2},Sp0);
	'ipv6.next'  -> expr({p,?OFFS_IPV6_NEXT,1},Sp0);
	'ipv4.next.tcp' -> expr({'==','ipv6.next','tcp'},Sp0);
	'ipv4.next.udp' -> expr({'==','ipv6.next','udp'},Sp0);
	'ipv6.hopc'  -> expr({p,?OFFS_IPV6_HOPC,1},Sp0);
	'ipv6.payload' -> iexpr(?OFFS_IPV6_PAYLOAD, Sp0);

	%% tcp/ipv4
	'ipv4.tcp' -> expr('ipv4.data', Sp0); %% (offset)
	'ipv4.tcp.dst_port' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_DST_PORT,2},Sp0);
	'ipv4.tcp.src_port' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_SRC_PORT,2},Sp0);
	'ipv4.tcp.seq' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_SEQ,4},Sp0);
	'ipv4.tcp.ack' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_ACK,4},Sp0);
	'ipv4.tcp.flags' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_FLAGS,2},Sp0);
	'ipv4.tcp.window' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_WINDOW,2}, Sp0);
	'ipv4.tcp.csum' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_CSUM,2}, Sp0);
	'ipv4.tcp.uptr' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_TCP_UPTR,2}, Sp0);
	'ipv4.tcp.flag.fin' -> expr({'&','ipv4.tcp.flags', 16#1}, Sp0);
	'ipv4.tcp.flag.syn' -> expr({'&',{'>>','ipv4.tcp.flags',1},1}, Sp0);
	'ipv4.tcp.flag.rst' -> expr({'&',{'>>','ipv4.tcp.flags',2},1}, Sp0);
	'ipv4.tcp.flag.psh' -> expr({'&',{'>>','ipv4.tcp.flags',3},1}, Sp0);
	'ipv4.tcp.flag.ack' -> expr({'&',{'>>','ipv4.tcp.flags',4},1}, Sp0);
	'ipv4.tcp.flag.urg' -> expr({'&',{'>>','ipv4.tcp.flags',5},1}, Sp0);
	'ipv4.tcp.data_offset' ->
	    expr({'>>',{'&',{p,{msh,?OFFS_IPV4_HLEN},
			     ?XOFFS_TCP_FLAGS,1},16#f0},2}, Sp0);
	'ipv4.tcp.data' -> %% start of data in data packet (offset)
	    expr({'+','ipv4.tcp.data_offset','ipv4.tcp'}, Sp0);

	%% udp/ipv4
	'ipv4.udp' -> expr('ipv4.data', Sp0); %% (offset)
	'ipv4.udp.dst_port' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_DST_PORT,2}, Sp0);
	'ipv4.udp.src_port' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_SRC_PORT,2}, Sp0);
	'ipv4.udp.length' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_LENGTH,2}, Sp0);
	'ipv4.udp.csum' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_CSUM,2}, Sp0);
	'ipv4.udp.data' -> %% (offset to data)
	    expr({'+','ipv4.hlen',?XOFFS_UDP_DATA}, Sp0);

	%% tcp/ipv6
	'ipv6.tcp' -> expr('ipv6.payload', Sp0); %% (offset)
	'ipv6.tcp.dst_port' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_DST_PORT,2},Sp0);
	'ipv6.tcp.src_port' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_SRC_PORT,2},Sp0);
	'ipv6.tcp.seq' ->
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_SEQ,4},Sp0);
	'ipv6.tcp.ack' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_ACK,4},Sp0);
	'ipv6.tcp.flags' ->
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_FLAGS,2},Sp0);
	'ipv6.tcp.window' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_WINDOW,2}, Sp0);
	'ipv6.tcp.csum' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_CSUM,2}, Sp0);
	'ipv6.tcp.uptr' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_UPTR,2}, Sp0);
	'ipv6.tcp.flag.fin' -> expr({'&','ipv6.tcp.flags', 16#1}, Sp0);
	'ipv6.tcp.flag.syn' -> expr({'&',{'>>','ipv6.tcp.flags',1},1}, Sp0);
	'ipv6.tcp.flag.rst' -> expr({'&',{'>>','ipv6.tcp.flags',2},1}, Sp0);
	'ipv6.tcp.flag.psh' -> expr({'&',{'>>','ipv6.tcp.flags',3},1}, Sp0);
	'ipv6.tcp.flag.ack' -> expr({'&',{'>>','ipv6.tcp.flags',4},1}, Sp0);
	'ipv6.tcp.flag.urg' -> expr({'&',{'>>','ipv6.tcp.flags',5},1}, Sp0);
	'ipv6.tcp.data_offset' ->
	    expr({'>>',{'&',
			{p,?OFFS_IPV6_PAYLOAD+?OFFS_TCP_FLAGS,1},16#f0},2},Sp0);
	'ipv6.tcp.data' -> %% start of data in data packet (offset)
	    expr({'+','ipv6.tcp.data_offset','ipv6.tcp'}, Sp0);
	%% udp/ipv6
	'ipv6.udp.dst_port' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_UDP_DST_PORT,2}, Sp0);
	'ipv6.udp.src_port' ->
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_UDP_SRC_PORT,2}, Sp0);
	'ipv6.udp.length' -> 
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_UDP_LENGTH,2}, Sp0);
	'ipv6.udp.csum' ->
	    expr({p,?OFFS_IPV6_PAYLOAD+?OFFS_UDP_CSUM,2}, Sp0)
    end.


pexpr(Code,K0,Sp0) ->
    K = pexpr_k(K0),
    Sp1 = Sp0-1,
    {Sp1, 
     [#bpf_insn { code=Code, k=K },
      #bpf_insn { code=sta, k=Sp1 }]}.

pexpr(Code,Ax,K0,Sp0) ->  %% indexed expression
    K = pexpr_k(K0),
    {SpX,AcX} = case Ax of
		    {msh,Kx} -> 
			{Sp0-1,[#bpf_insn{code=ldxmsh,k=Kx}]};
		    _ ->
			{Sp1,Ac} = expr(Ax, Sp0),
			{Sp1,[Ac,#bpf_insn { code=ldx,  k=Sp1 }]}
		end,
    {SpX, [AcX,
	   #bpf_insn { code=Code, k=K }, 
	   #bpf_insn { code=sta,  k=SpX }
	  ]}.

pexpr_k(K) when is_integer(K) ->
    K;
pexpr_k(K) when is_atom(K) ->
    case K of
	%% eth offsets
	'eth.dst'    -> ?OFFS_ETH_DST;
	'eth.src'    -> ?OFFS_ETH_SRC;
	'eth.type'   -> ?OFFS_ETH_TYPE;
	'eth.data'   -> ?OFFS_ETH_DATA;
	%% arp offsets
	'arp.htype'   -> ?OFFS_ARP_HTYPE;
	'arp.ptype'   -> ?OFFS_ARP_PTYPE;
	'arp.halen'   -> ?OFFS_ARP_HALEN;
	'arp.palen'   -> ?OFFS_ARP_PALEN;
	'arp.op'      -> ?OFFS_ARP_OP;
	%% ipv4 offsets
	'ipv4.hlen'  -> ?OFFS_IPV4_HLEN;
	'ipv4.dsrv'  -> ?OFFS_IPV4_DSRV;
	'ipv4.len'   -> ?OFFS_IPV4_LEN;
	'ipv4.id'    -> ?OFFS_IPV4_ID;
	'ipv4.frag'  -> ?OFFS_IPV4_FRAG;
	'ipv4.ttl'   -> ?OFFS_IPV4_TTL;
	'ipv4.proto' -> ?OFFS_IPV4_PROTO;
	'ipv4.dst'   -> ?OFFS_IPV4_DST;
	'ipv4.src'   -> ?OFFS_IPV4_SRC;
	%% ipv6 offsets
	'ipv6.len'   -> ?OFFS_IPV6_LEN;
	'ipv6.next'  -> ?OFFS_IPV6_NEXT;
	'ipv6.hopc'  -> ?OFFS_IPV6_HOPC;
	'ipv6.dst'   -> ?OFFS_IPV6_DST;
	'ipv6.src'   -> ?OFFS_IPV6_SRC
    end.

%% some common expressions
is_arp() ->    {'==', 'eth.type', 'arp'}.
is_revarp() -> {'==', 'eth.type', 'revarp'}.
is_ipv4() ->   {'==', 'eth.type', 'ipv4'}.
is_ipv6() ->   {'==', 'eth.type', 'ipv6'}.
is_ip() ->     {'||', is_ipv4(), is_ipv6()}.
is_ipv4_proto(Proto) ->
    {'&&', is_ipv4(),  {'==', 'ipv4.proto', Proto }}.
is_ipv6_proto(Proto) ->
    {'&&', is_ipv6(),  {'==', 'ipv6.next',  Proto }}.
is_tcp() ->
    {'||',  is_ipv4_proto('tcp'), is_ipv6_proto('tcp')}.
is_udp() ->
    {'||',  is_ipv4_proto('udp'), is_ipv6_proto('udp')}.
is_icmp() -> %% icmp6 is different ...
    {'&&',   is_ipv4(), {'==', 'ipv4.proto', 'icmp' }}.
is_ipv4_tcp_src(Src) ->
    {'&&', is_ipv4_proto(tcp),  {'==','ipv4.src', ipv4(Src)}}.
is_ipv4_tcp_dst(Dst) ->
    {'&&', is_ipv4_proto(tcp), {'==','ipv4.dst', ipv4(Dst)}}.
is_ipv4_tcp_dst_port(Port) ->
    {'&&', is_ipv4_proto(tcp), {'==', 'ipv4.tcp.dst_port', Port}}.
is_ipv4_tcp_src_port(Port) ->
    {'&&', is_ipv4_proto(tcp), {'==', 'ipv4.tcp.src_port', Port}}.
is_ipv6_tcp_dst_port(Port) ->
    {'&&', is_ipv6_proto(tcp), {'==', 'ipv6.tcp.dst_port', Port}}.
is_ipv6_tcp_src_port(Port) ->
    {'&&', is_ipv6_proto(tcp), {'==', 'ipv6.tcp.src_port', Port}}.

is_tcp_dst_port(Port) ->
    {'||', is_ipv4_tcp_dst_port(Port), is_ipv6_tcp_dst_port(Port)}.
is_tcp_src_port(Port) ->
    {'||', is_ipv4_tcp_dst_port(Port), is_ipv6_tcp_dst_port(Port)}.

is_tcp_syn() ->
    {'||', 
     {'&&', is_ipv4_proto(tcp), 'ipv4.tcp.flag.syn'},
     {'&&', is_ipv6_proto(tcp), 'ipv6.tcp.flag.syn'}}.

is_tcp_ack() ->
    {'||', 
     {'&&', is_ipv4_proto(tcp), 'ipv4.tcp.flag.ack'},
     {'&&', is_ipv6_proto(tcp), 'ipv6.tcp.flag.ack'}}.

is_tcp_fin() ->
   {'||', 
     {'&&', is_ipv4_proto(tcp), 'ipv4.tcp.flag.fin'},
     {'&&', is_ipv6_proto(tcp), 'ipv6.tcp.flag.fin'}}.

is_tcp_psh() ->
   {'||', 
     {'&&', is_ipv4_proto(tcp), 'ipv4.tcp.flag.psh'},
     {'&&', is_ipv6_proto(tcp), 'ipv6.tcp.flag.psh'}}.

is_tcp_urg() ->
    {'||', 
     {'&&', is_ipv4_proto(tcp), 'ipv4.tcp.flag.urg'},
     {'&&', is_ipv6_proto(tcp), 'ipv6.tcp.flag.urg'}}.


%% convert ipv4 address to uint32 format
ipv4({A,B,C,D}) ->	  
    (A bsl 24) + (B bsl 16) + (C bsl 8) + D;
ipv4(IPV4) when is_integer(IPV4) ->
    ?uint32(IPV4).

if_ethertype(Value, True, False) ->
    [#bpf_insn{code=ldah, k=?OFFS_ETH_TYPE} | if_eqk(Value, True, False)].

if_arpop(Value, True, False) ->
    [#bpf_insn{code=ldah, k=?OFFS_ARP_OP} | if_eqk(Value, True, False)].

if_ip_src(Value, True, False) ->
    [#bpf_insn{code=ldaw, k=?OFFS_IPV4_SRC} | if_eqk(Value, True, False)].

if_ip_dst(Value, True, False) ->
    [#bpf_insn{code=ldaw, k=?OFFS_IPV4_DST} | if_eqk(Value, True, False)].

if_ip_fragments(True, False) ->
    [ #bpf_insn{code=ldah, k=?OFFS_IPV4_FRAG } | if_setk(16#1fff, True, False)].

%% ipv4 | tcp/udp src port
if_port_src(Value, True, False) ->
    [ #bpf_insn{code=ldxmsh, k=?OFFS_IPV4_HLEN },
      #bpf_insn{code=ldih, k=14 } | if_eqk(Value, True, False)].

%% ipv4 | tcp/udp src port
if_port_dst(Value, True, False) ->
    [ #bpf_insn{code=ldxmsh, k=?OFFS_IPV4_HLEN },
      #bpf_insn{code=ldih, k=16 } | if_eqk(Value, True, False)].
    
if_ip_protocol(Value, True, False) ->
    [ #bpf_insn{code=ldab, k=?OFFS_IPV4_PROTO } | if_eqk(Value, True, False) ].

if_tcp(True, False) ->
    if_ip_protocol(?IPPROTO_TCP, True, False).

if_udp(True, False) ->
    if_ip_protocol(?IPPROTO_UDP, True, False).

if_eqk(K, True, False) ->
    if_opk(jeqk, K, True, False).

if_gtk(K, True, False) ->
    if_opk(jgtk, K, True, False).

if_gek(K, True, False) ->
    if_opk(jgek, K, True, False).

if_setk(K, True, False) ->
    if_opk(jsetk, K, True, False).

if_opk(Op,K,True,False) ->
    LT = code_length(True),
    LF = code_length(False),
    [ #bpf_insn{code=Op, k=K, jt=0, jf=LT+1 },
      True,
      #bpf_insn{code=jmp,k=LF+1},
      False,
      nop() ].

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

	    
