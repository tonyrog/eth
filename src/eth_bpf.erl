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

-import(lists, [reverse/1]).

%% "compile" the program 
encode(Prog) when is_tuple(Prog) ->
    list_to_binary([ encode_(B) || B <- tuple_to_list(Prog)]).

encode_(#bpf_insn{code=ldaw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_ABS, K);
encode_(#bpf_insn{code=ldah,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_ABS,K);
encode_(#bpf_insn{code=ldab,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_ABS, K);

encode_(#bpf_insn{code=ldiw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_IND,K);
encode_(#bpf_insn{code=ldih,k=K}) -> insn(?BPF_LD+?BPF_H +?BPF_IND,K);
encode_(#bpf_insn{code=ldib,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_IND,K);

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
	jsetk -> {jmp,'&=',k};
	jgtx  -> {jmp,'>', x};
	jgex  -> {jmp,'>=',x};
	jeqx  -> {jmp,'==',x};
	jsetx -> {jmp,'&=',x};

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
	txa ->  {misc,a,x};
	dead -> {misc,dead,dead}
    end.

%%
%% Print BPF
%%
print_bs([B|Bs]) when is_record(B, bpf_block) ->
    io:format("~w:\n", [B#bpf_block.label]),
    lists:foreach(
      fun(I) ->
	      print_insn("    ", -1, I)
      end, B#bpf_block.insns),
    print_insn("    ", -1, B#bpf_block.next),
    print_bs(Bs);
print_bs([]) ->
    ok.
    
    
print(Prog) when is_tuple(Prog) ->
    print_(Prog, 1).
    
print_(Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    L = io_lib:format("~.3.0w: ", [J]),
    print_insn(L, J, I),
    print_(Prog, J+1);
print_(Prog, _J) ->
    Prog.

print_insn(L, J, I) ->
    case class(I) of
	{jmp,Cond,R} ->
	    print_jmp_(Cond,R,I,L,J);
	{ld,Dst,Src} ->
	    print_ld_(Dst,Src,I,L);
	_ ->
	    case I of
		#bpf_insn { code=dead } ->
		    io:format("~sdead\n", [L]);
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


print_ld_(Dst,Src,_I,L) ->
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

print_jmp_(true,k,I,L,J) ->
    if I#bpf_insn.k =:= 0 ->
	    io:format("~snop;\n", [L]);
       true ->
	    io:format("~sgoto ~.3.0w;\n", 
		      [L,J+1+I#bpf_insn.k])
    end;
print_jmp_(Cond,k,I,L,J) ->
    io:format("~sif (A ~s ~w) goto ~.3.0w; else goto ~.3.0w;\n", 
	      [L,Cond,I#bpf_insn.k,
	       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]);
print_jmp_(Cond,x,I,L,J) ->
    io:format("~sif (A ~s X) goto ~.3.0w; else goto ~.3.0w;\n", 
	      [L,Cond,
	       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]).

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
%% Optimise BPF programes
%%
optimise(Prog) when is_tuple(Prog) ->
    optimise_meth_(Prog,
		   [
		    fun remove_multiple_jmp/1,
		    fun remove_ld/1,
		    fun remove_st/1,
		    fun kill_nops/1,
		    fun remove_multiple_jmp/1,
		    fun print/1,
		    fun validate/1
		   ]).

optimise_meth_(Prog, [F|Fs]) ->
    case F(Prog) of
	E={error,_} -> E;
	Prog1 ->
	    if Prog =/= Prog1 -> print(Prog1); true -> ok end,    
	    optimise_meth_(Prog1, Fs)
    end;
optimise_meth_(Prog, []) ->
    Prog.


%% remove duplicate/unnecessary ld M[K] instructions or a sta
%% Ex1:
%%    1: M[14] = A
%%    2: A = M[14]   (killed, if not target address!)
%% Ex2:
%%    1: M[14] = A
%%    2: X = M[15]
%%    3: A = M[14]   (killed, if not target address!)
%% Ex3:
%%    1: M[14] = A
%%    2: A = A + 45  (killed, not used since A is reloaded in 3)
%%    3: A = M[14]   (killed, since result is the same as in 1)
%%
remove_ld(Prog) ->
    %% keep this to be sure we do not remove instructions that can be reach
    %% by jumps.
    Map = build_target_map_(Prog),
    remove_ld_(Prog, 1, Map).

remove_ld_(Prog, J, Map) when J >= 1, J =< tuple_size(Prog) ->
    I1 = element(J,Prog),
    I2 = if J+1 =< tuple_size(Prog) -> element(J+1,Prog); true -> undefined end,
    I3 = if J+2 =< tuple_size(Prog) -> element(J+2,Prog); true -> undefined end,
    case {I1,I2,I3} of
	{ #bpf_insn { code=sta, k=K }, #bpf_insn { code=lda, k=K  }, _ } ->
	    Prog1 = maybe_nop_(Prog, [J+1], Map),
	    remove_ld_(Prog1, J+1, Map);
	{ #bpf_insn { code=sta, k=K }, _, #bpf_insn { code=lda, k=K  }} ->
	    Js = case class(I2) of
		     {ret,_}      -> [];
		     {jmp,_,_}    -> [];
		     {alu,_,_}    -> [J+1,J+2];
		     {misc,a,x}   -> [J+1,J+2];
		     {misc,x,a}   -> [J+2];
		     {misc,dead,_} -> [J+2];
		     {st,a,{k,K}} -> [J+1,J+2];
		     {st,_,_}     -> [J+2];
		     {ld,x,_}     -> [J+2];
		     {ld,a,_}     -> [J+1,J+2]
		 end,
	    Prog1 = maybe_nop_(Prog, Js, Map),
	    remove_ld_(Prog1, J+1, Map);
	_ ->
	    remove_ld_(Prog, J+1, Map)
    end;
remove_ld_(Prog, _J, _Map) ->
    Prog.

maybe_nop_(Prog, Js, Map) ->
    case lists:any(fun(J) -> element(J,Map) end, Js) of
	true  -> Prog;  %% there are jumps into this code
	false ->
	    lists:foldl(
	      fun(J,Pi) ->
		      io:format("~.3.0w: set to nop\n", [J]),
		      setelement(J,Pi,nop())
	      end, Prog, Js)
    end.

%% remove unnecessary sta|stx instructions ( M[K]=A|X )
%% Case1
%%    1: M[k]=A
%%    ... M[k] is never loaded, kill it
%% Ex2:
%%    1: M[k]=X
%%    ... M[k] is never loaded, kill it
%%
remove_st(Prog) ->
    remove_st_(Prog, 1).

remove_st_(Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case class(I) of
	{st,_,{m,K}} ->
	    case find_ld_(Prog, J+1, K) of
		false ->
		    io:format("~.3.0w: set to nop\n", [J]),
		    Prog1 = setelement(J,Prog,nop()),
		    remove_st_(Prog1, J+1);
		true ->
		    remove_st_(Prog, J+1)
	    end;
	_ ->
	    remove_st_(Prog, J+1)
    end;
remove_st_(Prog, _J) ->
    Prog.

find_ld_(Prog, J, K) when J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case class(I) of
	{ld,_,{m,K}} -> true;
	_ -> find_ld_(Prog, J+1, K)
    end;
find_ld_(_Prog, _J, _K) ->
    false.


%% remove indirection jumps & move return 
remove_multiple_jmp(Prog) ->
    case optimise_jmp_(Prog, 1) of
	Prog -> Prog;
	Prog1 ->
	    Prog2 = mark_unreach(Prog1),
	    compact(Prog2)
    end.

optimise_jmp_(Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case class(I) of 
	{jmp,true,k} ->
	    K0 = I#bpf_insn.k,
	    case follow_jump_(Prog, J, K0) of
		{I1=#bpf_insn{code=reta}, _} ->
		    io:format("~.3.0w: jump to ~w changed to ~w\n", 
			      [J,K0,reta]),
		    Prog1=setelement(J,Prog,I1),
		    optimise_jmp_(Prog1, J+1);
		{I1=#bpf_insn{code=retk}} ->
		    io:format("~.3.0w: jump to ~w changed to ~w\n", 
			      [J,K0,retk]),
		    Prog1=setelement(J,Prog,I1),
		    optimise_jmp_(Prog1, J+1);
		{_,K1} ->
		    io:format("~.3.0w: jump to ~w changed to ~w\n", [J,K0,K1]),
		    Prog1=setelement(J,Prog,I#bpf_insn { k=K1 }),
		    optimise_jmp_(Prog1, J+1);
		_ ->
		    optimise_jmp_(Prog, J+1)
	    end;
	{jmp,_Cond,_R} ->
	    optimise_cond_jmp_(Prog,J,I);
	_ ->
	    optimise_jmp_(Prog, J+1)
    end;
optimise_jmp_(Prog, _J) ->
    Prog.

%% optimise conditional lables by tracing jump path
%% follow unconditional jumps, also if jump ends in 
%% retk or reta find the last occurence of a retk|reta
%% and jump there (fixme long jumps!)

optimise_cond_jmp_(Prog,J,I) ->
    Jt0 = I#bpf_insn.jt,
    Jf0 = I#bpf_insn.jf,
    {It,Jt1} = follow_jump_(Prog,J,Jt0),
    {If,Jf1} = follow_jump_(Prog,J,Jf0),
    Jt2 = jmp_last_return(Prog,J,It,Jt1),
    Jf2 = jmp_last_return(Prog,J,If,Jf1),
    io:format("~.3.0w: jt ~w->~w, ft ~w->~w\n", [J,Jt0,Jt2,Jf0,Jf2]),
    Prog1=setelement(J,Prog,I#bpf_insn { jt=Jt2, jf=Jf2 }),
    optimise_jmp_(Prog1, J+1).

jmp_last_return(Prog,J,I=#bpf_insn{code=retk},_Offs) ->
    J1 = jmp_last_pos_(Prog,J,tuple_size(Prog),I),
    (J1-J)-1;
jmp_last_return(Prog,J,I=#bpf_insn{code=reta},_Offs) ->
    J1 = jmp_last_pos_(Prog,J,tuple_size(Prog),I),
    (J1 - J)-1;
jmp_last_return(_Prog,_J,_I,Offs) ->
    Offs.

jmp_last_pos_(Prog,J,J1,I) ->
    case element(J1,Prog) of
	I -> J1;
	_ -> jmp_last_pos_(Prog,J,J1-1,I)
    end.

follow_jump_(Prog,J,Offs) ->
    J1 = J+1+Offs,
    I  = element(J1,Prog),
    case I of
	#bpf_insn { code=jmp, k=K} ->
	    follow_jump_(Prog,J,Offs+1+K);
	_ -> {I,Offs}
    end.

%%
%% Create basic block representation from program.
%%
make_basic_block(Prog) when is_tuple(Prog) ->
    Map = build_target_map_(Prog),
    make_basic_block_(Prog, 1, Map, 1, [], []).

make_basic_block_(Prog, J, Map, A, Acc, Bs) when J =< tuple_size(Prog) ->
    I = element(J, Prog),
    case class(I) of
	{jmp,true,_} ->
	    L = J+1+I#bpf_insn.k, %% absolute jump address!
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = I#bpf_insn { k = L }},
	    make_basic_block_(Prog,J+1,Map,J+1,[],[B|Bs]);
	{jmp,_,_} ->
	    Lt = J+1+I#bpf_insn.jt,
	    Lf = J+1+I#bpf_insn.jf,
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I#bpf_insn { jt=Lt, jf=Lf }},
	    make_basic_block_(Prog,J+1,Map,J+1,[],[B|Bs]);
	{ret,_} ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I},
	    make_basic_block_(Prog,J+1,Map,J+1,[],[B|Bs]);
	_ ->
	    case element(J,Map) of
		true -> %% J: is a jump target
		    if Acc == [] ->
			    io:format("Acc empty\n"),
			    make_basic_block_(Prog,J+1,Map,J,[I],Bs);
		       true ->
			    io:format("Insert: Goto ~w\n", [J]),
			    B = #bpf_block { label = A,
					     insns = reverse(Acc),
					     next = #bpf_insn { code=jmp, 
								k = J }},
			    make_basic_block_(Prog,J+1,Map,J,[I],[B|Bs])
		    end;
		false ->
		    make_basic_block_(Prog,J+1,Map,A,[I|Acc],Bs)
	    end
    end;
make_basic_block_(_Prog, _J, _Map, A, Acc, Bs) ->
    if Acc =:= [] ->
	    reverse(Bs);
       true ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = reject()     %% default reject ?
			   },
	    reverse([B|Bs])
    end.

%%
%% Mark all unreachable instruction (replace them with 'dead')
%%
mark_unreach(Prog) ->
    Rs = mark_unreach_(Prog, queue:in(1, queue:new()), 
		       sets:from_list([1])),
    %% done mark all instructions not in Rs as unreach
    lists:foldl(
      fun(J,Pj) ->
	      case sets:is_element(J, Rs) of
		  false -> 
		      io:format("~.3.0w: set to dead\n", [J]),
		      setelement(J, Pj, #bpf_insn { code=dead });
		  true -> Pj
	      end
      end, Prog, lists:seq(1, tuple_size(Prog))).

mark_unreach_(Prog, Q, Rs) ->
    case queue:out(Q) of
	{empty,_Q1} ->
	    Rs;
	{{value,J},Q1} ->
	    I = element(J, Prog),
	    case class(I) of
		{jmp,true,k} ->
		    mark_uncond_unreach_(Prog,J+1+I#bpf_insn.k,Q1,Rs);
		{jmp,_Cond,_R} ->
		    mark_cond_unreach_(Prog,J,I,Q1,Rs);
		_ ->
		    case I#bpf_insn.code of
			reta  -> mark_unreach_(Prog,Q1,Rs);
			retk  -> mark_unreach_(Prog,Q1,Rs);
			_ -> mark_uncond_unreach_(Prog,J+1,Q1,Rs)
		    end
	    end
    end.

mark_uncond_unreach_(Prog,J,Q,Rs) ->		    
    case sets:is_element(J, Rs) of
	true ->
	    mark_unreach_(Prog, Q, Rs);
	false ->
	    Rs1 = sets:add_element(J, Rs),
	    Q1  = queue:in(J, Q),
	    mark_unreach_(Prog, Q1, Rs1)
    end.
    
mark_cond_unreach_(Prog,J,I,Q0,Rs0) ->
    Jt = J+1+I#bpf_insn.jt,
    {Q1,Rs1} = case sets:is_element(Jt, Rs0) of
		   true  -> {Q0,Rs0};
		   false -> {queue:in(Jt, Q0),
			     sets:add_element(Jt,Rs0)}
	       end,
    Jf = J+1+I#bpf_insn.jf,
    {Q2,Rs2} = case sets:is_element(Jf, Rs1) of
		   true  -> {Q1,Rs1};
		   false -> {queue:in(Jf, Q1),
			     sets:add_element(Jf,Rs1)}
	       end,
    mark_unreach_(Prog, Q2, Rs2).

%%
%% Kill nops (replace with dead) if possible
%%
kill_nops(Prog) ->
    Map = build_target_map_(Prog),
    kill_nops_(Prog, 1, Map, 0).

kill_nops_(Prog, J, Map, N) when J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case I of
	#bpf_insn {code=jmp,k=0} ->
	    case element(J,Map) of
		true -> kill_nops_(Prog, J+1, Map, N);
		false ->
		    io:format("~.3.0w: set to dead\n", [J]),
		    Prog1 = setelement(J, Prog, #bpf_insn { code=dead }),
		    kill_nops_(Prog1,J+1,Map,N+1)
	    end;
	_ ->
	    kill_nops_(Prog,J+1,Map,N)
    end;
kill_nops_(Prog,_J,_Map,N) ->
    if N > 0 -> compact(Prog);
       true -> Prog
    end.

%%
%% Remove all dead position in the code
%%
compact(Prog) ->
    Map = build_number_map_(Prog),
    compact_build_(Prog,1,Map,[]).
    
%% build the new code where the unreach instructions are removed by
%% updating jump instructions with new offsets
compact_build_(Prog,J,Map,Acc) when J =< tuple_size(Prog) ->
    I = element(J,Prog),
    case class(I) of
	{jmp,true,k} ->
	    J1 = J+1+I#bpf_insn.k,
	    K1 = (element(J1,Map)-element(J,Map))-1,
	    compact_build_(Prog,J+1,Map,
				    [I#bpf_insn { k=K1} | Acc]);
	{jmp,_Cond,_R} ->
	    J1 = J+1+I#bpf_insn.jt,
	    Jt = (element(J1,Map)-element(J,Map))-1,
	    J2 = J+1+I#bpf_insn.jf,
	    Jf = (element(J2,Map)-element(J,Map))-1,
	    compact_build_(Prog,J+1,Map,
				    [I#bpf_insn { jt=Jt,jf=Jf} | Acc]);
	_ ->
	    if I#bpf_insn.code =:= dead ->
		    compact_build_(Prog,J+1,Map,Acc);
	       true ->
		    compact_build_(Prog,J+1,Map,[I|Acc])
	    end
    end;
compact_build_(_Prog,_J,_Map,Acc) ->
    list_to_tuple(reverse(Acc)).

%%
%% Create a map from instruction position to instruction number
%% not counting the dead instructions (generated by mark_unreach_)
%%
build_number_map_(Prog) ->
    build_number_map_(Prog,1,1,[]).

%% build a map of instruction numbers
build_number_map_(Prog,J,J1,Acc) when J =< tuple_size(Prog) ->
    case element(J, Prog) of
	#bpf_insn {code=dead} -> build_number_map_(Prog,J+1,J1,[J1|Acc]);
	_ -> build_number_map_(Prog,J+1,J1+1,[J1|Acc])
    end;
build_number_map_(_Prog,_J0,_J1,Acc) ->
    list_to_tuple(reverse(Acc)).

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
exec(Is, P) when is_list(Is), is_binary(P) ->
    exec(list_to_tuple(Is), P);
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

-define(uint32(X), ((X) band 16#ffffffff)).

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

-define(XOFFS_UDP_SRC_PORT, ?OFFS_ETH_DATA+?OFFS_UDP_SRC_PORT).
-define(XOFFS_UDP_DST_PORT, ?OFFS_ETH_DATA+?OFFS_UDP_DST_PORT).
-define(XOFFS_UDP_LENGTH,   ?OFFS_ETH_DATA+?OFFS_UDP_LENGTH).
-define(XOFFS_UDP_CSUM,     ?OFFS_ETH_DATA+?OFFS_UDP_CSUM).


build_program(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,reject()])),
    case validate(Prog) of
	E={error,_} -> E;
	_ -> 
	    Prog1 = optimise(Prog),
	    Bs = make_basic_block(Prog1),
	    print_bs(Bs),
	    Prog1
    end.

build_programa(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,return()])),
    case validate(Prog) of
	E={error,_} -> E;
	_ -> 
	    Prog1 = optimise(Prog),
	    Bs = make_basic_block(Prog1),
	    print_bs(Bs),
	    Prog1
    end.

build_programx(Expr) ->
    X = expr(Expr),
    Prog = list_to_tuple(lists:flatten([X,
					if_gtk(0, [accept()], [reject()]),
					reject()])),
    print(Prog),
    case validate(Prog) of
	E={error,_} -> E;
	_ -> 
	    Prog1 = optimise(Prog),
	    Bs = make_basic_block(Prog1),
	    print_bs(Bs),
	    Prog1
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
expr({'|',Ax,Bx},Sp) -> bop(borx,Ax,Bx,Sp);
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
expr({'||',Ax,Bx},Sp) -> lor(Ax,Bx,Sp).

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
      #bpf_insn { code=ldc, k=1 },        %% true value A=1
      #bpf_insn { code=jmp, k=1 },        %% skip
      #bpf_insn { code=ldc, k=0 },        %% true value A=0
      #bpf_insn { code=sta, k=Sp1 }]}.

%% Ax || Bx
lor(Ax,Bx,Sp0) ->
    {Sp1,Ac} = expr(Ax, Sp0),
    {Sp1,Bc} = expr(Bx, Sp0),
    LBc = code_length(Bc),
    {Sp1,
     [Ac,
      #bpf_insn { code=lda, k=Sp1 },      %% A = exp(Ax)
      #bpf_insn { code=jgtk, k=0, jt=LBc+3, jf=0 },
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
	%% packet access 
	'eth.type'   -> expr({p,?OFFS_ETH_TYPE,2},Sp0);

	'arp.htype'   -> expr({p,?OFFS_ARP_HTYPE,2},Sp0);
	'arp.ptype'   -> expr({p,?OFFS_ARP_PTYPE,2},Sp0);
	'arp.halen'   -> expr({p,?OFFS_ARP_HALEN,1},Sp0);
	'arp.palen'   -> expr({p,?OFFS_ARP_PALEN,1},Sp0);
	'arp.op'      -> expr({p,?OFFS_ARP_OP,2},Sp0);

	'ipv4.hlen'   -> pexpr(txa,{msh,?OFFS_IPV4_HLEN},0,Sp0);
	'ipv4.diffsrv'  -> expr({p,?OFFS_IPV4_DSRV,1},Sp0);
	'ipv4.len'      -> expr({p,?OFFS_IPV4_LEN,2},Sp0);
	'ipv4.id'       -> expr({p,?OFFS_IPV4_ID,2},Sp0);
	'ipv4.flag.df'  -> expr({'&',{'>>',{p,?OFFS_IPV4_FRAG,2},14},16#1},Sp0);
	'ipv4.flag.mf' -> expr({'&',{'>>',{p,?OFFS_IPV4_FRAG,2}, 13},16#1},Sp0);
	'ipv4.frag' ->  expr({'&',{p,?OFFS_IPV4_FRAG,2},16#1FFF},Sp0);
	'ipv4.ttl'   -> expr({p,?OFFS_IPV4_TTL,2},Sp0);
	'ipv4.proto' -> expr({p,?OFFS_IPV4_PROTO,1},Sp0);
	'ipv4.dst'   -> expr({p,?OFFS_IPV4_DST,4},Sp0);
	'ipv4.src'   -> expr({p,?OFFS_IPV4_SRC,4},Sp0);

	'ipv6.len'   -> expr({p,?OFFS_IPV6_LEN,2},Sp0);
	'ipv6.next'  -> expr({p,?OFFS_IPV6_NEXT,1},Sp0);
	'ipv6.hopc'  -> expr({p,?OFFS_IPV6_HOPC,1},Sp0);

	%% TCP / UDP (currently only IPV4)

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
	    expr({'*',{'>>','ipv4.tcp.flags',12},4},Sp0);
	'ipv4.udp.dst_port' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_DST_PORT,2}, Sp0);
	'ipv4.udp.src_port' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_SRC_PORT,2}, Sp0);
	'ipv4.udp.length' -> 
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_LENGTH,2}, Sp0);
	'ipv4.udp.csum' ->
	    expr({p,{msh,?OFFS_IPV4_HLEN},?XOFFS_UDP_CSUM,2}, Sp0);

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
	    expr({'*',{'>>','ipv6.tcp.flags',12},4},Sp0);

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
