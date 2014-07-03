%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Basic bpf functions
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf).

-export([asm/1, disasm/1]).
-export([validate/1]).
-export([print/1, print/2]).
-export([print_p/1, print_p/2]).
-export([print_c/1, print_c/2]).
-export([print_insn_c/4, print_insn_p/3]).

-export([accept/0, reject/0, return/1, return/0, nop/0]).
-export([class/1, fanout/1]).

-include("eth_bpf.hrl").

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

%% return a list of output labels.
%% #bpf_insn{} => [label()]
%%
fanout(I=#bpf_insn { jt=Jt, jf=Jf, k=K }) ->
    case class(I) of
	{jmp,true,_} -> [K];
	{jmp,_Cond,_R} -> [Jt,Jf];
	_ -> []
    end;
fanout(undefined) ->
    [].

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


%% assemble the program 
asm(Prog) when is_tuple(Prog) ->
    list_to_binary([ asm_(B) || B <- tuple_to_list(Prog)]).

asm_(#bpf_insn{code=ldaw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_ABS, K);
asm_(#bpf_insn{code=ldah,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_ABS,K);
asm_(#bpf_insn{code=ldab,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_ABS, K);

asm_(#bpf_insn{code=ldiw,k=K}) -> insn(?BPF_LD+?BPF_W+?BPF_IND,K);
asm_(#bpf_insn{code=ldih,k=K}) -> insn(?BPF_LD+?BPF_H+?BPF_IND,K);
asm_(#bpf_insn{code=ldib,k=K}) -> insn(?BPF_LD+?BPF_B+?BPF_IND,K);

asm_(#bpf_insn{code=ldl })      -> insn(?BPF_LD + ?BPF_LEN);
asm_(#bpf_insn{code=ldc, k=K})  -> insn(?BPF_LD + ?BPF_IMM, K);
asm_(#bpf_insn{code=lda, k=K})  -> insn(?BPF_LD + ?BPF_MEM, K);

asm_(#bpf_insn{code=ldxc, k=K}) -> insn(?BPF_LDX+?BPF_W+?BPF_IMM, K);
asm_(#bpf_insn{code=ldx, k=K})  -> insn(?BPF_LDX+?BPF_W+?BPF_MEM, K);
asm_(#bpf_insn{code=ldxl })     -> insn(?BPF_LDX+?BPF_W+?BPF_LEN);
asm_(#bpf_insn{code=ldxmsh, k=K}) -> insn(?BPF_LDX+?BPF_B+?BPF_MSH, K);

asm_(#bpf_insn{code=sta,k=K})   -> insn(?BPF_ST, K);
asm_(#bpf_insn{code=stx,k=K})   -> insn(?BPF_STX, K);

asm_(#bpf_insn{code=addk, k=K}) -> insn(?BPF_ALU+?BPF_ADD+?BPF_K, K);
asm_(#bpf_insn{code=subk, k=K}) -> insn(?BPF_ALU+?BPF_SUB+?BPF_K, K);
asm_(#bpf_insn{code=mulk, k=K}) -> insn(?BPF_ALU+?BPF_MUL+?BPF_K, K);
asm_(#bpf_insn{code=divk, k=K}) -> insn(?BPF_ALU+?BPF_DIV+?BPF_K, K);
asm_(#bpf_insn{code=andk, k=K}) -> insn(?BPF_ALU+?BPF_AND+?BPF_K, K);
asm_(#bpf_insn{code=ork,  k=K}) ->  insn(?BPF_ALU+?BPF_OR+?BPF_K, K);
asm_(#bpf_insn{code=lshk, k=K}) -> insn(?BPF_ALU+?BPF_LSH+?BPF_K, K);
asm_(#bpf_insn{code=rshk, k=K}) -> insn(?BPF_ALU+?BPF_RSH+?BPF_K, K);
asm_(#bpf_insn{code=addx}) ->      insn(?BPF_ALU+?BPF_ADD+?BPF_X);
asm_(#bpf_insn{code=subx}) ->      insn(?BPF_ALU+?BPF_SUB+?BPF_X);
asm_(#bpf_insn{code=mulx}) ->      insn(?BPF_ALU+?BPF_MUL+?BPF_X);
asm_(#bpf_insn{code=divx}) ->      insn(?BPF_ALU+?BPF_DIV+?BPF_X);
asm_(#bpf_insn{code=andx}) ->      insn(?BPF_ALU+?BPF_AND+?BPF_X);
asm_(#bpf_insn{code=orx}) ->       insn(?BPF_ALU+?BPF_OR+?BPF_X);
asm_(#bpf_insn{code=lshx}) ->      insn(?BPF_ALU+?BPF_LSH+?BPF_X);
asm_(#bpf_insn{code=rshx}) ->      insn(?BPF_ALU+?BPF_RSH+?BPF_X);
asm_(#bpf_insn{code=neg}) ->       insn(?BPF_ALU+?BPF_NEG);
asm_(#bpf_insn{code=jmp,k=K}) ->   insn(?BPF_JMP+?BPF_JA, K);

asm_(I=#bpf_insn{code=jgtk})  -> jump(?BPF_JMP+?BPF_JGT+?BPF_K, I);
asm_(I=#bpf_insn{code=jgek})  -> jump(?BPF_JMP+?BPF_JGE+?BPF_K, I);
asm_(I=#bpf_insn{code=jeqk})  -> jump(?BPF_JMP+?BPF_JEQ+?BPF_K, I);
asm_(I=#bpf_insn{code=jsetk}) -> jump(?BPF_JMP+?BPF_JSET+?BPF_K, I);
asm_(I=#bpf_insn{code=jgtx})  -> jump(?BPF_JMP+?BPF_JGT+?BPF_X, I);
asm_(I=#bpf_insn{code=jgex})  -> jump(?BPF_JMP+?BPF_JGE+?BPF_X, I);
asm_(I=#bpf_insn{code=jeqx})  -> jump(?BPF_JMP+?BPF_JEQ+?BPF_X, I);
asm_(I=#bpf_insn{code=jsetx}) -> jump(?BPF_JMP+?BPF_JSET+?BPF_X, I);

asm_(#bpf_insn{code=reta})     -> insn(?BPF_RET+?BPF_A);
asm_(#bpf_insn{code=retk,k=K}) -> insn(?BPF_RET+?BPF_K,K);

asm_(#bpf_insn{code=tax}) -> insn(?BPF_MISC+?BPF_TAX);
asm_(#bpf_insn{code=txa}) -> insn(?BPF_MISC+?BPF_TXA).

jump(Code, #bpf_insn{jt=Jt,jf=Jf,k=K}) ->
    <<Code:16, Jt:8, Jf:8, K:32>>.

insn(Code) ->    <<Code:16, 0:8, 0:8, 0:32>>.
insn(Code, K) ->  <<Code:16, 0:8, 0:8, K:32>>.

%% disassemble a bpf program
disasm(Bin) when is_binary(Bin) ->
    list_to_tuple([ disasm_(I) || <<I:8/binary>> <= Bin ]).
    
disasm_(<<Code:16, Jt:8, Jf:8, K:32>>) ->
    case ?BPF_CLASS(Code) of
	?BPF_LD   -> disasm_ld_(Code, K);
	?BPF_LDX  -> disasm_ldx_(Code, K);
	?BPF_ST   -> disasm_st_(Code, K);
	?BPF_STX  -> disasm_stx_(Code, K);
	?BPF_ALU  -> disasm_alu_(Code, K);
	?BPF_JMP  -> disasm_jmp_(Code, Jt, Jf, K);
	?BPF_RET  -> disasm_ret_(Code, K);
	?BPF_MISC -> disasm_misc_(Code)
    end.

disasm_ld_(Code, K) ->
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

disasm_ldx_(Code, K) ->
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

disasm_st_(_Code, K) ->
    #bpf_insn { code=sta, k=K }.

disasm_stx_(_Code, K) ->
    #bpf_insn { code=stx, k=K }.

disasm_alu_(Code, K) ->
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

disasm_jmp_(Code, Jt, Jf, K) ->
    case ?BPF_OP(Code) of    
	?BPF_JA  -> #bpf_insn { code=jmp, k=K };
	?BPF_JEQ -> #bpf_insn { code=alu_src_(Code,jeqk,jeqx),k=K,jt=Jt,jf=Jf };
	?BPF_JGT -> #bpf_insn { code=alu_src_(Code,jgtk,jgtx),k=K,jt=Jt,jf=Jf };
	?BPF_JGE -> #bpf_insn { code=alu_src_(Code,jgek,jgex),k=K,jt=Jt,jf=Jf };
	?BPF_JSET ->#bpf_insn { code=alu_src_(Code,jsetk,jsetx),
				k=K,jt=Jt,jf=Jf }
    end.

disasm_ret_(Code, K) ->
    case ?BPF_RVAL(Code) of
	?BPF_A -> #bpf_insn { code=reta };
	?BPF_K -> #bpf_insn { code=retk, k=K }
    end.

disasm_misc_(Code) ->
    case ?BPF_MISCOP(Code) of
	?BPF_TAX -> #bpf_insn { code=tax };
	?BPF_TXA -> #bpf_insn { code=txa }
    end.
	    
alu_src_(Code, K, X) ->
    case ?BPF_SRC(Code) of
	?BPF_K -> K;
	?BPF_X -> X
    end.

print(Prog) when is_tuple(Prog) -> print_p(user, Prog, 0).
print(Fd, Prog) when is_tuple(Prog) -> print_p(Fd, Prog, 0).

print_p(Prog)  when is_tuple(Prog) ->  print_p(user, Prog, 0).
print_p(Fd, Prog) when is_tuple(Prog) -> print_p(Fd, Prog, 0).
    
print_p(Fd, Prog, J) when J >= 0, J < tuple_size(Prog) ->
    I = element(J+1,Prog),
    print_insn_p(Fd, J, I),
    print_p(Fd, Prog, J+1);
print_p(_Fd, Prog, _J) ->
    Prog.

%%
%% Print in pcap format
%%
    

print_insn_p(Fd,J,I) ->
    case I of
	#bpf_insn{code=ldaw,k=K}  -> out_p(Fd,J,"ld","[~w]", [K]);
	#bpf_insn{code=ldah,k=K}  -> out_p(Fd,J,"ldh","[~w]", [K]);
	#bpf_insn{code=ldab,k=K}  -> out_p(Fd,J,"ldb","[~w]", [K]);
	#bpf_insn{code=ldiw,k=K}  -> out_p(Fd,J,"ld","[x + ~w]", [K]);
	#bpf_insn{code=ldih,k=K}  -> out_p(Fd,J,"ldh","[x + ~w]", [K]);
	#bpf_insn{code=ldib,k=K}  -> out_p(Fd,J,"ldb","[x + ~w]", [K]); 
	#bpf_insn{code=ldl }      -> out_p(Fd,J,"ld", "len", []);
	#bpf_insn{code=ldc, k=K}  -> out_p(Fd,J,"ld", "#0x~.16b", [K]);
	#bpf_insn{code=lda, k=K}  -> out_p(Fd,J,"ld", "M[~w]", [K]);
	#bpf_insn{code=ldxc, k=K} -> out_p(Fd,J,"ldx","#0x~.16b", [K]);
	#bpf_insn{code=ldx, k=K}  -> out_p(Fd,J,"ldx", "M[~w]", [K]);
	#bpf_insn{code=ldxl }     -> out_p(Fd,J,"ldx", "len", []);
	#bpf_insn{code=ldxmsh, k=K} -> out_p(Fd,J,"ldxb","4*([~w]&0xf)",[K]);
	#bpf_insn{code=sta,k=K}   -> out_p(Fd,J, "st", "M[~w]", [K]);
	#bpf_insn{code=stx,k=K}   -> out_p(Fd,J, "stx", "M[~w]", [K]);
	#bpf_insn{code=addk, k=K} -> out_p(Fd,J, "add", "#~w", [K]);
	#bpf_insn{code=subk, k=K} -> out_p(Fd,J, "sub", "#~w", [K]);
	#bpf_insn{code=mulk, k=K} -> out_p(Fd,J, "mul", "#~w", [K]);
	#bpf_insn{code=divk, k=K} -> out_p(Fd,J, "div", "#~w", [K]);
	#bpf_insn{code=andk, k=K} -> out_p(Fd,J, "and", "#0x~.16b", [K]);
	#bpf_insn{code=ork,  k=K} -> out_p(Fd,J, "or", "#0x~.16b", [K]);
	#bpf_insn{code=lshk, k=K} -> out_p(Fd,J, "lsh", "#~w", [K]);
	#bpf_insn{code=rshk, k=K} -> out_p(Fd,J, "rsh", "#~w", [K]);
	#bpf_insn{code=addx}      -> out_p(Fd,J, "add", "x", []);
	#bpf_insn{code=subx}      -> out_p(Fd,J, "sub", "x", []);
	#bpf_insn{code=mulx}      -> out_p(Fd,J, "mul", "x", []);
	#bpf_insn{code=divx}      -> out_p(Fd,J, "div", "x", []);
	#bpf_insn{code=andx}      -> out_p(Fd,J, "and", "x", []);
	#bpf_insn{code=orx}       -> out_p(Fd,J, "or", "x", []);
	#bpf_insn{code=lshx}      -> out_p(Fd,J, "lsh", "x", []);
	#bpf_insn{code=rshx}      -> out_p(Fd,J, "rsh", "x", []);
	#bpf_insn{code=neg}       -> out_p(Fd,J, "neg", "", []);
	#bpf_insn{code=jmp,k=K}   -> out_p(Fd,J, "jmp", "#0x~.16b", [J+1+K]);
	#bpf_insn{code=jgtk,k=K}  -> out_pj(Fd,J, "jgt", "#0x~.16b", [K],I);
	#bpf_insn{code=jgek,k=K}  -> out_pj(Fd,J, "jge", "#0x~.16b", [K],I);
	#bpf_insn{code=jeqk,k=K}  -> out_pj(Fd,J, "jeq", "#0x~.16b", [K],I);
	#bpf_insn{code=jsetk,k=K} -> out_pj(Fd,J, "jset", "#0x~.16b", [K],I);
	#bpf_insn{code=jgtx}      -> out_pj(Fd,J, "jgt", "x", [], I);
	#bpf_insn{code=jgex}      -> out_pj(Fd,J, "jge", "x", [], I);
	#bpf_insn{code=jeqx}      -> out_pj(Fd,J, "jeq", "x", [], I);
	#bpf_insn{code=jsetx}     -> out_pj(Fd,J, "jset", "x", [], I);
	#bpf_insn{code=reta}      -> out_p(Fd,J, "ret", "", []);
	#bpf_insn{code=retk,k=K}  -> out_p(Fd,J, "ret", "#~w", [K]);
	#bpf_insn{code=tax}       -> out_p(Fd,J, "tax", "", []);
	#bpf_insn{code=txa}       -> out_p(Fd,J, "txa", "", [])
    end.

out_p(Fd,J, Mnemonic, Fmt, Args) ->
    A = io_lib:format(Fmt, Args),
    io:format(Fd,"(~.3.0w) ~-10s~s\n", [J,Mnemonic,A]).

out_pj(Fd,J, Mnemonic, Fmt, Args, I) ->
    A = io_lib:format(Fmt, Args),
    io:format(Fd,"(~.3.0w) ~-10s~-18sjt ~w jf ~w\n", 
	      [J,Mnemonic,A,J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf]).

%%
%% Print in "C" format
%%
print_c(Prog)  when is_tuple(Prog) ->  print_c_main(user, Prog).
print_c(Fd, Prog) when is_tuple(Prog) -> print_c_main(Fd, Prog).

print_c_main(Fd, Prog) ->
    print_c_main(Fd, "filter", Prog).

print_c_main(Fd, Name, Prog) ->
    io:format(Fd, "unsigned int ~s(unsigned char* P) {\n", [Name]),
    io:format(Fd, "  unsigned int A = 0;\n", []),
    io:format(Fd, "  unsigned int X = 0;\n", []),
    io:format(Fd, "  unsigned int M[~w];\n", [?BPF_MEMWORDS]),
    print_c(Fd, "  ", Prog, 1),
    io:format(Fd, "}\n", []).

print_c(Fd, Ind, Prog, J) when J >= 1, J =< tuple_size(Prog) ->
    I = element(J,Prog),
    L = io_lib:format("L~w: ", [J]),
    print_insn_c(Fd, Ind, L, J, I),
    print_c(Fd, Ind, Prog, J+1);
print_c(_Fd, _Ind, Prog, _J) ->
    Prog.

print_insn_c(Fd, L, J, I) ->
    print_insn_c(Fd, "", L, J, I).

print_insn_c(Fd, Ind, L, J, I) ->
    case class(I) of
	{jmp,Cond,R} ->
	    print_jmp_c(Fd,Ind,Cond,R,I,L,J);
	{ld,Dst,Src} ->
	    print_ld_c(Fd,Ind,Dst,Src,I,L);
	_ ->
	    case I of
		#bpf_insn { code=sta, k=K} ->
		    io:format(Fd,"~s~sM[~w] = A;\n", [Ind,L,K]);
		#bpf_insn { code=stx, k=K} ->
		    io:format(Fd,"~s~sM[~w] = X;\n", [Ind,L,K]);
		#bpf_insn { code=addk, k=K } ->
		    io:format(Fd,"~s~sA += ~w;\n", [Ind,L,K]);
		#bpf_insn { code=subk, k=K } ->
		    io:format(Fd,"~s~sA -= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=mulk, k=K } ->
		    io:format(Fd,"~s~sA *= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=divk, k=K } ->
		    io:format(Fd,"~s~sA /= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=andk, k=K } ->
		    io:format(Fd,"~s~sA &= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=ork, k=K } ->
		    io:format(Fd,"~s~sA |= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=lshk, k=K } ->
		    io:format(Fd,"~s~sA <<= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=rshk, k=K } ->
		    io:format(Fd,"~s~sA >>= ~w;\n", [Ind,L,K]);
		#bpf_insn { code=addx } ->
		    io:format(Fd,"~s~sA += X;\n", [Ind,L]);
		#bpf_insn { code=subx } ->
		    io:format(Fd,"~s~sA -= X;\n", [Ind,L]);
		#bpf_insn { code=mulx } ->
		    io:format(Fd,"~s~sA *= X;\n", [Ind,L]);
		#bpf_insn { code=divx } ->
		    io:format(Fd,"~s~sA /= X;\n", [Ind,L]);
		#bpf_insn { code=andx } ->
		    io:format(Fd,"~s~sA &= X;\n", [Ind,L]);
		#bpf_insn { code=orx } ->
		    io:format(Fd,"~s~sA |= X;\n", [Ind,L]);
		#bpf_insn { code=lshx } ->
		    io:format(Fd,"~s~sA <<= X;\n", [Ind,L]);
		#bpf_insn { code=rshx } ->
		    io:format(Fd,"~s~sA >>= X;\n", [Ind,L]);
		#bpf_insn { code=neg } ->
		    io:format(Fd,"~s~sA = -A;\n", [Ind,L]);
		#bpf_insn { code=tax } ->
		    io:format(Fd,"~s~sX = A;\n", [Ind,L]);
		#bpf_insn { code=txa } ->
		    io:format(Fd,"~s~sA = X;\n", [Ind,L]);
		#bpf_insn { code=reta } ->
		    io:format(Fd,"~s~sreturn A;\n", [Ind,L]);
		#bpf_insn { code=retk, k=K } ->
		    io:format(Fd,"~s~sreturn ~w;\n", [Ind,L,K])
	    end
    end.

print_ld_c(Fd,Ind,Dst,Src,_I,L) ->
    D = if Dst =:= 'a' -> "A";
	   Dst =:= 'x' -> "X"
	end,
    case Src of
	{p,K,S} ->
	    io:format(Fd,"~s~s~s = ~s;\n", [Ind,L,D,pk(K,S)]);
	{px,K,S} ->
	    io:format(Fd,"~s~s~s = ~s;\n", [Ind,L,D,pkx(K,S)]);
	{l,_S} ->
	    io:format(Fd,"~s~s~s = len;\n", [Ind,L,D]);
	{k,K} ->
	    io:format(Fd,"~s~s~s = ~w;\n", [Ind,L,D,K]);
	{m,K} ->
	    io:format(Fd,"~s~s~s = M[~w];\n", [Ind,L,D,K]);
	{msh,K} ->
	    io:format(Fd,"~s~s~s = 4*(P[~w]&0xF);\n", [Ind,L,D,K])
    end.

print_jmp_c(Fd,Ind,true,k,I,L,J) ->
    if I#bpf_insn.k =:= 0 ->
	    io:format(Fd,"~s~s/*nop*/;\n", [Ind,L]);
       true ->
	    io:format(Fd,"~s~sgoto L~0w;\n", 
		      [Ind,L,J+1+I#bpf_insn.k])
    end;
print_jmp_c(Fd,Ind,Cond,k,I,L,J) ->
    if I#bpf_insn.jf =:= 0 ->
	    io:format(Fd,"~s~sif (A ~s 0x~.16B) goto L~w;\n", 
		      [Ind,L,Cond,I#bpf_insn.k,J+1+I#bpf_insn.jt]);
       true ->
	    io:format(Fd,"~s~sif (A ~s 0x~.16B) goto L~w; else goto L~w;\n", 
		      [Ind,L,Cond,I#bpf_insn.k,
		       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf])
    end;
print_jmp_c(Fd,Ind,Cond,x,I,L,J) ->
    if I#bpf_insn.jf =:= 0 ->
	    io:format(Fd,"~s~sif (A ~s X) goto L~w;\n", 
		      [Ind,L,Cond,J+1+I#bpf_insn.jt]);
       true ->
	    io:format(Fd,"~s~sif (A ~s X) goto L~w; else goto L~w;\n", 
		      [Ind,L,Cond,
		       J+1+I#bpf_insn.jt,J+1+I#bpf_insn.jf])
    end.


pk(Index,1) ->
    io_lib:format("P[~w]", [Index]);
pk(Index,2) ->
    io_lib:format("*((unsigned short*)(P+~w))", [Index]);
pk(Index,4) ->
    io_lib:format("*((unsigned int*)(P+~w))", [Index]).

pkx(Index,1) ->
    io_lib:format("P[X+~w]", [Index]);
pkx(Index,2) ->
    io_lib:format("*((unsigned short*)(P+X+~w))", [Index]);
pkx(Index,4) ->
    io_lib:format("*((unsigned int*)(P+X+~w))", [Index]).


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
