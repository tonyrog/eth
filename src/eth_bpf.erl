%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%    BPF machine support
%%% @end
%%% Created :  2 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_bpf).

%% -define(DEBUG, true).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%% bpf program utils

-export([build_program/1, build_programa/1, build_programx/1]).
-export([join/1]).
-export([expr/1,expr/2]).

%% some predefined expressions
-compile(export_all).

-import(lists, [reverse/1, foldl/3]).


%% Join encoded filters into one big filter
join([]) ->
    bpf:asm({bpf:reject()});
join(Fs) -> 
    join_(Fs, []).

join_([F], Acc) ->
    Prog = if F =:= <<>> -> {bpf:accept()};
	      true -> bpf:disasm(F)
	   end,
    Is = tuple_to_list(Prog),
    Js = lists:flatten(reverse([Is | Acc])),
    Prog1 = list_to_tuple(Js),
    %% Bs1 = bpf_bs:from_prog(Prog1),
    %% Bs2 = optimise(Bs1),
    %% Prog2 = bpf_bs:to_prog(Bs2),
    bpf:asm(Prog1);
join_([F|Fs], Acc) ->
    Prog = if F =:= <<>> -> {bpf:nop()};
	      true -> bpf:disasm(F)
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

%%
%% Optimise basic blocks
%%
optimise(Bs) ->
    bpf_opt:run(Bs, ?MAX_OPTIMISE).

%% (nested) list of code, default to reject
build_program(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,bpf:reject()])),
    build_(Prog).

%% (nested) list of code returning ackumulator value
build_programa(Code) when is_list(Code) ->
    Prog = list_to_tuple(lists:flatten([Code,bpf:return()])),
    build_(Prog).

%% build expression, A>0 => accept, A=0 => reject
build_programx(Expr) ->
    X = expr(Expr, 0),
    Prog = list_to_tuple(lists:flatten([X,
					#bpf_insn { code=jgtk, k=0,
						    jt=0, jf=1 },
					bpf:accept(),
					bpf:reject()])),
    build_(Prog).

%% build expression list return the number of the expression
%% that match or 0 if no match
build_program_list(ExprList) ->
    Prog = lists:flatten(make_program_list(ExprList,0,1)),
    build_(list_to_tuple(Prog)).

make_program_list([Expr],Offs,I) ->
    [expr(Expr,Offs),
     #bpf_insn { code=jgtk, k=0, jt=0, jf=1 },
     bpf:return(I),
     bpf:reject()];
make_program_list([Expr|ExprList],Offs,I) ->
    Prog1 = make_program_list(ExprList,Offs,I+1),
    [expr(Expr,Offs),
     #bpf_insn { code=jgtk, k=0, jt=0, jf=1 },
     bpf:return(I),
     Prog1].

build_(Prog0) ->
    Bs0 = bpf_bs:from_prog(Prog0),
    %% bpf_bs:print(Bs0),
    case bpf:validate(Prog0) of
	E={error,_} -> E;
	_ ->
	    Bs1 = optimise(Bs0),
	    Prog1 = bpf_bs:to_prog(Bs1),
	    %% bpf:print_c(Prog1),
	    %% bpf:print(Prog1),
	    case bpf:validate(Prog1) of
		E={error,_} -> E;
		_ -> Prog1
	    end
    end.

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
    land({'||',"ether.type.vlan","ether.type.bridge"},
	 Bx, Offs, Offs+?VLAN,Sp0);
land(VID="vlan."++_ID,Bx,Offs,Sp0) ->
    land({'&&',{'||',"ether.type.vlan","ether.type.bridge"},VID},
	 Bx, Offs, Offs+?VLAN,Sp0);
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
	"ether["++Elem      -> vexpr_(Elem, ?OFFS_ETH, Offs, Sp);
	"ether.dst."++Addr  -> eth_address(Addr,?OFFS_ETH_DST,Offs,Sp);
	"ether.src."++Addr  -> eth_address(Addr,?OFFS_ETH_SRC,Offs,Sp);
	"ether.dst["++Elem  -> vexpr_(Elem,?OFFS_ETH_DST,Offs,Sp);
	"ether.src["++Elem  -> vexpr_(Elem,?OFFS_ETH_SRC,Offs,Sp);
	"ether.type"        -> expr_({p,?OFFS_ETH_TYPE,2},Offs,Sp);
	"ether.type."++Type -> eth_type(Type, Offs, Sp);
	"ether.data"        -> iexpr(?OFFS_ETH_DATA,Offs,Sp);
	"ether.data["++Elem -> vexpr_(Elem, ?OFFS_ETH_DATA, Offs, Sp);

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
		   [{'&&',["ether.type.ip","ip.port."++PortStr]},
		    {'&&',["ether.type.ip6","ip6.port."++PortStr]}
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
	    "vlan" -> ?ETHERTYPE_VLAN;
	    "bridge" -> ?ETHERTYPE_QINQ; %% ?ETHERTYPE_BRIDGE;
	    "qinq" -> ?ETHERTYPE_QINQ
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
		"sctp" -> ?IPPROTO_SCTP;
		"icmp" -> ?IPPROTO_ICMP6
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
	"ether.dst"    -> ?OFFS_ETH_DST;
	"ether.src"    -> ?OFFS_ETH_SRC;
	"ether.type"   -> ?OFFS_ETH_TYPE;
	"ether.data"   -> ?OFFS_ETH_DATA;

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
