%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - constant propagation
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_const).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Constant propagation
%%     for each node 
%%     recursive calculate the constants for all
%%     fanin nodes. 
%%     Calculate the union of all constants
%%     and then proceed to calculate the block 
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: constant propagation\n", []),
    Ls = bpf_bs:get_labels(Bs),
    {Bs1,_,_} = constant_propagation_(Ls, Bs, dict:new(), sets:new()),
    Bs1.

%% Ds is dict of dicts of block calculations, Vs is set of visited nodes
constant_propagation_([I|Is], Bs, Ds, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    constant_propagation_(Is,Bs,Ds,Vs);
	false ->
	    B0 = bpf_bs:get_block(I, Bs),
	    FanIn = bpf_bs:get_fanin(I, Bs),
	    Vs1 = sets:add_element(I,Vs),
	    {Bs1,Ds1,Vs2} = constant_propagation_(FanIn,Bs,Ds,Vs1),
	    D0 = constant_intersect_(FanIn,Ds1),
	    {B1,D1} = constant_eval_(B0,D0),
	    Ds2 = dict:store(I,D1,Ds1),
	    constant_propagation_(Is, bpf_bs:set_block(B1,Bs1),Ds2,Vs2)
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
    {lists:reverse(Js), D}.

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
