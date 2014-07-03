%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF emulator - for debug and test
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_emu).

-export([exec/2, exec/6]).

-include("eth_bpf.hrl").

%% run packet filter found in Prog over the packet data in P
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
