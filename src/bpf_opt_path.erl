%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - find already check condition in path
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_path).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Constant path
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: constant path\n", []),
    Ls = bpf_bs:get_labels(Bs),
    {Bs1,_} = constant_path_(Ls, Bs, sets:new()),
    Bs1.

%% Ds is dict of dicts of block calculations, Vs is set of visited nodes
constant_path_([I|Is], Bs, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    constant_path_(Is,Bs,Vs);
	false ->
	    B0 = bpf_bs:get_block(I, Bs),
	    FanIn = bpf_bs:get_fanin(I, Bs),
	    Vs1 = sets:add_element(I,Vs),
	    {Bs1,Vs2} = constant_path_(FanIn,Bs,Vs1),
	    {B1,Bs2} = constant_block_(B0,Bs1),
	    constant_path_(Is, bpf_bs:set_block(B1,Bs2),Vs2)
    end;
constant_path_([],Bs,Vs) ->
    {Bs,Vs}.

constant_block_(B, Bs) ->
    %% check all paths to this block to see if they may be patched
    Next = B#bpf_block.next,
    case bpf:class(Next) of
	{jmp,true,_} ->
	    {B, Bs};
	{jmp,_,_} ->
	    %% check if ncond is patch among parents and update
	    L = B#bpf_block.label,
	    Cond = B#bpf_block.ncond,
	    case compare_all_conds_(bpf_bs:get_fanin(L, Bs), L, Cond, Bs) of
		undefined ->
		    %% try forward patch
		    Bf = bpf_bs:get_block(Next#bpf_insn.jf, Bs),
		    case compare_cond(Cond, Bf#bpf_block.ncond) of
			true ->
			    Nf = Bf#bpf_block.next,
			    Next1 = Next#bpf_insn { jf=Nf#bpf_insn.jf },
			    B1 = B#bpf_block { next = Next1 },
			    {B1, Bs};
			false ->
			    {B,Bs};  %% hmm?
			undefined ->
			    Bt = bpf_bs:get_block(Next#bpf_insn.jt, Bs),
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
    B = bpf_bs:get_block(L, Bs),
    %% first seach grand parents
    case compare_all_conds_(bpf_bs:get_fanin(B#bpf_block.label, Bs), L, Cond, Bs) of
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
