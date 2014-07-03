%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - normalize return 
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_ret).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Normalize return blocks (block with only a return statement)
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: normalise return\n", []),
    LKs0 =
	bpf_bs:fold_block(
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
    bpf_bs:map_block(
	fun(B) ->
		N = B#bpf_block.next,
		N1 =
		    case bpf:class(N) of
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
