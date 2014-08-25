%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt).

-export([run/1, run/2]).
-export([is_referenced_mk/4,
	 is_referenced_aj/2,
	 is_referenced_a/3, is_referenced_a/4,
	 is_referenced_x/3]).
	 
-include("eth_bpf.hrl").
-include("eth_def.hrl").

run(Bs) ->
    run(Bs, ?MAX_OPTIMISE).

run(Bs, Max) ->
    run_(Bs, 1, Max).

run_(Bs, I, Max) when I < Max ->
    ?info("OPTIMISE: ~w", [I]),
    L = [fun bpf_opt_ld:run/1,
	 fun bpf_opt_st:run/1,
	 fun bpf_opt_jmp:run/1,
	 fun bpf_opt_ret:run/1,
	 fun bpf_opt_unreach:run/1,
	 fun bpf_opt_const:run/1,
	 fun bpf_opt_bjmp:run/1,
	 fun bpf_opt_unreach:run/1,  %% want extra unreach pass here!
	 fun bpf_opt_path:run/1
	],
    Bs1 = run_list_(L, Bs#bpf_bs { changed = 0 }),
    if Bs1#bpf_bs.changed =:= 0 ->
	    %% bpf_bs:print(Bs1),
	    Bs1;
       true ->
	    run_(Bs1, I+1, Max)
    end;
run_(Bs, _I, Max) ->
    ?warning("Looping optimiser limit ~w was reached", [Max]),
    %% bpf_bs:print(Bs),
    Bs.


run_list_([F|Fs], Bs) ->
    Bs1 = F(Bs),
    ?info("new size = ~w", [bpf_bs:size(Bs1)]),
    run_list_(Fs, Bs1);
run_list_([], Bs) ->
    Bs.

%%
%% UTILS
%%

%% check if M[K] is referenced (or killed)
is_referenced_mk(K, Is, B, Bs) ->
    bpf_bs:fold_insns(
      fun(J,_Acc) ->
	      case bpf:class(J) of
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
    bpf_bs:fold_insns(
      fun(J,_Acc) ->
	      case bpf:class(J) of
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
    bpf_bs:fold_insns(
      fun(J,_Acc) ->
	      case bpf:class(J) of
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
