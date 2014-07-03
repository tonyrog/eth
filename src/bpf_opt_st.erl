%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - st
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_st).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% remove unnecessary sta|stx instructions (see OPTIMISE.md)
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_st\n", []),
    bpf_bs:map_block(fun(B) -> remove_st_bl_(B, Bs) end, Bs).

remove_st_bl_(B, Bs) ->
    B#bpf_block { insns = remove_st_bl__(B#bpf_block.insns, B, Bs) }.

remove_st_bl__([I | Is], B, Bs) ->
    case is_referenced_st(I, Is, B, Bs) of
	false ->
	    ?debug("REMOVE: ~w\n", [I]),
	    remove_st_bl__(Is, B, Bs);
	true ->
	    [I | remove_st_bl__(Is, B, Bs)]
    end;
remove_st_bl__([], _B, _Bs) ->
    [].

%% check if a st / lda / ldx / tax / txa can be removed
is_referenced_st(I, Is, B, Bs) ->
    case bpf:class(I) of
	{st,_,{m,K}} ->
	    bpf_opt:is_referenced_mk(K,Is,B,Bs);
	{ld,a,_} ->
	    bpf_opt:is_referenced_a(Is,B,Bs);
	{ld,x,_} ->
	    bpf_opt:is_referenced_x(Is,B,Bs);
	{alu,_,_} ->
	    bpf_opt:is_referenced_a(Is,B,Bs);
	{misc,a,_} -> %% (txa A=X)
	    bpf_opt:is_referenced_a(Is,B,Bs);
	{misc,x,_} -> %% (tax X=A)
	    bpf_opt:is_referenced_x(Is,B,Bs);
	_ ->
	    true
    end.
