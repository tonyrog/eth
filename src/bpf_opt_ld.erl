%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - ld
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_ld).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%%
%% remove duplicate/unnecessary ld M[K] instructions or a sta
%%
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove_ld\n", []),
    bpf_bs:map_block(
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
    ?debug("REMOVE: ~w\n", [_I2]),
    [I1 | remove_ld_bl_([#bpf_insn {code=tax}| Is])];

%% M[k] = A, <opA>, A=M[k]  => M[k]=A [<opA]
remove_ld_bl_([I1=#bpf_insn{code=sta,k=K},I2,_I3=#bpf_insn{code=lda,k=K}|Is]) ->
    case bpf:class(I2) of
	{alu,_,_}    -> %% ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,a,x}   -> %% ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{misc,x,a}   -> %% remove I3 since X is update to A
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{st,a,{k,K}} -> %% I1 = I2 remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,_,_}     -> %% just remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);	    
	{ld,x,_}     ->
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_}     -> %% A=<...>  A is reloaded in I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
%% M[k]=X, INSN, X=M[k]  => M[k]=X, INSN
remove_ld_bl_([I1=#bpf_insn{code=stx,k=K},I2,_I3=#bpf_insn{code=ldx,k=K}|Is]) ->
    case bpf:class(I2) of
	{alu,_,_} ->   %% A += <...>  do not update X remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,a,x} ->  %% A=X remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{misc,x,a} ->  %% X=A ineffective, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,{k,K}} -> %% I1=I2, duplicate, remove I2,I3
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is]);
	{st,x,_} ->     %% remove I3
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1,I2|Is]);
	{ld,a,_} ->     %% A=<..>, keep x is not updated
	    remove_ld_bl_([I1,I2|Is]);
	{ld,x,_}     -> %% X=<..>  X is reloaded in I3 
	    ?debug("REMOVE: ~w\n", [I2]),
	    ?debug("REMOVE: ~w\n", [_I3]),
	    remove_ld_bl_([I1|Is])
    end;
remove_ld_bl_([I|Is]) ->
    [I|remove_ld_bl_(Is)];
remove_ld_bl_([]) ->
    [].
