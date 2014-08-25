%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer short circuit mulit jumps
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_jmp).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% remove multiple unconditional jumps 
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: short ciruit jmp\n", []),
    bpf_bs:fold_block(fun(B,BsI) -> remove_multiple_jmp_bl_(B, BsI) end,Bs,Bs).

%% 1 - fanout is unconditional jump 
%%     there are no instructions in the target block, move
%%     the next instruction (and fanout) to B  (unlink)
%% 2 - conditional Tf or Tf labels jump to an empty block
%%     with unconditional jump, then jump to that block
remove_multiple_jmp_bl_(B, Bs) ->
    case bpf:fanout(B#bpf_block.next) of
	[J] ->
	    Bj = bpf_bs:get_block(J, Bs),
	    if Bj#bpf_block.insns =:= [] ->
		    ?debug("REPLACE: ~w with ~w",
			   [B#bpf_block.next,Bj#bpf_block.next]),
		    bpf_bs:set_next(B#bpf_block.label, Bj#bpf_block.next, Bs);
	       true ->
		    Bs
	    end;
	[Jt,Jf] ->
	    Bt = bpf_bs:get_block(Jt, Bs),
	    Jt2 = case {Bt#bpf_block.insns, bpf:fanout(Bt#bpf_block.next)} of
		      {[], [Jt1]} -> Jt1;
		      {[],[Jt1,_Jf1]} ->
			  %% Same condition on the landing site?
			  case {B#bpf_block.next,Bt#bpf_block.next} of
			      {#bpf_insn { code=jgtk, k=0},
			       #bpf_insn { code=jgtk, k=0}} -> Jt1;
			      _ -> Jt
			  end;
		      _ -> Jt
		  end,
	    Bf = bpf_bs:get_block(Jf, Bs),
	    Jf2 = case {Bf#bpf_block.insns, bpf:fanout(Bf#bpf_block.next)} of
		      {[], [Jf1]} -> Jf1;
		      {[],[_Jt1,Jf1]} ->
			  %% Same condition on the landing site?
			  case {B#bpf_block.next,Bf#bpf_block.next} of
			      {#bpf_insn { code=jgtk, k=0},
			       #bpf_insn { code=jgtk, k=0}} -> Jf1;
			      _ -> Jf
			  end;
		      _ -> Jf
		  end,
	    if Jt =/= Jt2; Jf =/= Jf2 ->
		    Next = B#bpf_block.next,
		    Next1 = Next#bpf_insn { jt=Jt2, jf=Jf2 },
		    ?debug("REPLACE: ~w with ~w", [Next,Next1]),
		    bpf_bs:set_next(B#bpf_block.label, Next1, Bs);
	       true ->
		    Bs
	    end;
	_ ->
	    Bs
    end.
