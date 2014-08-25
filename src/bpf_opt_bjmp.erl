%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - optimize bit field jumps
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_bjmp).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").
    
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Find bitfield & optimise jumps: (see OPTIMISE.md)
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: bitfield jmp\n", []),
    bpf_bs:fold_block(fun(B,Bsi) -> bitfield_jmp_bl_(B, Bsi) end, Bs, Bs).

bitfield_jmp_bl_(B, Bs) ->
    case lists:reverse(B#bpf_block.insns) of
	[#bpf_insn{ code=andk, k=1 }, #bpf_insn{ code=rshk, k=K } | Is] ->
	    case B#bpf_block.next of
		N = #bpf_insn { code=jgtk, k=0 } ->
		    ?info("Optimisation bitfield 6.a\n", []),
		    case bpf_opt:is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED", []),
			    Bs;
			false ->
			    ?debug(" UPDATED", []),
			    N1 = N#bpf_insn { code=jsetk, k=(1 bsl K) },
			    B1 = B#bpf_block { insns=lists:reverse(Is),
					       next = N1},
			    bpf_bs:set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;
	[#bpf_insn{ code=andk, k=Km } | Is] ->
	    case B#bpf_block.next of
		#bpf_insn { code=jeqk, k=Km, jt=L1, jf=L3 } ->
		    Bt = bpf_bs:get_block(L1,Bs),
		    case {Bt#bpf_block.insns,Bt#bpf_block.next} of
			{[],N1=#bpf_insn { code=jsetk, k=Kl, jt=L2, jf=L3} } ->
			    ?info("Optimisation bitfield 6.f\n", []),
			    case bpf_opt:is_referenced_aj([L2,L3],Bs) of
				true ->
				    ?debug(" REFERENCED",[]),
				    Bs;
				false ->
				    ?debug(" UPDATED",[]),
				    Kn = Km bor Kl,
				    I1=#bpf_insn {code=andk, k=Kn},
				    N2 = N1#bpf_insn { code=jeqk, k=Kn },
				    B1 = B#bpf_block { insns=lists:reverse([I1|Is]),
						       next = N2},
				    bpf_bs:set_block(B1, Bs)
			    end;
			_ ->
			    Bs
		    end;

		N = #bpf_insn { code=jgtk, k=0 } ->
		    ?info("Optimisation bitfield 6.b\n", []),
		    case bpf_opt:is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED",[]),
			    Bs;
			false ->
			    ?debug(" UPDATED",[]),
			    N1 = N#bpf_insn { code=jsetk, k=Km },
			    B1 = B#bpf_block { insns=lists:reverse(Is),
					       next = N1},
			    bpf_bs:set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;

	[#bpf_insn{ code=rshk, k=K } | Is] ->
	    case B#bpf_block.next of
		N = #bpf_insn { code=jsetk, k=1 } ->
		    ?info("Optimisation bitfield 6.c\n", []),
		    case bpf_opt:is_referenced_aj([N#bpf_insn.jt,N#bpf_insn.jf],Bs) of
			true ->
			    ?debug(" REFERENCED",[]),
			    Bs;
			false ->
			    ?debug(" UPDATED",[]),
			    N1 = N#bpf_insn { code=jsetk, k=(1 bsl K) },
			    B1 = B#bpf_block { insns=lists:reverse(Is),
					       next = N1},
			    bpf_bs:set_block(B1, Bs)
		    end;
		_ ->
		    Bs
	    end;
	Is ->
	    case B#bpf_block.next of
		#bpf_insn { code=jsetk,k=Km,jt=L2,jf=L1} ->
		    Bf = bpf_bs:get_block(L1,Bs),
		    Bt = bpf_bs:get_block(L2,Bs),
		    case {Bf#bpf_block.insns,Bf#bpf_block.next} of
			{[],#bpf_insn { code=jsetk,k=Kl,jt=L2,jf=L3} } ->
			    ?info("Optimisation bitfield 6.d\n", []),
			    Kn = Km bor Kl,
			    N=#bpf_insn { code=jsetk,jt=L2,jf=L3,k=Kn},
			    bpf_bs:set_next(B#bpf_block.label, N, Bs);
			_ ->
			    case {Bt#bpf_block.insns,Bt#bpf_block.next} of
				{[],#bpf_insn {code=jsetk,k=Kl,jt=L3,jf=L1} } ->
				    ?info("Optimisation bitfield 6.e\n", []),
				    Kn = Km bor Kl,
				    I=#bpf_insn { code=andk,k=Kn},
				    N=#bpf_insn { code=jeqk,jt=L3,jf=L1,k=Kn},
				    B1=B#bpf_block { insns=lists:reverse([I|Is]),
						     next=N },
				    bpf_bs:set_block(B1, Bs);
				_ ->
				    Bs
			    end
		    end;
		_ ->
		    Bs
	    end
    end.

