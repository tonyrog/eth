%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    BPF optimizer - remove unreachable code
%%% @end
%%% Created :  3 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_opt_unreach).

-export([run/1]).

-include("eth_bpf.hrl").
-include("eth_def.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Remove unreachable blocks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run(Bs) when is_record(Bs,bpf_bs) ->
    ?info("optimiser pass: remove unreachable code\n", []),
    remove_unreach_([Bs#bpf_bs.init], Bs, sets:new()).

remove_unreach_([I|Is], Bs, Vs) ->
    case sets:is_element(I, Vs) of
	true ->
	    remove_unreach_(Is, Bs, Vs);
	false ->
	    B = bpf_bs:get_block(I, Bs),
	    remove_unreach_(Is++bpf:fanout(B#bpf_block.next), 
			    Bs, sets:add_element(I,Vs))
    end;
remove_unreach_([], Bs, Vs) ->
    %% Remove blocks not visited
    All = bpf_bs:get_labels(Bs),
    Remove = All -- sets:to_list(Vs),
    lists:foldl(fun(I,Bsi) -> 
			?debug("REMOVE BLOCK: ~w\n", [I]),
			bpf_bs:del_block(I, Bsi) end, 
		Bs, Remove).

