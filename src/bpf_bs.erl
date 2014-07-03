%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Basic block representation
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(bpf_bs).

-include("eth_bpf.hrl").

-export([new/1]).
-export([size/1]).
-export([from_prog/1, to_prog/1]).
-export([print/1, print/2]).
-export([get_labels/1]).
-export([get_block/2,set_block/2]).
-export([add_block/2,del_block/2]).
-export([map_block/2, each_block/2, fold_block/3]).
-export([get_next/2, get_insns/2]).
-export([set_next/3, set_insns/3]).
-export([get_fanout/2, get_fanin/2]).

-export([fold_insns/5, fold_insns/6]).

-import(lists, [foldl/3, reverse/1]).
%%
%% Basic block representation
%%  bpf_bprog {
%%     fanout:  dict L -> [L]
%%     fanin:   dict L -> [L]
%%     block:   dict L -> #bpf_block
%%  }
%%

new(Init) ->
    #bpf_bs {
       init = Init,
       changed = 0,
       block  = dict:new(),
       fanin  = dict:new(),
       fanout = dict:new()
      }.

%% return number of instructions found in program 
size(Bs) ->
    fold_block(
      fun(B, Acc) ->
	      Acc+length(B#bpf_block.insns)+1
      end, 0, Bs).
    
%%
%% Create basic block representation from tuple program.
%% The labels will initially be the address of the first
%% instruction in the block.
%% Label 1 must always be present and represent the first
%% instruction.
%%
from_prog(Prog) when is_tuple(Prog) ->
    Map = build_target_map_(Prog),
    from_prog_(Prog, 1, Map, 1, [], new(1)).

from_prog_(Prog, J, Map, A, Acc, Bs) when J =< tuple_size(Prog) ->
    I = element(J, Prog),
    case bpf:class(I) of
	{jmp,true,_} ->
	    L = J+1+I#bpf_insn.k, %% absolute jump address!
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = I#bpf_insn { k = L }},
	    from_prog_(Prog,J+1,Map,J+1,[], add_block(B,Bs));
	{jmp,_,_} ->
	    Lt = J+1+I#bpf_insn.jt,
	    Lf = J+1+I#bpf_insn.jf,
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I#bpf_insn { jt=Lt, jf=Lf }},
	    from_prog_(Prog,J+1,Map,J+1,[], add_block(B,Bs));
	{ret,_} ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next = I},
	    from_prog_(Prog,J+1,Map,J+1,[], add_block(B,Bs));
	_ ->
	    case element(J,Map) of
		true ->
		    if A =:= J ->
			    from_prog_(Prog,J+1,Map,A,[I|Acc],Bs);
		       true ->
			    B = #bpf_block { label = A,
					     insns = reverse(Acc),
					     next = #bpf_insn { code=jmp,
								k=J }},
			    from_prog_(Prog,J+1,Map,J,[I], add_block(B,Bs))
		    end;
		false ->
		    from_prog_(Prog,J+1,Map,A,[I|Acc],Bs)
	    end
    end;
from_prog_(_Prog, _J, _Map, A, Acc, Bs) ->
    if Acc =:= [] ->
	    Bs;
       true ->
	    B = #bpf_block { label = A,
			     insns = reverse(Acc),
			     next  = #bpf_insn{code=retk, k=0 }
			   },
	    add_block(B, Bs)
    end.

%%
%% Create a map of positions that are reachable from a jump
%% Map[J] == true iff instruction at position J can be
%% reached directly through a jump instruction
%%
build_target_map_(Prog) ->
    build_target_map_(Prog,1,[]).

%% build a map of instruction numbers
build_target_map_(Prog,J,Acc) when J =< tuple_size(Prog) ->
    I = element(J, Prog),
    case bpf:class(I) of
	{jmp,true,k} ->
	    J1 = J+1+I#bpf_insn.k,  %% jump destination
	    build_target_map_(Prog,J+1,[J1|Acc]);
	{jmp,_Cond,_R} ->
	    J1 = J+1+I#bpf_insn.jt,
	    J2 = J+1+I#bpf_insn.jf,
	    build_target_map_(Prog,J+1,[J1,J2|Acc]);
	_ ->
	    build_target_map_(Prog,J+1,Acc)
    end;
build_target_map_(Prog,_J,Acc) ->
    S = sets:from_list(Acc),
    list_to_tuple([ sets:is_element(I,S) || 
		      I <- lists:seq(1, tuple_size(Prog))]).


%%
%% Convert a basic block representation into a program
%%
%% topological sort, 1 must be present and be less than all other nodes
%%
to_prog(Bs) when is_record(Bs,bpf_bs) ->
    Bs1 = topsort(Bs),
    to_prog_(Bs1,1,[],[]).

%% first map blocks into positions
to_prog_([B|Bs], Pos, Ins, Map) ->
    N = length(B#bpf_block.insns),
    case bpf:fanout(B#bpf_block.next) of
	[L1] when (hd(Bs))#bpf_block.label =:= L1 ->
	    %% do not add dummy jump
	    to_prog_(Bs, Pos+N,
		     [B#bpf_block.insns | Ins],
		     [{B#bpf_block.label,Pos}|Map]);
	_ ->
	    to_prog_(Bs, Pos+N+1,
			[B#bpf_block.next, B#bpf_block.insns | Ins],
			[{B#bpf_block.label,Pos}|Map])
    end;
to_prog_([],_Pos,Ins,Map) ->
    Ins1 = lists:flatten(reverse(Ins)),
    list_to_tuple(prog_map_(Ins1, 1, Map)).


%% now assign the relative jumps
prog_map_([I|Is], J, Map) ->
    case bpf:class(I) of
	{jmp,true,_} ->
	    {_,A} = lists:keyfind(I#bpf_insn.k, 1, Map),
	    [I#bpf_insn { k=A-J-1 } | prog_map_(Is, J+1, Map)];
	{jmp,_,_} ->
	    {_,At} = lists:keyfind(I#bpf_insn.jt, 1, Map),
	    {_,Af} = lists:keyfind(I#bpf_insn.jf, 1, Map),
	    [I#bpf_insn { jt=At-J-1, jf=Af-J-1 } | prog_map_(Is, J+1, Map)];
	_ ->
	    [I|prog_map_(Is,J+1,Map)]
    end;
prog_map_([], _J, _Map) ->
    [].

%%
%% Topological sort the basic block DAG.
%% return a list of topsorted blocks
%%
-spec topsort(Bs::#bpf_bs{}) -> [#bpf_block{}].

topsort(Bs) when is_record(Bs,bpf_bs) ->
    topsort_([Bs#bpf_bs.init], Bs, [], sets:new()).

topsort_([{add,N,Bn}|Q], Bs, L, Vs) ->
    topsort_(Q, Bs, [Bn|L], sets:add_element(N,Vs));
topsort_([N|Q], Bs, L, Vs) ->
    case sets:is_element(N, Vs) of
	true ->
	    topsort_(Q, Bs, L, Vs);
	false ->
	    Bn = get_block(N,Bs),
	    topsort_(bpf:fanout(Bn#bpf_block.next) ++
			 [{add,N,Bn}]++Q, Bs, L, Vs)
    end;
topsort_([], _Bs, L, _Vs) ->
    L.

%%
%% Print bpf instruction in C style
%%

print(Bs) when is_record(Bs,bpf_bs) ->
    print_(user, Bs).

print(Fd, Bs) when is_record(Bs,bpf_bs) ->
    print_(Fd, Bs).
    
print_(Fd, Bs) ->
    each_block(
      fun(B) ->
	      io:format(Fd, "L~w:\n", [B#bpf_block.label]),
	      lists:foreach(
		fun(I) ->
			bpf:print_insn_c(Fd, "    ", -1, I)
		end, B#bpf_block.insns),
	      bpf:print_insn_c(Fd, "    ", -1, B#bpf_block.next)
	      %% io:format("    cond ~w\n", [B#bpf_block.ncond])
      end, Bs),
    Bs.

map_block(Fun, Bs) when is_record(Bs,bpf_bs) ->
    Ls = [L || {L,_B} <- dict:to_list(Bs#bpf_bs.block)],
    map_(Fun, Bs, Ls).

map_(Fun, Bs, [I|Is]) ->
    B = get_block(I, Bs),
    case Fun(B) of
	B  -> map_(Fun, Bs, Is);
	B1 -> map_(Fun, set_block(B1,Bs),Is)
    end;
map_(_Fun,Bs,[]) ->
    Bs.

each_block(Fun, Bs) when is_record(Bs,bpf_bs) ->
    Ls = [B || {_L,B} <- dict:to_list(Bs#bpf_bs.block)],
    lists:foreach(Fun, lists:keysort(#bpf_block.label, Ls)).

fold_block(Fun, Acc, Bs) when is_record(Bs,bpf_bs) ->
    dict:fold(fun(_K,B,AccIn) -> Fun(B,AccIn) end, Acc, Bs#bpf_bs.block).

set_block(B, Bs) when is_record(B,bpf_block), is_record(Bs,bpf_bs) ->
    case dict:fetch(B#bpf_block.label, Bs#bpf_bs.block) of
	B -> Bs;  %% no changed
	_ ->
	    Bs1 = del_block(B#bpf_block.label, Bs),
	    add_block(B, Bs1)
    end.
    
add_block(B, Bs) when is_record(B,bpf_block), is_record(Bs,bpf_bs) ->
    La = B#bpf_block.label,
    Block = dict:store(La, B, Bs#bpf_bs.block),
    Bs1 = Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 },
    foldl(fun(Lb,Bsi) -> add_edge(La, Lb, Bsi) end, Bs1,
	  bpf:fanout(B#bpf_block.next)).

del_block(La, Bs) when is_record(Bs,bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Block = dict:erase(La, Bs#bpf_bs.block),
    Bs1 = Bs#bpf_bs { block=Block, changed=Bs#bpf_bs.changed+1 },
    foldl(fun(Lb,Bsi) -> del_edge(La, Lb, Bsi) end, Bs1,
	  bpf:fanout(B#bpf_block.next)).
    
set_next(La, Next, Bs) when is_record(Next,bpf_insn), is_record(Bs,bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Next0 = B#bpf_block.next,
    if Next =:= Next0 ->
	    Bs;
       true ->
	    Ldel = bpf:fanout(Next0),
	    Ladd = bpf:fanout(Next),
	    B1 = B#bpf_block { next = Next },
	    Block = dict:store(La, B1, Bs#bpf_bs.block),
	    Bs1 = Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 },
	    Bs2 = foldl(fun(Lb,Bsi) -> add_edge(La, Lb, Bsi) end, Bs1, Ladd),
	    Bs3 = foldl(fun(Lb,Bsi) -> del_edge(La, Lb, Bsi) end, Bs2, Ldel),
	    Bs3
    end.

set_insns(La, Insns, Bs) when is_list(Insns), is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    Insns0 = B#bpf_block.insns,
    if Insns0 =:= Insns ->
	    Bs;
       true ->
	    B1 = B#bpf_block { insns = Insns },
	    Block = dict:store(La, B1, Bs#bpf_bs.block),
	    Bs#bpf_bs { block = Block, changed=Bs#bpf_bs.changed+1 }
    end.

get_block(La, Bs) when is_record(Bs, bpf_bs) ->
    dict:fetch(La, Bs#bpf_bs.block).

get_labels(Bs) when is_record(Bs, bpf_bs) ->
    dict:fold(fun(K,_,Acc) -> [K|Acc] end, [], Bs#bpf_bs.block).

get_next(La, Bs) when is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    B#bpf_block.next.

get_insns(La, Bs) when is_record(Bs, bpf_bs) ->
    B = dict:fetch(La, Bs#bpf_bs.block),
    B#bpf_block.insns.    

get_fanout(L, Bs) when is_record(Bs, bpf_bs) ->
    case dict:find(L, Bs#bpf_bs.fanout) of
	error -> [];
	{ok,Ls} -> Ls
    end.

get_fanin(L, Bs) when is_record(Bs, bpf_bs) ->
    case dict:find(L, Bs#bpf_bs.fanin) of
	error -> [];
	{ok,Ls} -> Ls
    end.

%% add edge La -> Lb
add_edge(La,Lb,Bs) ->
    Fo = dict:append(La, Lb, Bs#bpf_bs.fanout),   %% La -> Lb
    Fi = dict:append(Lb, La, Bs#bpf_bs.fanin),    %% Lb <- La
    Bs#bpf_bs { fanout = Fo, fanin = Fi }.

%% del edge La -> Lb
del_edge(La,Lb,Bs) ->
    Fo = dict_subtract(La, Lb, Bs#bpf_bs.fanout),   %% La -> Lb
    Fi = dict_subtract(Lb, La, Bs#bpf_bs.fanin),    %% Lb <- La
    Bs#bpf_bs { fanout = Fo, fanin = Fi }.

%% subtract V from list in key K
dict_subtract(K,V,D) ->
    case dict:find(K, D) of
	error -> D;
	{ok,L} when is_list(L) ->
	    case L -- [V] of
		[] -> dict:erase(K,D);
		L1 -> dict:store(K,L1,D)
	    end
    end.

%%
%% iterate through all instructions (including next)
%% tracing the code path (depth first)
%%
fold_insns(Fun, Acc, Is, B, Bs) ->
    fold_insns_(Fun, Acc, Is++[B#bpf_block.next],[],B,Bs,sets:new()).

fold_insns(Fun, Acc, Is, As, undefined, Bs) ->
    fold_insns_(Fun, Acc, Is,As,undefined,Bs,sets:new());
fold_insns(Fun, Acc, Is, As, B, Bs) ->
    fold_insns_(Fun, Acc, Is++[B#bpf_block.next],As,B,Bs,sets:new()).
    
fold_insns_(Fun,Acc,[I|Is],As,B,Bs,Vs) ->
    case Fun(I, Acc) of
	{ok, Acc1} -> 
	    Acc1;
	{skip,Acc1} ->
	    fold_insns_(Fun,Acc1,[],As,undefined,Bs,Vs);
	{next,Acc1} -> 
	    fold_insns_(Fun,Acc1,Is,As,B,Bs,Vs)
    end;
fold_insns_(Fun,Acc,[],As,B,Bs,Vs) ->
    As1 = if B =:= undefined ->
		  As;
	     true -> 
		  As ++ bpf:fanout(B#bpf_block.next)
	  end,
    case As1 of
	[A|As2] ->
	    case sets:is_element(A, Vs) of
		true ->
		    fold_insns_(Fun,Acc,[],As2,undefined,Bs,Vs);
		false ->
		    B1 = get_block(A,Bs),
		    fold_insns_(Fun, Acc,
				B1#bpf_block.insns++[B1#bpf_block.next],
				As2, B1, Bs, sets:add_element(A,Vs))
	    end;
	[] ->
	    Acc
    end.
