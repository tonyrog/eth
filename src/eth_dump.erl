%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     tcpdump rip off
%%% @end
%%% Created :  7 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_dump).

-compile(export_all).

-include_lib("enet/include/enet_types.hrl").

start(Interface, Expr) ->
    start(Interface, Expr, -1, 5000).

start(Interface, Expr, Timeout) ->
    start(Interface, Expr, -1, Timeout).

start(Interface, Expr, Count, Timeout) ->
    {ok,E} = eth:start_link(),
    ok = eth:bind(E, Interface),
    F = eth_bpf:build_programx(Expr),
    ok = eth:set_filter(E, F),
    TRef = if Timeout =:= infinity ->
		   undefined;
	      is_integer(Timeout), Timeout>=0 -> 
		   erlang:start_timer(Timeout, self(), done)
	   end,
    eth:active(E, Count),
    R = loop(E, Count, TRef),
    eth:stop(E),
    R.



loop(_E, 0, _TRef) ->
    ok;
loop(E, Count, TRef) ->
    receive 
	{eth_frame, _EPort, _Index, Data} ->
	    try eth_packet:decode(Data, [{decode_types,all},nolookup]) of
		Eth -> 
		    try eth_packet:dump(Eth) of
			ok ->
			    loop(E, Count-1, TRef)
		    catch
			error:Reason ->
			    io:format("crash: ~p\n  ~p\n", 
				      [Reason,erlang:get_stacktrace()]),
			    loop(E, Count-1, TRef)
		    end
	    catch
		error:Reason ->
		    io:format("crash: ~p\n  ~p\n",
			      [Reason,erlang:get_stacktrace()]),
		    loop(E, Count-1, TRef)
	    end;
	{timeout,TRef,done} ->
	    timeout
    end.
