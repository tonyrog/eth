%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     Api to network devices
%%% @end
%%% Created : 29 Apr 2013 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(eth).

-export([send/2, set_active/2, set_filter/2]).

%% @doc
%%  Send frame.
%% @end
send(Interface, Data) when is_list(Interface), is_binary(Data) ->
    case eth_devices:find(Interface) of
	{ok,Port} ->
	    eth_devices:send(Port, Data);
	Error ->
	    Error
    end;
send(Port, Data) when is_port(Port), is_binary(Data) ->
    eth_devices:send(Port, Data).

%% @doc
%%  Set packet active mode.
%%  The caller will receive (N != 0) ether net frames on form:
%%    {eth_frame, EthPort, IfIndex, FrameData}
%%  If N == 0 then packet reception is disabled, 
%%     N == -1 then ther is unlimited number of frames forwarded
%%     otheriwse N frames are forwarded to caller
%% @end
set_active(Interface, N) when is_integer(N), N >= -1 ->
    case eth_devices:find(Interface) of
	{ok, Port} ->
	    eth_devices:set_active(Port, N);
	Error ->
	    Error
    end.

%% @doc
%%    Set packet filter subscripion (local & global)
%% @end
set_filter(Interface, Prog) when is_list(Interface), is_tuple(Prog) ->
    case eth_devices:find(Interface) of
	{ok, Port} ->
	    Filter = eth_bpf:encode(Prog),
	    eth_devices:set_filter(Port, Filter);
	Error ->
	    Error
    end.
