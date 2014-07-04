%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Program to probe for hosts (names) 
%%% @end
%%% Created :  4 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(eth_hosts).


-behaviour(gen_server).

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-export([start/1, stop/1]).
-export([i/1, hosts/1, find_host/2]).

-include_lib("enet/include/enet_types.hrl").

-record(host,
	{
	  name,  %% hostname/client name
	  ip,    %% ipv4 address(es)
	  ip6,   %% ipv6 address(es)
	  mac    %% mac address
	}).

-record(state, 
	{
	  eth,
	  hosts = [] :: [#host {}]
	}).

start(Interface) ->
    application:ensure_all_started(eth),
    start_link(Interface).

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Pid) ->
    gen_server:call(Pid, stop).

hosts(Pid) ->
    gen_server:call(Pid, hosts).

find_host(Pid,Name) ->
    gen_server:call(Pid, {find_host,Name}).

i(Pid) ->
    case gen_server:call(Pid, hosts) of
	{ok,L} ->
	    lists:foreach(
	      fun(H) ->
		      io:format("~s: mac=~w, ip=~w, ip6=~w\n", 
				[H#host.name,
				 H#host.mac,
				 H#host.ip,
				 H#host.ip6])
	      end, L);
	Error ->
	    Error
    end.

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------
init([Interface]) ->
    case eth_devices:open(Interface) of
	{ok,Port} ->
	    Prog = eth_bpf:build_programx(
		     {'||', [ "ether.type.arp",
			      %% BOOTP/DHCP traffic
			      {'&&',["ether.type.ip", "ip.proto.udp",
				     "ip.udp.dst_port.67",
				     "ip.udp.src_port.68"]},
			      %% Zerozonf/bonjour
			      {'&&',["ether.type.ip", "ip.proto.udp",
				     "ip.udp.port.5353"]}
			    ]}),
	    Filter = bpf:asm(Prog),
	    _Reply0 = eth:set_filter(Port, Filter),
	    _Reply1 = eth:set_active(Port, -1),
	    {ok, #state { eth = Port }};
	Error ->
	    {stop, Error}
    end.

handle_call(hosts, _From, State) ->
    {reply, State#state.hosts, State};
handle_call({find_host,Name}, _From, State) ->
    case lists:keyfind(Name, #host.name, State#state.hosts) of
	false ->
	    {reply, {error,enoent}, State};
	H ->
	    {reply, {ok,H}, State}
    end;
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = {error,bad_call},
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.


handle_info({eth_frame,_Port,_IfIndex,Data}, State) ->
    try eth_packet:decode(Data, [{decode_types,all},nolookup]) of
	Eth ->
	    try eth_packet:dump_json(Eth) of
		ok -> ok
	    catch
		error:Reason ->
		    io:format("crash: ~p\n  ~p\n", 
			      [Reason,erlang:get_stacktrace()])
	    end
    catch
	error:Reason ->
	    io:format("crash: ~p\n  ~p\n",
		      [Reason,erlang:get_stacktrace()])
    end,
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.	    

%%--------------------------------------------------------------------
%% utils
%%--------------------------------------------------------------------
