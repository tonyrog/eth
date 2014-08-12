%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Eth arp daemon
%%% @end
%%% Created : 10 Aug 2014 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(eth_arpd).

-behaviour(gen_server).

%% API
-export([start/1]).
-export([start_link/1]).
-export([stop/1, add_ip/3, del_ip/2, find_mac/2, query_mac/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).


-define(dbg(F,A), io:format((F),(A))).
%% -define(dbg(F,A), ok).

-include_lib("enet/include/enet_types.hrl").

-define(BROADCAST, {16#ff,16#ff,16#ff,16#ff,16#ff,16#ff}).
-define(ZERO,      {16#00,16#00,16#00,16#00,16#00,16#00}).

-record(state,
	{
	  name :: string(),  %% name of interface (like "tap0", "en1", "eth0")
	  eth,       %% interface handler
	  mac :: ethernet_address(),       %% the mac address on interface
	  ipmac :: sets:set(ip_address()), %% handled address pairs
	  cache :: dict:dict(ip_address(),ethernet_address())
	 }).

%%%===================================================================
%%% API
%%%===================================================================

start(Interface) ->
    application:ensure_all_started(eth),
    gen_server:start(?MODULE, [Interface], []).

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Arpd) ->
    gen_server:call(Arpd, stop).

add_ip(Arpd, IP, Mac) when (tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8) 
			   andalso (tuple_size(Mac) =:= 6) ->
    gen_server:call(Arpd, {add_ip,IP,Mac}).

del_ip(Arpd, IP) when tuple_size(IP) =:= 4; tuple_size(IP) =:= 8 ->
    gen_server:call(Arpd, {del_ip,IP}).

find_mac(Arpd, IP) when tuple_size(IP) =:= 4; tuple_size(IP) =:= 8 ->
    gen_server:call(Arpd, {find_mac,IP}). 

query_mac(Arpd, IP) ->
    gen_server:call(Arpd, {query_mac,IP}).

%% Callbacks

init([Interface]) ->
    case eth_devices:open(Interface) of
	{ok,Port} ->
	    FilterProg = eth_bpf:build_programx("ether.type.arp"),
	    Filter = bpf:asm(FilterProg),
	    _Reply0 = eth:set_filter(Port, Filter),
	    _Reply1 = eth:set_active(Port, -1),
	    Mac = get_mac_address(Interface),
	    %% io:format("set mac address: ~s to ~w\n", [Interface,Mac]),
	    {ok, #state { name = Interface,
			  eth = Port,
			  mac = Mac, 
			  ipmac = dics:new(),
			  cache = dict:new()
			}};
	Error ->
	    {stop, Error}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({add_ip,IP,Mac}, _From, State) ->
    IPMac = dict:store(IP, Mac, State#state.ipmac),
    %% inform network about this fact, gratuitous ARP
    {PType,PLen} = if tuple_size(IP) =:= 4 -> {ipv4, 4};
		      tuple_size(IP) =:= 8 -> {ipv6, 16}
		   end,
    send_arp(?BROADCAST,State#state.mac,
	     #arp { op=request, %% or reply ?
		    htype = ethernet,
		    ptype = PType,
		    haddrlen = 6,
		    paddrlen = PLen,
		    sender={Mac,IP},
		    target={?BROADCAST,IP}}, State),
    {reply, ok, State#state { ipmac = IPMac }};
handle_call({del_ip,IP}, _From, State) ->
    IPMac = dict:erase(IP, State#state.ipmac),
    {reply, ok, State#state { ipmac = IPMac }};
handle_call({find_mac,IP}, _From, State) ->
    case dict:find(IP, State#state.cache) of
	error ->
	    case dict:find(IP, State#state.ipmac) of
		error ->
		    {reply, {error,enoent}, State};
		{ok,Mac} -> {reply, {ok,Mac}, State}
	    end;
	{ok,Mac} -> {reply, {ok,Mac}, State}
    end;
handle_call({query_mac,IP}, _From, State) ->
    %% initiate a arp request
    case inet:ifget(State#state.name, [addr]) of
	{ok,[{addr,LocalIP}]} ->
	    {PType,PLen} = if tuple_size(IP) =:= 4 -> {ipv4, 4};
			      tuple_size(IP) =:= 8 -> {ipv6, 16}
			   end,
	    send_arp(?BROADCAST,State#state.mac,
		     #arp { op=request,
			    htype = ethernet,
			    ptype = PType,
			    haddrlen = 6,
			    paddrlen = PLen,
			    sender={State#state.mac,LocalIP},
			    target={?ZERO,IP}}, State),
	    {reply, ok, State};
	Error ->
	    {reply, Error, State}
    end;
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
    
handle_call(_Request, _From, State) ->
    {reply, {error,bad_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({eth_frame,_Port,_IfIndex,Data}, State) ->
    try eth_packet:decode(Data, [{decode_types,all},nolookup]) of
	Eth ->
	    State1 = insert_frame(Eth, State),
	    {noreply, State1}
    catch
	error:Reason ->
	    io:format("crash: ~p\n  ~p\n",
		      [Reason,erlang:get_stacktrace()]),
	    {noreply, State}	    
    end;
handle_info(_Info, State) ->
    ?dbg("got info: ~p\n", [_Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

insert_frame(#eth { src=Src,dst=Dst,data = Arp = #arp {}}, State) ->
    insert_arp(Arp,Src,Dst,State);
insert_frame(_Frame, State) ->
    ?dbg("insert_frame: ~p\n", [_Frame]),
    State.


get_mac_address(Interface) ->
    {ok, IfList} =  inet:getifaddrs(),
    case lists:keyfind(Interface, 1, IfList) of
	false -> undefined;
	{_,Fs} -> list_to_tuple(proplists:get_value(hwaddr,Fs))
    end.

%% respon or cache arp entries
insert_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIp},
		       target = {TargetMac, TargetIp}},_Src,_Dst,State) ->
    ?dbg("cache arp: ~p\n", [_Arp]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIp, SenderMac, State),
    State2 = insert_cache(TargetIp, TargetMac, State1),
    State2;
insert_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIp},
		      target = {?ZERO, TargetIp}},Src,Dst,State) ->
    ?dbg("handle arp request: ~p\n", [Arp]),
    case dict:find(TargetIp, State#state.ipmac) of
	error ->
	    State;
	{ok,TargetMac} ->
	    ?dbg("handle arp reply with mac=~w\n", [TargetMac]),
	    send_arp(Src,Dst,
		     Arp#arp { op=reply,
			       sender={TargetMac,TargetIp},
			       target={SenderMac,SenderIp}}, State),
	    State
    end;
insert_arp(Arp,_Src,_Dst,State) ->
    ?dbg("ignore arp request: ~p\n", [Arp]),
    State.


send_arp(Dst,Src,Arp,State) ->
    Frame=#eth { src=Src, dst=Dst, type=arp, data=Arp},
    Data=enet_eth:encode(Frame, []),
    eth_devices:send(State#state.eth, Data).


%% build for 
insert_cache(_, {0,0,0,0,0,0}, State) -> State;
insert_cache({0,0,0,0}, _, State) -> State;
insert_cache({0,0,0,0,0,0,0,0}, _, State) -> State;
insert_cache(Ip, Mac, State) ->
    IpMac = dict:store(Ip, Mac, State#state.cache),
    State#state { cache = IpMac }.
