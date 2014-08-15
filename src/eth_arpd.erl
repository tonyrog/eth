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

-export([test/0]).

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
	  ipmac :: dict:dict(ip_address(),ethernet_address()),
	  macs :: sets:set(ethernet_address()),
	  cache :: dict:dict(ip_address(),ethernet_address())
	 }).

%%%===================================================================
%%% API
%%%===================================================================

test() ->  %% run as root!
    {ok,A} = start("tap"),
    "" = os:cmd("ifconfig tap0 192.168.10.1 up"),
    add_ip(A, {192,168,10,10}, {1,2,3,4,5,6}),
    {ok,A}.

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
	    FilterProg = eth_bpf:build_programx(
			   {'||', "ether.type.arp",
			    {'&&', "ether.type.ip","ip.proto.icmp"}}),
	    Filter = bpf:asm(FilterProg),
	    _Reply0 = eth:set_filter(Port, Filter),
	    _Reply1 = eth:set_active(Port, -1),
	    {ok,Name} = eth_devices:get_name(Port), %% pic up potential tun<n>
	    Mac = get_mac_address(Name),
	    io:format("set mac address: ~s to ~w\n", [Name,Mac]),
	    {ok, #state { name = Name,
			  eth = Port,
			  mac = Mac, 
			  ipmac = dict:new(),
			  macs = sets:new(),
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
    Macs = sets:add_element(Mac, State#state.macs),
    %% inform network about this fact, gratuitous ARP
    {PType,PLen} = if tuple_size(IP) =:= 4 -> {ipv4, 4};
		      tuple_size(IP) =:= 8 -> {ipv6, 16}
		   end,
    send_arp(?BROADCAST,State#state.mac,
	     #arp { op=reply, %% or request ?
		    htype = ethernet,
		    ptype = PType,
		    haddrlen = 6,
		    paddrlen = PLen,
		    sender={Mac,IP},
		    target={?BROADCAST,IP}}, State),
    {reply, ok, State#state { ipmac = IPMac, macs = Macs }};
handle_call({del_ip,IP}, _From, State) ->
    IPMac = dict:erase(IP, State#state.ipmac),
    %% fixme delete mac from macs set when all {ip,mac} pairs are gone
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
	    State1 = handle_frame(Eth, State),
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

handle_frame(Eth=#eth { data = Arp = #arp {}}, State) ->
    handle_arp(Arp,Eth,State);
handle_frame(Eth=#eth { data = IP = #ipv4 {}}, State) ->
    handle_ipv4(IP,Eth,State);
handle_frame(_Frame, State) ->
    ?dbg("handle_frame: not handled: ~p\n", [_Frame]),
    State.

handle_ipv4(Ip=#ipv4 { data = Icmp = #icmp{} }, Eth, State) ->
    case dict:find(Ip#ipv4.dst, State#state.ipmac) of
	error -> %% host not found?
	    State;  %% just ignore right now
	{ok,_Mac} ->
	    handle_icmp(Icmp, Ip, Eth, State)
    end;
handle_ipv4(_Ip, _Eth, State) ->
    ?dbg("handle_ipv4: not handled: ~p\n", [_Ip]),
    State.

handle_icmp(#icmp { type=echo_request,id=ID,seq=Seq,data=Data},Ip,Eth,State) ->
    Icmp1 = #icmp { type=echo_reply, id=ID, seq=Seq, data=Data},
    Ip1  = #ipv4 { src=Ip#ipv4.dst, dst=Ip#ipv4.src, proto=icmp, data=Icmp1 },
    Eth1 = #eth { src=Eth#eth.dst, dst=Eth#eth.src, type=ipv4, data=Ip1},
    send_frame(Eth1, State),
    State;
handle_icmp(_Icmp,_Ip,_Eth,State) ->
    ?dbg("handle_icmp: not handled: ~p\n", [_Icmp]),
    State.


%% respon or cache arp entries
handle_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIp},
		       target = {TargetMac, TargetIp}},_Eth,State) ->
    ?dbg("cache arp: ~p\n", [_Arp]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIp, SenderMac, State),
    State2 = insert_cache(TargetIp, TargetMac, State1),
    State2;
handle_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIp},
		      target = {TargetMac, TargetIp}},Eth,State) ->
    ?dbg("handle arp request: ~p\n", [Arp]),
    case (TargetMac =:= ?ZERO) orelse
	sets:is_element(TargetMac,State#state.macs) of
	true ->
	    case dict:find(TargetIp, State#state.ipmac) of
		error ->
		    State;
		{ok,_TargetMac} ->
		    ?dbg("handle arp reply with mac=~w\n", [TargetMac]),
		    send_arp(Eth#eth.src,Eth#eth.dst,
			     Arp#arp { op=reply,
				       sender={TargetMac,TargetIp},
				       target={SenderMac,SenderIp}}, State),
		    State
	    end;
	false ->
	    State
    end;
handle_arp(Arp,_Eth,State) ->
    ?dbg("handle_arp: not handled: ~p\n", [Arp]),
    State.

send_arp(Dst,Src,Arp,State) ->
    Frame=#eth { src=Src, dst=Dst, type=arp, data=Arp},
    send_frame(Frame, State).

send_frame(Frame, State) ->
    Data=enet_eth:encode(Frame, []),
    eth_devices:send(State#state.eth, Data).


get_mac_address(Interface) ->
    {ok, IfList} =  inet:getifaddrs(),
    case lists:keyfind(Interface, 1, IfList) of
	false -> undefined;
	{_,Fs} -> list_to_tuple(proplists:get_value(hwaddr,Fs))
    end.


%% build for 
insert_cache(_, {0,0,0,0,0,0}, State) -> State;
insert_cache({0,0,0,0}, _, State) -> State;
insert_cache({0,0,0,0,0,0,0,0}, _, State) -> State;
insert_cache(Ip, Mac, State) ->
    IpMac = dict:store(Ip, Mac, State#state.cache),
    State#state { cache = IpMac }.
