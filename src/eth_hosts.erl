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
-export([dump/1]). %% debug
%% -export([flush/1]). %% debug ?
-export([link_local_to_mac/1,
	 mac_to_link_local/1]).
-export([strcasecmp/2]).
	 

-define(dbg(F,A), io:format((F),(A))).
%% -define(dbg(F,A), ok).

-include_lib("enet/include/enet_types.hrl").

-record(host,
	{
	  name,  %% hostname/client name
	  proto, %% how name was found (dns/bonjour/dhcp)
	  ip,    %% ipv4/ipv6 address
	  mac    %% mac address
	}).

-type proto() :: atom().

-record(state, 
	{
	  eth,
	  ipmac  :: dict:dict(ip_address(), {proto(),ethernet_address()}),
	  ipname :: dict:dict(ip_address(), {proto(),string()})
	}).

start(Interface) ->
    application:ensure_all_started(eth),
    gen_server:start(?MODULE, [Interface], []).

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Pid) ->
    gen_server:call(Pid, stop).

hosts(Pid) ->
    gen_server:call(Pid, hosts).

find_host(Pid,Name) ->
    gen_server:call(Pid, {find_host,Name}).

dump(Pid) ->
    gen_server:call(Pid, dump).

i(Pid) ->
    L = gen_server:call(Pid, hosts),
    lists:foreach(
      fun(H) ->
	      io:format("ip=~s: mac=~s, name=~s\n", 
			[ntoa(H#host.ip),
			 eth_packet:ethtoa(H#host.mac),
			 H#host.name])
      end, L).

ntoa(undefined) -> "";
ntoa(IP) -> inet_parse:ntoa(IP).

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------
init([Interface]) ->
    case eth_devices:open(Interface) of
	{ok,Port} ->
	    FilterProg = eth_bpf:build_programx(
		     {'||', [ "ether.type.arp",
			      %% BOOTP/DHCP traffic
			      {'&&',["ether.type.ip", "ip.proto.udp",
				     {'||',
				      {'&&',  %% request
				       "ip.udp.dst_port.67",
				       "ip.udp.src_port.68"},
				      {'&&',  %% reply
				       "ip.udp.dst_port.68",
				       "ip.udp.src_port.67"}}
				     ]},
			      %% DHCPv6
			      {'&&',["ether.type.ip6", "ip6.proto.udp",
				     {'||',
				      {'&&',  %% request
				       "ip.udp.dst_port.547",
				       "ip.udp.src_port.546"},
				      {'&&',  %% reply
				       "ip.udp.dst_port.546",
				       "ip.udp.src_port.547"}}
				     ]},
			      %% dns?
			      %% multicast dns mDNS (RFC 6762)
			      {'&&',["ether.type.ip", "ip.proto.udp",
				     "ip.udp.port.5353"]}
			    ]}),
	    Filter = bpf:asm(FilterProg),
	    _Reply0 = eth:set_filter(Port, Filter),
	    _Reply1 = eth:set_active(Port, -1),
	    {ok, #state { eth = Port,
			  ipmac = dict:new(),
			  ipname = dict:new()
			}};
	Error ->
	    {stop, Error}
    end.

handle_call(hosts, _From, State) ->
    L1 = dict:fold(
	   fun(IP, {_ProtoMac,Mac}, Acc) ->
		   {Name,Proto} =
		       case dict:find(IP, State#state.ipname) of
			   error ->
			       {"", undefined};
			   {ok,{ProtoN,N}} -> 
			       {N,ProtoN}
		       end,
		   [#host { name=Name, proto=Proto, ip=IP, mac=Mac } | Acc]
	   end, [], State#state.ipmac),
    %% add ipv6 link local addresses with names
    L2 = dict:fold(
	   fun(IP={A,_B,_C,_D,_E,_F,_G,_H},{Proto,NameVal}, Acc) when
		     A band 16#FFC0 =:= 16#FE80 ->
		   Mac = link_local_to_mac(IP),
		   [#host { name=NameVal, proto=Proto,ip=IP, mac=Mac } | Acc];
	      (_, _, Acc) ->
		   Acc
	   end, L1, State#state.ipname),

    {reply, L2, State};
handle_call({find_host,Name}, _From, State) ->
    L = dict:fold(
	  fun(IP={A,_B,_C,_D,_E,_F,_G,_H},{Proto,NameVal}, Acc) when
		    A band 16#FFC0 =:= 16#FE80 ->
		  case strcasecmp(NameVal,Name) of
		      0 ->
			  Mac = link_local_to_mac(IP),
			  [#host { name=Name, proto=Proto, 
				   ip=IP, mac=Mac } | Acc];
		      _ ->
			  Acc
		  end;
	     (IP, {Proto,NameVal}, Acc) ->
		  case strcasecmp(NameVal,Name) of
		      0 ->
			  {Mac,_ProtoMac} =
			      case dict:find(IP, State#state.ipmac) of
				  error -> 
				      {{0,0,0,0,0,0}, undefined};
				  {ok,{ProtoM,M}} -> 
				      {M,ProtoM}
			      end,
			  [#host { name=Name, proto=Proto, 
				   ip=IP, mac=Mac } | Acc];
		      _ ->
			  Acc
	      	  end
	  end, [], State#state.ipname),
    {reply, L, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(dump, _From, State) ->
    io:format("ipmac = ~p\n", [dict:to_list(State#state.ipmac)]),
    io:format("ipname = ~p\n", [dict:to_list(State#state.ipname)]),
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    Reply = {error,bad_call},
    {reply, Reply, State}.

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
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.	    

%%--------------------------------------------------------------------
%% utils
%%--------------------------------------------------------------------

strcasecmp([C|As], [C|Bs]) ->
    strcasecmp(As, Bs);
strcasecmp([C|As], [D|Bs]) ->
    C1 = string:to_lower(C),
    D1 = string:to_lower(D),
    if C1 =:= D1 ->
	    strcasecmp(As, Bs);
       true ->
	    C1 - D1
    end;
strcasecmp([], []) -> 0;
strcasecmp([], _) -> -1;
strcasecmp(_, []) ->  1.

link_local_to_mac({A,_B,_C,_D,E,F,G,H}) when
      A band 16#FFC0 =:= 16#FE80 ->
    %% convert link local ipv6 address to mac
    E1 = E bxor 16#0200,
    {E1 bsr 8, E1 band 16#ff,F bsr 8, G band 16#ff, H bsr 8, H band 16#ff}.

mac_to_link_local({X1,X2,X3,X4,X5,X6}) ->
    A = 16#FE80,
    B = 16#0000,
    C = 16#0000,
    D = 16#0000,
    E = ((X1 bsl 8)+X2) bxor 16#0200,
    F = ((X3 bsl 8)+16#FF),
    G = 16#FE00 + X4,
    H = ((X5 bsl 8)+X6),
    {A,B,C,D,E,F,G,H}.

insert_frame(#eth { data = Arp = #arp {}}, State) ->
    insert_arp(Arp, State);
insert_frame(#eth { data = IP = #ipv4 {}}, State) ->
    insert_ipv4(IP, State);
insert_frame(_Frame, State) ->
    ?dbg("insert_frame: ~p\n", [_Frame]),
    State.

insert_arp(_Arp=#arp { sender = {SenderMac, SenderIp},
		      target = {TargetMac, TargetIp}}, State) ->
    ?dbg("insert_arp: ~p\n", [_Arp]),
    State1 = insert_ipmac(arp, SenderIp, SenderMac, State),
    State2 = insert_ipmac(arp, TargetIp, TargetMac, State1),
    State2.

insert_ipv4(#ipv4 { data = Udp = #udp {} }, State) ->
    insert_udp(Udp, State);
insert_ipv4(_Ip, State) ->
    ?dbg("insert_ipv4: ~p\n", [_Ip]),
    State.

insert_udp(#udp { data = Dhcp = #dhcp {} }, State) ->
    insert_dhcp(Dhcp, State);
insert_udp(#udp { data = Dns = #dns_rec {} }, State) ->
    insert_dns(Dns, State);
insert_udp(_Udp, State) ->
    ?dbg("insert_udp: ~p\n", [_Udp]),
    State.

insert_dhcp(Dhcp, State) ->
    case proplists:get_value(dhcp_message_type, Dhcp#dhcp.options) of
	request ->
	    %% in broadcast mode we only see the request, assume it will work
	    %% otherwise we can/must use the reply to validate this assumption
	    Options = Dhcp#dhcp.options,
	    Name = case proplists:lookup(host_name, Options) of
		       none -> undefined;
		       {host_name,Name0} -> Name0
		   end,
	    IP = case proplists:lookup(dhcp_requested_address, Options) of
		     none -> undefined;
		     {_,IP0} -> IP0
		 end,
	    State1 = insert_ipmac(dhcp, IP, Dhcp#dhcp.chaddr, State),
	    insert_ipname(dhcp, IP, Name, State1);
	_ ->  %% discover / reply ...
	    ?dbg("insert_dhcp: ~p\n", [Dhcp]),
	    State
    end.


insert_dns(Dns, State) ->
    io:format("insert_dns: ~p\n", [Dns]),
    Header = Dns#dns_rec.header,
    if Header#dns_header.qr ->
	    State1 = insert_dns_rr(Dns#dns_rec.anlist, State),
	    State2 = insert_dns_rr(Dns#dns_rec.arlist, State1),
	    State2;
       true ->
	    ?dbg("insert_dns: ~p\n", [Dns]),
	    State
    end.

insert_dns_rr([#dns_rr { domain = Name, class=in, type=a, data=IP } | T],
	      State) ->
    State1 = insert_ipname(dns, IP, Name, State),
    insert_dns_rr(T, State1);
insert_dns_rr([#dns_rr { domain = Name, class=in, type=aaaa, data=IP } | T],
	      State) ->
    State1 = insert_ipname(dns, IP, Name, State),
    insert_dns_rr(T, State1);

%% this is the same as above but with cashe-flush bit set,
%% this should possibly be done in inet_dns.erl
insert_dns_rr([#dns_rr { domain = Name, class=16#8001, type=a, data=Data } | T],
	      State) ->
    IP = enet_ipv4:decode_addr(Data), %% data is not interpreted in this case
    State1 = insert_ipname(dns, IP, Name, State),
    insert_dns_rr(T, State1);
insert_dns_rr([#dns_rr { domain = Name, class=16#8001, type=aaaa,
			 data=Data } | T],
	      State) ->
    IP = enet_ipv6:decode_addr(Data), %% data is not interpreted in this case
    State1 = insert_ipname(dns, IP, Name, State),
    insert_dns_rr(T, State1);

insert_dns_rr([_RR|T], State) ->
    ?dbg("dns_rr: ~p\n", [_RR]),
    insert_dns_rr(T, State);
insert_dns_rr([], State) ->
    State.

insert_ipmac(_Proto, _, {0,0,0,0,0,0}, State) -> State;
insert_ipmac(_Proto, {0,0,0,0}, _, State) -> State;
insert_ipmac(_Proto, {0,0,0,0,0,0,0,0}, _, State) -> State;
insert_ipmac(Proto, Ip, Mac, State) ->
    %% Fixme: add trigger when IP move mac address!
    io:format("insert_ipmac: ~p\n", [{Ip,Proto,Mac}]),
    IpMac = dict:store(Ip, {Proto,Mac}, State#state.ipmac),
    State#state { ipmac = IpMac }.

insert_ipname(_Proto, undefined, _Name, State) -> State;
insert_ipname(_Proto, _IP, undefined, State) -> State;
insert_ipname(Proto, Ip, Name, State) ->
    %% Fixme: add trigger when IP change name.
    io:format("insert_ipname: ~p\n", [{Ip,Proto,Name}]),
    IpName = dict:store(Ip, {Proto,Name}, State#state.ipname),
    State#state { ipname = IpName }.
