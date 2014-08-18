%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Eth tiny network stack
%%% @end
%%% Created : 10 Aug 2014 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(eth_net).

-behaviour(gen_server).

%% API
-export([start/1]).
-export([start_link/1]).
-export([stop/1, add_ip/3, del_ip/2, find_mac/2, query_mac/2]).

%% UDP
-export([udp_open/4, udp_close/2, udp_send/5]).
%% TCP
-export([tcp_listen/4, tcp_accept/2, tcp_connect/6, tcp_close/2, tcp_send/3]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-export([test_init/0]).
-export([test_udp/1]).
-export([test_tcp_accept/1]).
-export([test_tcp_connect/1]).

-define(dbg(F,A), io:format((F),(A))).
%% -define(dbg(F,A), ok).

-include_lib("enet/include/enet_types.hrl").

-define(BROADCAST, {16#ff,16#ff,16#ff,16#ff,16#ff,16#ff}).
-define(ZERO,      {16#00,16#00,16#00,16#00,16#00,16#00}).

-define(TCP_HEADER_MIN_LEN,   20).
-define(IPV4_HEADER_MIN_LEN,  20).
-define(IPV6_HEADER_MIN_LEN,  40).
-define(TCP_IPV4_HEADER_MIN_LEN, (?IPV4_HEADER_MIN_LEN+?TCP_HEADER_MIN_LEN)).
-define(TCP_IPV6_HEADER_MIN_LEN, (?IPV6_HEADER_MIN_LEN+?TCP_HEADER_MIN_LEN)).

-type socket_key() :: 
	{ tcp, ip_address(), port_no() } | %% listen "socket"
	{ tcp_a, ip_address(), port_no() } | %% acceptor (only in ref->key map)
	{ tcp, ip_address(), port_no(), ip_address(), port_no() } |
	{ udp, ip_address(), port_no(), ip_address(), port_no() } |
	{ udp, ip_address(), port_no() }.

-type tcp_state() ::
	listen     | syn_rcvd  | syn_sent | established | 
	fin_wait1  | fin_wait2 | closing  | timewait |
	close_wait | last_ack  | closed.
%%
%% input stream window = wsize*(1<<wscale ) our own anounced input size
%%
%% output stream window = wsize*(1<<wscale) other sides input size
%%                        as used for transmission

-record(stream,
	{
	  wsize=65535,         %% current announced window size
	  wscale=0 :: 0..14,   %% window scaling wsize*(1 << wscale)
	  mss :: non_neg_integer(), %% maximum segment size used
	  bytes = 0,                %% number bytes sent / received in window
	  seq = 0 :: non_neg_integer(), %% current seqeuence number
	  segs = []   %% unacked output segments / undelivered input segments
	}).

-record(socket,
	{
	  ref      :: reference(),
	  mac      :: ethernet_address(),
	  src      :: ip_address(),
	  dst      :: ip_address(),
	  src_port :: port_no(),
	  dst_port :: port_no(),
	  proto    :: tcp | udp,
	  owner    :: pid(),
	  tcp_state = closed :: tcp_state(),
	  aqueue = [] :: [{reference(),pid()}],  %% accept queue
	  ostream :: #stream{},
	  istream :: #stream{}
	}).

-record(state,
	{
	  name :: string(),  %% name of interface (like "tap0", "en1", "eth0")
	  eth,       %% interface handler
	  mtu,       %% mtu size of interface / minimum mtu usable
	  mac :: ethernet_address(),       %% the mac address on interface
	  ipmac :: dict:dict(ip_address(),ethernet_address()),
	  macs :: sets:set(ethernet_address()),
	  cache :: dict:dict(ip_address(),ethernet_address()),
	  sockets :: dict:dict(socket_key(), #socket{}),
	  sockref :: dict:dict(reference(), socket_key())
	}).

-define(u32(X), ((X)  band 16#ffffffff)).
-define(seq_next(X), ?u32((X)+1)).

%%%===================================================================
%%% API
%%%===================================================================

test_init() ->   %% run as root!
    {ok,Net} = start("tap"),
    "" = os:cmd("ifconfig tap0 192.168.10.1 up"),
    add_ip(Net, {192,168,10,10}, {1,2,3,4,5,6}),
    {ok,Net}.

test_udp(Net) ->
    {ok,U} = udp_open(Net, {192,168,10,10}, 6666, []),
    test_udp_loop(Net, U).

test_udp_loop(Net, U) ->
    receive
	{udp,U,IP,Port,Message} ->
	    case Message of
		<<"ping">> ->
		    udp_send(Net, U, IP, Port, <<"pong">>),
		    test_udp_loop(Net, U);
		<<"stop">> ->
		    udp_send(Net, U, IP, Port, <<"ok">>),
		    udp_close(Net, U),
		    {ok,Net};
		_ ->
		    udp_send(Net, U, IP, Port, <<"error">>),
		    test_udp_loop(Net, U)
	    end;
	Message ->
	    io:format("test_udp_loop: got message: ~p\n", [Message]),
	    test_udp_loop(Net, U)
		
    end.

test_tcp_accept(Net) ->
    {ok,L} = tcp_listen(Net, {192,168,10,10}, 6667, []),
    {ok,S} = tcp_accept(Net, L),
    S.

test_tcp_connect(Net) ->
    query_mac(Net, {192,168,10,1}),
    timer:sleep(100),
    {ok,S} = tcp_connect(Net,{192,168,10,10},57563,{192,168,10,1},6668,[]),
    S.


start(Interface) ->
    application:ensure_all_started(eth),
    gen_server:start(?MODULE, [Interface], []).

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Arpd) ->
    gen_server:call(Arpd, stop).

%% udp interface
udp_open(Net, SrcIP, SrcPort, Options) ->
    gen_server:call(Net, {udp_open, self(), SrcIP, SrcPort, Options}).

udp_close(Net, UdpRef) ->
    gen_server:call(Net, {udp_close, UdpRef}).

udp_send(Net, UdpRef, DestIP, DestPort, Data) ->
    gen_server:call(Net, {udp_send, UdpRef, DestIP, DestPort, Data}).

%% tcp interface
tcp_listen(Net, SrcIP, SrcPort, Options) ->
    gen_server:call(Net, {tcp_listen, self(), SrcIP, SrcPort, Options}).

tcp_accept(Net, ListenRef) ->
    gen_server:call(Net, {tcp_accept, ListenRef, self()}).

tcp_connect(Net, SrcIP, SrcPort, DstIP, DstPort, Options) ->
    gen_server:call(Net, {tcp_connect, self(), 
			  SrcIP, SrcPort, DstIP, DstPort, Options}).

tcp_send(Net, TcpRef, Data) ->
    gen_server:call(Net, {tcp_send, TcpRef, Data}).

tcp_close(Net, TcpRef) ->
    gen_server:call(Net, {tcp_close, TcpRef}).

%% other

add_ip(Net, IP, Mac) when (tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8) 
			  andalso (tuple_size(Mac) =:= 6) ->
    gen_server:call(Net, {add_ip,IP,Mac}).

del_ip(Net, IP) when tuple_size(IP) =:= 4; tuple_size(IP) =:= 8 ->
    gen_server:call(Net, {del_ip,IP}).

find_mac(Net, IP) when tuple_size(IP) =:= 4; tuple_size(IP) =:= 8 ->
    gen_server:call(Net, {find_mac,IP}). 

query_mac(Net, IP) ->
    gen_server:call(Net, {query_mac,IP}).

%% Callbacks

init([Interface]) ->
    case eth_devices:open(Interface) of
	{ok,Port} ->
	    %% to be used for "real" we should be more selective
	    FilterProg = eth_bpf:build_programx(
			   {'||', 
			    ["ether.type.arp",
			     {'&&',"ether.type.ip","ip.proto.icmp"},
			     {'&&', "ether.type.ip","ip.proto.udp"},
			     {'&&', "ether.type.ip","ip.proto.tcp"}]}),
	    Filter = bpf:asm(FilterProg),
	    _Reply0 = eth:set_filter(Port, Filter),
	    _Reply1 = eth:set_active(Port, -1),
	    {ok,Name} = eth_devices:get_name(Port), %% pic up potential tun<n>
	    Mac = get_mac_address(Name),
	    io:format("set mac address: ~s to ~w\n", [Name,Mac]),
	    {ok, #state { name = Name,
			  eth = Port,
			  mac = Mac, 
			  %% fixme:read mtu from eth_devices / minimum mtu
			  mtu = 1500, 
			  ipmac = dict:new(),
			  macs = sets:new(),
			  cache = dict:new(),
			  sockets = dict:new(),
			  sockref = dict:new()
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

handle_call({udp_open,Owner,SrcIP,SrcPort,_Options}, _From, State) ->
    Key = {udp,SrcIP,SrcPort},
    case dict:find(Key, State#state.sockets) of
	error ->
	    case dict:find(SrcIP, State#state.ipmac) of
		error ->
		    {reply, {error, einval}, State};
		{ok,SrcMac} ->
		    Ref = erlang:monitor(process, Owner),
		    Socket = #socket { ref=Ref, mac = SrcMac,
				       src = SrcIP,
				       src_port = SrcPort,
				       proto = udp, owner = Owner },
		    Sockets = dict:store(Key, Socket, State#state.sockets),
		    SockRef = dict:store(Ref, Key, State#state.sockref),
		    State1 =  State#state { sockets=Sockets, sockref=SockRef},
		    {reply, {ok,Ref}, State1}
	    end;
	{ok,_Socket} ->
	    {reply, {error,ealready}, State}
    end;
handle_call({udp_close,Ref}, _From, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {reply, {error, enoent},  State};
	{ok, SockKey={udp,_IP,_Port}} ->
	    {Reply,State1} = close_session(Ref,SockKey,State),
	    {reply, Reply, State1};
	{ok, _SockKey} ->
	    ?dbg("try to udp_close on ~w\n", [_SockKey]),
	    {reply, {error, einval},  State}
    end;
handle_call({udp_send,Ref,DstIP,DstPort,Data}, _From, State) ->
    Result = transmit_udp(Ref,DstIP,DstPort,Data, State),
    {reply,Result,State};

handle_call({tcp_listen,Owner,SrcIP,SrcPort,_Options}, _From, State) ->
    Key = {tcp,SrcIP,SrcPort},
    case dict:find(Key,State#state.sockets) of
	error ->
	    case dict:find(SrcIP, State#state.ipmac) of
		error ->
		    {reply, {error, einval}, State};
		{ok,SrcMac} ->
		    Ref = erlang:monitor(process, Owner),
		    Socket = #socket { ref=Ref,
				       mac = SrcMac,
				       src = SrcIP,
				       src_port = SrcPort,
				       proto = tcp, 
				       tcp_state = listen,
				       owner = Owner },
		    Sockets = dict:store(Key, Socket, State#state.sockets),
		    SockRef = dict:store(Ref, Key, State#state.sockref),
		    State1 =  State#state { sockets=Sockets, sockref=SockRef},
		    {reply, {ok,Ref}, State1}
	    end;
	{ok,_Socket} ->
	    {reply, {error,ealready}, State}
    end;

handle_call({tcp_accept,LRef,Acceptor}, _From, State) ->
    case dict:find(LRef, State#state.sockref) of
	error ->
	    {reply, {error, enoent},  State};
	{ok,Key={tcp,IP,Port}} ->
	    AKey = {tcp_a,IP,Port},
	    Ref = erlang:monitor(process, Acceptor),
	    Socket = dict:fetch(Key, State#state.sockets),
	    AQueue = Socket#socket.aqueue ++ [{Ref,Acceptor}],
	    Socket1 = Socket#socket { aqueue = AQueue },
	    Sockets = dict:store(Key, Socket1, State#state.sockets),
	    SockRef = dict:store(Ref, AKey, State#state.sockref),
	    State1 = State#state { sockets=Sockets, sockref=SockRef },
	    {reply, {ok,Ref}, State1};
	{ok,_OtherKey} ->
	    {reply, {error, einval},  State} 
    end;

handle_call({tcp_connect,Owner,SrcIP,SrcPort,DstIP,DstPort,_Options},
	    _From, State) ->
    %% fixme: SrcPort=0 means dynamic port
    Key = {tcp,SrcIP,SrcPort,DstIP,DstPort},
    case dict:find(Key,State#state.sockets) of
	error ->
	    case dict:find(SrcIP, State#state.ipmac) of
		error ->
		    {reply, {error, einval}, State};
		{ok,SrcMac} ->
		    Ref = erlang:monitor(process, Owner),
		    Mss = if State#state.mtu > ?TCP_IPV4_HEADER_MIN_LEN ->
				  State#state.mtu-?TCP_IPV4_HEADER_MIN_LEN;
			     true -> 1500 - ?TCP_IPV4_HEADER_MIN_LEN
			  end,
		    Ostream = #stream { mss=Mss, seq=random_32() },
		    Istream = #stream {},
		    Socket = #socket { ref=Ref, mac = SrcMac,
				       src = SrcIP,
				       src_port = SrcPort,
				       dst = DstIP,
				       dst_port = DstPort,
				       proto = tcp, 
				       tcp_state = syn_sent,
				       ostream = Ostream,
				       istream = Istream,
				       owner = Owner },
		    Sockets = dict:store(Key, Socket, State#state.sockets),
		    SockRef = dict:store(Ref, Key, State#state.sockref),
		    State1 = State#state { sockets=Sockets, sockref=SockRef },
		    TcpOptions = [],
		    State2 = transmit_syn(Socket,TcpOptions,State1),
		    {reply, {ok,Ref}, State2}
	    end;
	{ok,_Socket} ->
	    {reply, {error,ealready}, State}
    end;

handle_call({tcp_send,Ref,_Data}, _From, State) ->
    case dict:find(Ref, State#state.sockref) of
	{ok,_Key={tcp,_SrcIP,_SrcPort,_DstIP,_DstPort}} ->
	    %% fixme: queue data
	    {reply, ok, State};
	_ ->
	    {reply, {error, einval},  State}
    end;

handle_call({tcp_close,Ref}, _From, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {reply, {error, einval},  State};
	{ok, SockKey={tcp,_IP,_Port}} ->
	    {Reply,State1} = close_listen_socket(Ref,SockKey,State),
	    {reply, Reply, State1};
	{ok, SockKey={tcp_a,_IP,_Port}} ->
	    {Reply,State1} = close_accept_socket(Ref,SockKey,State),
	    {reply, Reply, State1};
	{ok, SockKey={tcp,_SrcIP,_SrcPort,_DstIP,_DstPort}} ->
	    {Reply,State1} = close_session(Ref,SockKey,State),
	    {reply, Reply, State1};
	{ok, _SockKey} ->
	    ?dbg("try to tcp_close on ~w\n", [_SockKey]),
	    {reply, {error, einval},  State}
    end;

handle_call({add_ip,IP,Mac}, _From, State) ->
    IPMac = dict:store(IP, Mac, State#state.ipmac),
    Macs = sets:add_element(Mac, State#state.macs),
    %% inform network about this fact, gratuitous ARP
    {PType,PLen} = if tuple_size(IP) =:= 4 -> {ipv4, 4};
		      tuple_size(IP) =:= 8 -> {ipv6, 16}
		   end,
    transmit_arp(?BROADCAST,State#state.mac,
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
	    transmit_arp(?BROADCAST,State#state.mac,
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

handle_info({udp,Ref,DstIP,DstPort,Data}, State) ->
    transmit_udp(Ref,DstIP,DstPort,Data,State),
    {noreply, State};

handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {noreply, State};
	{ok, SockKey={tcp,_IP,_Port}} ->
	    {_Reply,State1} = close_listen_socket(Ref,SockKey,State),
	    {noreply, State1};
	{ok, SockKey={tcp_a,_IP,_Port}} ->
	    {_Reply,State1} = close_accept_socket(Ref,SockKey,State),
	    {noreply, State1};
	{ok, SockKey} -> %% tcp/udp
	    {_Reply,State1} = close_session(Ref,SockKey,State),
	    {noreply, State1}
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

close_listen_socket(Ref, SockKey, State) ->
    case dict:find(SockKey, State#state.sockets) of
	{ok,Socket} -> %% close queued accepter processes
	    ?dbg("closing socket ~p\n", [Socket]),
	    SockRef1 = lists:foldl(
			 fun({ARef,Pid},SockRef) ->
				 Pid ! {tcp_closed,ARef},
				 dict:erase(ARef, SockRef)
			 end, State#state.sockref, Socket#socket.aqueue),
	    SockRef2 = dict:erase(Ref, SockRef1),
	    Sockets = dict:erase(SockKey, State#state.sockets),
	    {ok,State#state { sockets=Sockets, sockref = SockRef2 }};
	error ->
	    {{error,einval}, State}
    end.

close_accept_socket(Ref, _SockKey={tcp_a,IP,Port}, State) ->
    LKey={tcp,IP,Port},
    case dict:find(LKey, State#state.sockets) of
	{ok,Socket} ->  %% close one acceptor process
	    ?dbg("closing accept on socket ~p\n", [Socket]),
	    AQueue = Socket#socket.aqueue,
	    case lists:keytake(1,Ref,AQueue) of
		false ->
		    {{error,enoent}, State};
		{value,_,AQueue1} -> %% close acceptor
		    erlang:demonitor(Ref, [flush]),
		    Socket1 = Socket#socket { aqueue=AQueue1 },
		    Sockets1 = dict:store(LKey, Socket1, State#state.sockets),
		    SockRef1 = dict:erase(Ref, State#state.sockref),
		    {ok,State#state { sockets=Sockets1, sockref = SockRef1 }}
	    end;
	error ->
	    {{error,einval}, State}
    end.

close_session(Ref, SockKey, State) ->
    case dict:find(SockKey, State#state.sockets) of
	error ->
	    {{error,einval}, State};
	{ok,Socket} ->
	    ?dbg("closing socket ~p\n", [Socket]),
	    erlang:demonitor(Ref, [flush]),
	    SockRef = dict:erase(Ref, State#state.sockref),
	    Sockets = dict:erase(SockKey, State#state.sockets),
	    {noreply, State#state { sockref = SockRef, sockets =Sockets}}
    end.


handle_frame(Eth=#eth { data = Arp = #arp {}}, State) ->
    handle_arp(Arp,Eth,State);
handle_frame(Eth=#eth { data = IP = #ipv4 {}}, State) ->
    %% FIXME: right now we update cache with latest info, this
    %% is probably not what we want ?
    State1 = insert_cache(IP#ipv4.src, Eth#eth.src, State),
    handle_ipv4(IP,Eth,State1);
handle_frame(_Frame, State) ->
    ?dbg("handle_frame: not handled: ~p\n", [_Frame]),
    State.

handle_ipv4(IP=#ipv4 { data = Icmp = #icmp{} }, Eth, State) ->
    case dict:find(IP#ipv4.dst, State#state.ipmac) of
	error -> %% host not found?
	    State;  %% just ignore right now
	{ok,_Mac} ->
	    handle_icmp(Icmp, IP, Eth, State)
    end;
handle_ipv4(IP=#ipv4 { data = Udp = #udp{} }, Eth, State) ->
    case dict:find(IP#ipv4.dst, State#state.ipmac) of
	error -> %% host not found?
	    State;  %% just ignore right now
	{ok,_Mac} ->
	    handle_udp(Udp, IP, Eth, State)
    end;
handle_ipv4(IP=#ipv4 { data = Tcp = #tcp{} }, Eth, State) ->
    case dict:find(IP#ipv4.dst, State#state.ipmac) of
	error -> %% host not found?
	    State;  %% just ignore right now
	{ok,_Mac} ->
	    handle_tcp(Tcp, IP, Eth, State)
    end;
handle_ipv4(_IP, _Eth, State) ->
    ?dbg("handle_ipv4: not handled: ~p\n", [_IP]),
    State.

handle_icmp(#icmp { type=echo_request,id=ID,seq=Seq,data=Data},IP,Eth,State) ->
    Icmp1 = #icmp { type=echo_reply, id=ID, seq=Seq, data=Data},
    IP1  = #ipv4 { src=IP#ipv4.dst, dst=IP#ipv4.src, proto=icmp, data=Icmp1 },
    Eth1 = #eth { src=Eth#eth.dst, dst=Eth#eth.src, type=ipv4, data=IP1},
    transmit_frame(Eth1, State),
    State;
handle_icmp(_Icmp,_IP,_Eth,State) ->
    ?dbg("handle_icmp: not handled: ~p\n", [_Icmp]),
    State.

handle_udp(_Udp=#udp { src_port = SrcPort, dst_port = DstPort, data=Data },
	   IP, _Eth, State) ->
    case dict:find({udp,IP#ipv4.dst,DstPort},State#state.sockets) of
	error ->
	    ?dbg("handle_udp: not handled: ~p\n", [_Udp]),
	    %% icmp error?
	    State;
	{ok,#socket{ref=Ref,owner=Pid}} ->
	    Pid  ! {udp,Ref,IP#ipv4.src,SrcPort,Data},
	    State
    end;
handle_udp(_Udp,_IP,_Eth,State) ->
    ?dbg("handle_udp: not handled: ~p\n", [_Udp]),
    State.


handle_tcp(Tcp=#tcp { src_port = SrcPort, dst_port = DstPort },
	   IP, Eth, State) ->
    Key = {tcp,IP#ipv4.dst,DstPort,IP#ipv4.src,SrcPort},
    case dict:find(Key, State#state.sockets) of
	error ->
	    LKey = {tcp,IP#ipv4.dst,DstPort},
	    case dict:find(LKey,State#state.sockets) of
		error ->
		    ?dbg("handle_tcp: not handled: ~p\n", [Tcp]),
		    %% icmp error?
		    State;
		{ok,Socket} ->
		    handle_tcp_input(LKey,Socket,Tcp,IP,Eth,State)
	    end;
	{ok,Socket} ->
	    handle_tcp_input(Key,Socket,Tcp,IP,Eth,State)
    end;
handle_tcp(_Tcp,_IP,_Eth,State) ->
    ?dbg("handle_tcp: not handled: ~p\n", [_Tcp]),
    State.

handle_tcp_input(Key,LSocket=#socket{tcp_state=listen},Tcp,IP,Eth,State) ->
    case Tcp of
	#tcp { urg=false,ack=false,psh=false,rst=false,syn=true,fin=false,
	       window=Window,options=Options,data= <<>> } ->
	    case LSocket#socket.aqueue of
		[{Ref,Pid}|AQueue] ->
		    Key1 = {tcp,IP#ipv4.dst,Tcp#tcp.dst_port,
			    IP#ipv4.src,Tcp#tcp.src_port},
		    Mss = if State#state.mtu > ?TCP_IPV4_HEADER_MIN_LEN ->
				  State#state.mtu-?TCP_IPV4_HEADER_MIN_LEN;
			     true -> 1500 - ?TCP_IPV4_HEADER_MIN_LEN
			  end,
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Ostream = #stream { mss=Mss, seq=random_32(),
					wsize=Window, wscale=Wscale },
		    Istream = #stream { seq=?seq_next(Tcp#tcp.seq_no) },

		    Socket = #socket { ref=Ref, mac = Eth#eth.dst,
				       src = IP#ipv4.dst,
				       src_port = Tcp#tcp.dst_port,
				       dst = IP#ipv4.src,
				       dst_port = Tcp#tcp.src_port,
				       tcp_state = syn_rcvd,
				       proto = tcp, 
				       owner = Pid,
				       istream = Istream,
				       ostream = Ostream
				     },
		    ?dbg("socket syn_rcvd = ~w\n", [Socket]),
		    LSocket1 = LSocket#socket { aqueue = AQueue },
		    Sockets1 = dict:store(Key, LSocket1, State#state.sockets),
		    Sockets2 = dict:store(Key1, Socket, Sockets1),
		    SockRef = dict:store(Ref, Key1, State#state.sockref),
		    State1 =  State#state { sockets=Sockets2, sockref=SockRef},
		    TcpOptions = [],
		    transmit_syn_ack(Socket, TcpOptions, State1);
		[] ->
		    %% no one will accept the call?
		    ?dbg("handle_tcp_accept: no acceptor: ~p\n", [Tcp]),
		    State
	    end;
	_ ->
	    %% no one will accept the call?
	    ?dbg("handle_tcp_accept: tcp not accepted: ~p\n", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=syn_rcvd,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=Window,options=Options,data= <<>> } when
	      Ack =:= ?seq_next(Ostream#stream.seq) ->
	    Pid ! {tcp_connected, Ref, IP#ipv4.src, Tcp#tcp.src_port},
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Ostream1 = Ostream#stream {	seq=Ack, wsize=Window, wscale=Wscale },
	    Istream1 = Istream#stream { seq=?seq_next(Seq) },
	    Socket1 = Socket#socket { tcp_state = established,
				      istream = Istream1,
				      ostream = Ostream1 },
	    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
	    State#state { sockets = Sockets1 };
	_ ->
	    ?dbg("handle_tcp_input(syn_rcvd): tcp dropped: ~p\n", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=syn_sent,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=true,psh=false,
	       rst=false,syn=true,fin=false,
	       window=Window,options=Options,data= <<>> } when
	      Ack =:= ?seq_next(Ostream#stream.seq) ->
	    Pid ! {tcp_connected, Ref, IP#ipv4.src, Tcp#tcp.src_port},
	    Mss = proplists:get_value(mss, Options,
				      1500-?TCP_IPV4_HEADER_MIN_LEN),
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Ostream1 = Ostream#stream { seq=Ack },
	    Istream1 = Istream#stream { wsize=Window, wscale=Wscale,
					mss = Mss, bytes=0, 
					seq=?seq_next(Seq),
					segs=[]},
	    Socket1 = Socket#socket { tcp_state = established,
				      ostream=Ostream1,
				      istream=Istream1 },
	    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
	    TcpOptions = [],
	    State1 = State#state { sockets = Sockets1 },
	    transmit_ack(Socket1,TcpOptions,State1);
	_ ->
	    ?dbg("handle_tcp_input(syn_rcvd): tcp dropped: ~p\n", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=established,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=IsAck,psh=true,
	       rst=false,syn=false,fin=false,
	       window=Window,options=Options,data=Data } ->
	    Ostream1 = ack_output_data(IsAck, Ack, Ostream),
	    if Seq =:= Istream#stream.seq ->  %% new data
		    Pid ! {tcp,Ref,Data},
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Len = byte_size(Data),
		    Istream1 = Istream#stream { wsize=Window, wscale=Wscale,
						seq=?u32(Seq+Len),
						segs=[]},
		    Socket1 = Socket#socket { ostream=Ostream1,
					      istream=Istream1 },
		    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
		    TcpOptions = [],
		    State1 = State#state { sockets = Sockets1 },
		    transmit_ack(Socket1,TcpOptions,State1);
	       true ->
		    Socket1 = Socket#socket { ostream=Ostream1 },
		    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
		    TcpOptions = [],
		    State1 = State#state { sockets = Sockets1 },
		    transmit_ack(Socket1,TcpOptions,State1)
	    end;
	_ ->
	    ?dbg("handle_tcp_input(established): tcp dropped: ~p\n", [Tcp]),
	    State
    end;
handle_tcp_input(_Key,_Socket,Tcp,_IP,_Eth,State) ->
    ?dbg("handle_tcp_input: not handled: ~p\n", [Tcp]),
    State.


%% respon or cache arp entries
handle_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIP},
		       target = {TargetMac, TargetIP}},_Eth,State) ->
    ?dbg("cache arp: ~p\n", [_Arp]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIP, SenderMac, State),
    State2 = insert_cache(TargetIP, TargetMac, State1),
    State2;
handle_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIP},
		      target = {TargetMac, TargetIP}},Eth,State) ->
    ?dbg("handle arp request: ~p\n", [Arp]),
    case (TargetMac =:= ?ZERO) orelse
	sets:is_element(TargetMac,State#state.macs) of
	true ->
	    case dict:find(TargetIP, State#state.ipmac) of
		error ->
		    State;
		{ok,TargetMac1} ->
		    ?dbg("handle arp reply with mac=~w\n", [TargetMac1]),
		    transmit_arp(Eth#eth.src,Eth#eth.dst,
				 Arp#arp { op=reply,
					   sender={TargetMac1,TargetIP},
					   target={SenderMac,SenderIP}}, State),
		    State
	    end;
	false ->
	    State
    end;
handle_arp(Arp,_Eth,State) ->
    ?dbg("handle_arp: not handled: ~p\n", [Arp]),
    State.

%% Handle ack of output data (fixme handle sack)
ack_output_data(true, Ack, Ostream) -> %% check Ack within expected bounds
    if Ack =:= ?seq_next(Ostream#stream.seq+Ostream#stream.bytes) ->
	    Ostream1 = Ostream#stream { seq = Ack },
	    %% transmit data
	    Ostream1;
       true ->
	    Ostream
    end;
ack_output_data(false, _Ack, Ostream) ->
    Ostream.


transmit_arp(Dst,Src,Arp,State) ->
    Frame=#eth { src=Src, dst=Dst, type=arp, data=Arp},
    transmit_frame(Frame, State).

transmit_udp(Ref,DstIP,DstPort,Data,State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {error, einval};
	{ok, SockKey} ->
	    case dict:find(SockKey, State#state.sockets) of
		error ->
		    {error, einval};
		{ok, Socket} ->
		    Udp = #udp { src_port = Socket#socket.src_port,
				 dst_port = DstPort,
				 data = Data },
		    Ip  = #ipv4 { src=Socket#socket.src,
				  dst=DstIP, proto=udp, data=Udp },
		    %% this lookup should be placed before udp_send!
		    DstMac = cache_lookup(DstIP, State),
		    Eth = #eth { src=Socket#socket.mac, dst=DstMac,
				 type=ipv4,data=Ip },
		    transmit_frame(Eth, State),
		    ok
	    end
    end.


transmit_syn(Socket=#socket{ostream=Ostream, istream=Istream},Options,State) ->
    Options1 = if Istream#stream.wscale > 0 ->
		       [{window_size_shift, Istream#stream.wscale}|Options];
		  true ->
		       Options
	       end,
    Options2 = [{mss,Ostream#stream.mss}|Options1],

    Tcp = #tcp { src_port = Socket#socket.src_port,
		 dst_port = Socket#socket.dst_port,
		 seq_no   = Ostream#stream.seq,
		 ack_no   = Istream#stream.seq,
		 data_offset=0,
		 reserved=0,
		 urg=false,ack=false,psh=false,
		 rst=false,syn=true,fin=false,
		 window= Ostream#stream.wsize,
		 csum=correct,
		 urg_pointer=0,
		 options = Options2,
		 data = <<>>},
    Ip  = #ipv4 { src=Socket#socket.src,
		  dst=Socket#socket.dst, 
		  proto=tcp, data=Tcp },
    DstMac = cache_lookup(Socket#socket.dst, State), %% fixme!!!
    Eth = #eth { src=Socket#socket.mac, dst=DstMac,type=ipv4,data=Ip },
    ?dbg("transmit syn = ~w\n", [Eth]),
    transmit_frame(Eth, State),
    State.
    
transmit_syn_ack(Socket=#socket{ostream=Ostream, istream=Istream},
		 Options, State) ->
    Options1 = if Istream#stream.wscale > 0 ->
		       [{window_size_shift, Istream#stream.wscale}|Options];
		  true ->
		       Options
	       end,
    Options2 = [{mss,Ostream#stream.mss}|Options1],
    Tcp = #tcp { src_port = Socket#socket.src_port,
		 dst_port = Socket#socket.dst_port,
		 seq_no   = Ostream#stream.seq,
		 ack_no   = Istream#stream.seq,
		 data_offset=0,
		 reserved=0,
		 urg=false,ack=true,psh=false,
		 rst=false,syn=true,fin=false,
		 window=Istream#stream.wsize,
		 csum=correct,
		 urg_pointer=0,
		 options = Options2,
		 data = <<>>},
    Ip  = #ipv4 { src=Socket#socket.src,
		  dst=Socket#socket.dst, proto=tcp, data=Tcp },
    DstMac = cache_lookup(Socket#socket.dst, State), %% fixme!!!
    Eth = #eth { src=Socket#socket.mac, dst=DstMac,type=ipv4,data=Ip },
    ?dbg("transmit syn/ack = ~w\n", [Eth]),
    transmit_frame(Eth, State),
    State.

transmit_ack(Socket=#socket{ostream=Ostream, istream=Istream},
	     Options, State) ->
    Options1 = if Istream#stream.wscale > 0 ->
		       [{window_size_shift, Istream#stream.wscale}|Options];
		  true ->
		       Options
	       end,
    Tcp = #tcp { src_port = Socket#socket.src_port,
		 dst_port = Socket#socket.dst_port,
		 seq_no   = Ostream#stream.seq,
		 ack_no   = Istream#stream.seq,
		 data_offset=0,
		 reserved=0,
		 urg=false,ack=true,psh=false,
		 rst=false,syn=false,fin=false,
		 window=Istream#stream.wsize,
		 csum=correct,
		 urg_pointer=0,
		 options = Options1,
		 data = <<>>},
    Ip  = #ipv4 { src=Socket#socket.src,
		  dst=Socket#socket.dst, proto=tcp, data=Tcp },
    DstMac = cache_lookup(Socket#socket.dst, State), %% fixme!!!
    Eth = #eth { src=Socket#socket.mac, dst=DstMac,type=ipv4,data=Ip },
    ?dbg("transmit ack = ~w\n", [Eth]),
    transmit_frame(Eth, State),
    State.


transmit_frame(Frame, State) ->
    Data=enet_eth:encode(Frame, []),
    eth_devices:send(State#state.eth, Data).

get_mac_address(Interface) ->
    {ok, IfList} =  inet:getifaddrs(),
    case lists:keyfind(Interface, 1, IfList) of
	false -> undefined;
	{_,Fs} -> list_to_tuple(proplists:get_value(hwaddr,Fs))
    end.

random_32() ->
    <<X:32>> = crypto:rand_bytes(4),
    X.

%% build for 
insert_cache(_, {0,0,0,0,0,0}, State) -> State;
insert_cache({0,0,0,0}, _, State) -> State;
insert_cache({0,0,0,0,0,0,0,0}, _, State) -> State;
insert_cache(IP, Mac, State) ->
    IPMac = dict:store(IP, Mac, State#state.cache),
    State#state { cache = IPMac }.

cache_lookup(IP, State) ->
    case dict:find(IP, State#state.cache) of
	{ok,Mac} -> Mac;
	error -> ?BROADCAST   %% signal that arp is needed (or route)
    end.
