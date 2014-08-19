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

-define(dbg(F,A), io:format("~s:~w: "++(F)++"\r\n",[?FILE,?LINE|(A)])).
%% -define(dbg(F,A), ok).
-compile(export_all).

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

-define(TCP_LISTEN, listen).
-define(TCP_SYN_RCVD, syn_rcvd).
-define(TCP_SYN_SENT, syn_sent).
-define(TCP_ESTABLISHED, established).
-define(TCP_FIN_WAIT1, fin_wait1).
-define(TCP_FIN_WAIT2, fin_wait2).
-define(TCP_CLOSING, closing).
-define(TCP_TIME_WAIT, time_wait).
-define(TCP_CLOSE_WAIT, close_wait).
-define(TCP_LAST_ACK, last_ack).
-define(TCP_CLOSED, closed).


-type tcp_state() ::
	?TCP_LISTEN | ?TCP_SYN_RCVD  | ?TCP_SYN_SENT | ?TCP_ESTABLISHED |
	?TCP_FIN_WAIT1 | ?TCP_FIN_WAIT2 | ?TCP_CLOSING  | ?TCP_TIME_WAIT |
	?TCP_CLOSE_WAIT | ?TCP_LAST_ACK  | ?TCP_CLOSED.
%%
%% input stream window = wsize*(1<<wscale ) our own anounced input size
%%
%% output stream window = wsize*(1<<wscale) other sides input size
%%                        as used for transmission

%% fixme: add a fin pushed flag! to make sure data is not pushed after fin!
%% fixme: add callbacks that are called when data is acked!
-record(stream,
	{
	  window=65535,          %% current announced window size
	  mss :: uint16(),       %% maximum segment size used
	  bytes = 0 :: uint32(), %% number bytes sent / received in window
	  seq = 0 :: uint32(),   %% current seqeuence number
	  closed = false :: pushed | boolean(),
	  %% unacked output segments / undelivered input segments
	  segments = []  :: [{Seq::uint32(),binary()}]
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

%% send binary data or if a list of binaries, send each binary as 
%% one or more segments.
tcp_send(Net, TcpRef, Data) when is_binary(Data);
				 is_binary(hd(Data)) ->
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
	    ?dbg("try to udp_close on ~w", [_SockKey]),
	    {reply, {error, einval},  State}
    end;
handle_call({udp_send,Ref,DstIP,DstPort,Data}, _From, State) ->
    {Result,State1} = transmit_udp(Ref,DstIP,DstPort,Data, State),
    {reply,Result,State1};

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
				       tcp_state = ?TCP_LISTEN,
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
		    Mss = calc_mss(SrcIP, State),
		    Ostream = #stream { mss=Mss, seq=random_32() },
		    Istream = #stream {},
		    Socket = #socket { ref=Ref, mac = SrcMac,
				       src = SrcIP,src_port = SrcPort,
				       dst = DstIP,dst_port = DstPort,
				       proto = tcp, 
				       tcp_state = ?TCP_SYN_SENT,
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

handle_call({tcp_send,Ref,Data}, _From, State) ->
    case enqueue_data(Ref, Data, State) of
	{ok,Socket,Key,State1} ->
	    TcpOptions = [],
	    State2 = transmit_data(Socket,Key,TcpOptions, State1),
	    {reply, ok, State2};
	{Error, State1} ->
	    {reply, Error, State1}
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
	    ?dbg("try to tcp_close on ~w", [_SockKey]),
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

handle_info({tcp,Ref,Data}, State) ->
    case enqueue_data(Ref, Data, State) of
	{ok,Socket,Key,State1} ->
	    TcpOptions = [],
	    State2 = transmit_data(Socket,Key,TcpOptions,State1),
	    {noreply, State2};
	{Error, State1} ->
	    ?dbg("unable to queue segments: ~p", [Error]),
	    {noreply, State1}
    end;
handle_info({tcp_close,Ref}, State) ->
    case enqueue_data(Ref, fin, State) of
	{ok,Socket,Key,State1} ->
	    TcpOptions = [],
	    State2 = transmit_data(Socket,Key,TcpOptions,State1),
	    {noreply, State2};
	{Error, State1} ->
	    ?dbg("unable to queue fin segments: ~p", [Error]),
	    {noreply, State1}
    end;

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
    ?dbg("got info: ~p", [_Info]),
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
	    ?dbg("closing socket ~p", [Socket]),
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
	    ?dbg("closing accept on socket ~p", [Socket]),
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
	    ?dbg("closing socket ~p", [Socket]),
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
    ?dbg("handle_frame: not handled: ~p", [_Frame]),
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
    ?dbg("handle_ipv4: not handled: ~p", [_IP]),
    State.

handle_icmp(#icmp { type=echo_request,id=ID,seq=Seq,data=Data},IP,Eth,State) ->
    Icmp1 = #icmp { type=echo_reply, id=ID, seq=Seq, data=Data},
    IP1  = #ipv4 { src=IP#ipv4.dst, dst=IP#ipv4.src, proto=icmp, data=Icmp1 },
    Eth1 = #eth { src=Eth#eth.dst, dst=Eth#eth.src, type=ipv4, data=IP1},
    transmit_frame(Eth1, State),
    State;
handle_icmp(_Icmp,_IP,_Eth,State) ->
    ?dbg("handle_icmp: not handled: ~p", [_Icmp]),
    State.

handle_udp(_Udp=#udp { src_port = SrcPort, dst_port = DstPort, data=Data },
	   IP, _Eth, State) ->
    case dict:find({udp,IP#ipv4.dst,DstPort},State#state.sockets) of
	error ->
	    ?dbg("handle_udp: not handled: ~p", [_Udp]),
	    %% icmp error?
	    State;
	{ok,#socket{ref=Ref,owner=Pid}} ->
	    Pid  ! {udp,Ref,IP#ipv4.src,SrcPort,Data},
	    State
    end;
handle_udp(_Udp,_IP,_Eth,State) ->
    ?dbg("handle_udp: not handled: ~p", [_Udp]),
    State.


handle_tcp(Tcp=#tcp { src_port = SrcPort, dst_port = DstPort },
	   IP, Eth, State) ->
    Key = {tcp,IP#ipv4.dst,DstPort,IP#ipv4.src,SrcPort},
    case dict:find(Key, State#state.sockets) of
	error ->
	    LKey = {tcp,IP#ipv4.dst,DstPort},
	    case dict:find(LKey,State#state.sockets) of
		error ->
		    ?dbg("handle_tcp: not handled: ~p", [Tcp]),
		    %% icmp error?
		    State;
		{ok,Socket} ->
		    handle_tcp_input(LKey,Socket,Tcp,IP,Eth,State)
	    end;
	{ok,Socket} ->
	    handle_tcp_input(Key,Socket,Tcp,IP,Eth,State)
    end;
handle_tcp(_Tcp,_IP,_Eth,State) ->
    ?dbg("handle_tcp: not handled: ~p", [_Tcp]),
    State.

handle_tcp_input(Key,LSocket=#socket{tcp_state=?TCP_LISTEN},Tcp,IP,Eth,State) ->
    case Tcp of
	#tcp { urg=false,ack=false,psh=false,rst=false,syn=true,fin=false,
	       window=Wsize,options=Options,data= <<>> } ->
	    case LSocket#socket.aqueue of
		[{Ref,Pid}|AQueue] ->
		    Key1 = {tcp,IP#ipv4.dst,Tcp#tcp.dst_port,
			    IP#ipv4.src,Tcp#tcp.src_port},
		    Mss = calc_mss(IP#ipv4.dst, State),
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Window = wss_to_window(Wsize,Wscale),
		    Ostream = #stream { window=Window,mss=Mss,seq=random_32() },
		    Istream = #stream { seq=?seq_next(Tcp#tcp.seq_no) },

		    Socket = #socket { ref=Ref, mac = Eth#eth.dst,
				       src = IP#ipv4.dst,
				       src_port=Tcp#tcp.dst_port,
				       dst = IP#ipv4.src,
				       dst_port = Tcp#tcp.src_port,
				       tcp_state = ?TCP_SYN_RCVD,
				       proto = tcp, 
				       owner = Pid,
				       istream = Istream,
				       ostream = Ostream
				     },
		    ?dbg("socket syn_rcvd = ~w", [Socket]),
		    LSocket1 = LSocket#socket { aqueue = AQueue },
		    Sockets1 = dict:store(Key, LSocket1, State#state.sockets),
		    Sockets2 = dict:store(Key1, Socket, Sockets1),
		    SockRef = dict:store(Ref, Key1, State#state.sockref),
		    State1 =  State#state { sockets=Sockets2, sockref=SockRef},
		    TcpOptions = [],
		    transmit_syn_ack(Socket, TcpOptions, State1);
		[] ->
		    %% no one will accept the call?
		    ?dbg("handle_tcp_accept: no acceptor: ~p", [Tcp]),
		    State
	    end;
	_ ->
	    %% no one will accept the call?
	    ?dbg("handle_tcp_accept: tcp not accepted: ~p", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=?TCP_SYN_RCVD,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=Wsize,options=Options,data= <<>> } when
	      Ack =:= ?seq_next(Ostream#stream.seq) ->
	    Pid ! {tcp_connected, Ref, IP#ipv4.src, Tcp#tcp.src_port},
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Window = wss_to_window(Wsize,Wscale),
	    Ostream1 = Ostream#stream {	seq=Ack, window=Window },
	    Istream1 = Istream#stream { seq=?seq_next(Seq) },
	    Socket1 = Socket#socket { tcp_state = ?TCP_ESTABLISHED,
				      istream = Istream1,
				      ostream = Ostream1 },
	    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
	    State#state { sockets = Sockets1 };
	_ ->
	    ?dbg("handle_tcp_input(syn_rcvd): tcp dropped: ~p", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=?TCP_SYN_SENT,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=true,psh=false,
	       rst=false,syn=true,fin=false,
	       window=Wsize,options=Options,data= <<>> } when
	      Ack =:= ?seq_next(Ostream#stream.seq) ->
	    Pid ! {tcp_connected, Ref, IP#ipv4.src, Tcp#tcp.src_port},
	    Mss = proplists:get_value(mss, Options,
				      1500-?TCP_IPV4_HEADER_MIN_LEN),
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Window = wss_to_window(Wsize,Wscale),
	    Ostream1 = Ostream#stream { seq=Ack },
	    Istream1 = Istream#stream { window=Window,mss=Mss,bytes=0, 
					seq=?seq_next(Seq), segments=[]},
	    Socket1 = Socket#socket { tcp_state = ?TCP_ESTABLISHED,
				      ostream=Ostream1,
				      istream=Istream1 },
	    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
	    TcpOptions = [],
	    State1 = State#state { sockets = Sockets1 },
	    transmit_ack(Socket1,TcpOptions,State1);
	_ ->
	    ?dbg("handle_tcp_input(syn_rcvd): tcp dropped: ~p", [Tcp]),
	    State
    end;
handle_tcp_input(Key,Socket=#socket{ref=Ref,
				    tcp_state=?TCP_ESTABLISHED,
				    istream=Istream,
				    ostream=Ostream,
				    owner=Pid
				   },Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=Ack,urg=false,ack=IsAck,psh=_IsPsh,
	       rst=false,syn=false,fin=false,
	       window=Wsize,options=Options,data=Data } ->
	    Ostream1 = ack_output_data(IsAck, Ack, Socket, Ostream),
	    if Seq =:= Istream#stream.seq ->  %% new data
		    Len = byte_size(Data),
		    if Len > 0 ->  %% IsPsh or wait?
			    Pid ! {tcp,Ref,Data};
		       true ->
			    ok
		    end,
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Window = wss_to_window(Wsize,Wscale),
		    Istream1 = Istream#stream { window=Window,
						seq=?u32(Seq+Len),
						segments=[] },
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
	    ?dbg("handle_tcp_input(established): tcp dropped: ~p", [Tcp]),
	    State
    end;
handle_tcp_input(_Key,_Socket,Tcp,_IP,_Eth,State) ->
    ?dbg("handle_tcp_input: not handled: ~p", [Tcp]),
    State.

%% respon or cache arp entries
handle_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIP},
		       target = {TargetMac, TargetIP}},_Eth,State) ->
    ?dbg("cache arp: ~p", [_Arp]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIP, SenderMac, State),
    State2 = insert_cache(TargetIP, TargetMac, State1),
    State2;
handle_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIP},
		      target = {TargetMac, TargetIP}},Eth,State) ->
    ?dbg("handle arp request: ~p", [Arp]),
    case (TargetMac =:= ?ZERO) orelse
	sets:is_element(TargetMac,State#state.macs) of
	true ->
	    case dict:find(TargetIP, State#state.ipmac) of
		error ->
		    State;
		{ok,TargetMac1} ->
		    ?dbg("handle arp reply with mac=~w", [TargetMac1]),
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
    ?dbg("handle_arp: not handled: ~p", [Arp]),
    State.

%% Handle ack of output data (fixme handle sack)
ack_output_data(true,Ack,Socket,Ostream) -> %% check Ack within expected bounds
    Segments = ack_segments(Ack,Socket,Ostream#stream.segments),
    Ostream#stream { seq = Ack, segments=Segments };
ack_output_data(false,_Ack,_Socket,Ostream) ->
    Ostream.

ack_segments(Ack,Socket,Segments0=[{Seq,Data}|Segments]) ->
    Seq1 = ?u32(Seq+segment_size(Data)),
    if Ack >= Seq1 ->
	    ?dbg("acked data ~w:~p", [Seq1,Data]),
	    if is_reference(Data) ->
		    Socket#socket.owner ! {tcp_event,Socket#socket.ref,Data};
	       is_function(Data,0) ->
		    (catch Data());
	       true ->
		    ok
	    end,
	    ack_segments(Ack,Socket,Segments);
       true -> Segments0
    end;
ack_segments(_Ack,_Socket,[]) ->
    [].

%% put data onto output segment queue
%% accepted data format: (soon)
%%   item() = binary() | 'fin' | reference() | callback().
%%   Data = item() | [item()]
%%   
enqueue_data(Ref, Data, State) ->
    case dict:find(Ref, State#state.sockref) of
	{ok,Key} ->
	    case dict:find(Key,State#state.sockets) of
		error ->
		    {{error, einval}, State};
		{ok,Socket=#socket { tcp_state = TcpState,
				     ostream = Ostream } } when
		      TcpState =:= ?TCP_ESTABLISHED;
		      ((TcpState =:= ?TCP_SYN_RCVD) andalso Data =:= fin) ->
		    Ostream1 = enqueue_stream(Ostream, Data),
		    Socket1 = Socket#socket { ostream = Ostream1 },
		    Sockets1 = dict:store(Key, Socket1, State#state.sockets),
		    State1 = State#state { sockets=Sockets1 },
		    {ok, Socket1, Key, State1};
		{ok,_Socket} ->
		    {{error, einval}, State}
	    end;
	_ ->
	    {{error, einval},  State}
    end.

%% put data onto segments list
enqueue_stream(Stream,fin) ->
    Stream#stream { closed=pushed };
enqueue_stream(Stream,Mark) when is_reference(Mark); is_function(Mark,0);
				 Mark =:= <<>>; Mark =:= [] ->
    LastSeq = next_sequence_no(Stream),
    Segments = Stream#stream.segments,
    Stream#stream { segments = Segments ++ [{LastSeq,Mark}]};
enqueue_stream(Stream=#stream{mss=Mss,segments=Segments},Data) 
  when is_binary(Data); is_list(Data) ->
    LastSeq = next_sequence_no(Stream),
    MoreSegments = make_segment_list_(LastSeq, Mss, Data, [], []),
    Stream#stream { segments = Segments ++ MoreSegments }.


%% store this in stream?
next_sequence_no(#stream { seq=Seq,segments=[] }) -> Seq;
next_sequence_no(#stream { segments=Segments }) ->
    {Seq,Data} = lists:last(Segments),
    ?u32(Seq+segment_size(Data)).
    
segment_size(Data) when is_binary(Data) ->
    byte_size(Data);
segment_size(Data) when is_reference(Data) -> 0;
segment_size(Data) when is_function(Data,0) -> 0.

%% Handle lists of segment data. This version does not try to merge
%% binaries because of testing purposes. User decide how segments are
%% handled (may require to be able to read mss).

make_segment_list_(Seq, Mss, [Data|Ds], Cont, Acc) ->
    make_segment_list_(Seq, Mss, Data, [Ds|Cont], Acc);
make_segment_list_(Seq, Mss, Data, Cont, Acc) when 
      byte_size(Data) =< Mss; is_reference(Data); is_function(Data,0) ->
    Acc1 = [{Seq,Data}|Acc],
    case Cont of
	[] -> lists:reverse(Acc1);
	[Data1|Cont1] -> 
	    Seq1 = ?u32(Seq + segment_size(Data)),
	    make_segment_list_(Seq1, Mss, Data1, Cont1, Acc1)
    end;
make_segment_list_(Seq, Mss, Data, Cont, Acc) when is_binary(Data) ->
    {Segment,Rest} = erlang:split_binary(Data, Mss),
    Seq1 = ?u32(Seq + Mss),
    make_segment_list_(Seq1, Mss, Rest, Cont, [{Seq,Segment}|Acc]).


transmit_arp(Dst,Src,Arp,State) ->
    Frame=#eth { src=Src, dst=Dst, type=arp, data=Arp},
    transmit_frame(Frame, State).

transmit_udp(Ref,DstIP,DstPort,Data,State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {{error, einval}, State};
	{ok, SockKey} ->
	    case dict:find(SockKey, State#state.sockets) of
		error ->
		    {{error, einval}, State};
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
		    {ok, State}
	    end
    end.

transmit_syn(Socket,TcpOptions,State) ->
    transmit_tcp(Socket,true,false,false,false,<<>>,TcpOptions,State,
		 "transmit syn").
    
transmit_syn_ack(Socket,TcpOptions,State) ->
    transmit_tcp(Socket,true,true,false,false,<<>>,TcpOptions,State,
		 "transmit syn/ack").

transmit_ack(Socket, TcpOptions, State) ->
    transmit_tcp(Socket,false,true,false,false,<<>>,TcpOptions,State,
		 "transmit ack").

%% fixme: send the as much as possible and do window accouting on
%% wsize / wscale stored in ostream wsize and wscale.
%% return {FinSent, State'}
transmit_data(Socket=#socket{ostream=Ostream}, Key, TcpOptions, State) ->
    #stream { closed=Closed,bytes=Bytes,window=Window,segments=Segments } =
	Ostream,
    R = transmit_stream(Socket,Segments,Bytes,Window,Closed,TcpOptions,State),
    case R of
	{true,State1} ->
	    Socket1 = Socket#socket { tcp_state = ?TCP_FIN_WAIT1 },
	    Sockets = dict:store(Key, Socket1, State1#state.sockets),
	    State1#state { sockets=Sockets };
	{false,State} ->
	    State
    end.
	
transmit_stream(Socket,[{Seq,Data}|Segments],Bytes,Window,Closed,
		TcpOptions,State) ->
    if is_binary(Data) ->
	    Bytes1 = Bytes + byte_size(Data),
	    if Bytes1 =< Window ->
		    if (Segments =:= <<>>) andalso (Closed =:= pushed) ->
			    State1 = transmit_tcp(Socket,Seq,false,true,
						  true,false,Data,TcpOptions,
						  State,"transmit fin"),
			    {true,State1};
		       true ->
			    State1 = transmit_tcp(Socket,Seq,false,true,
						  false,false,Data,TcpOptions,
						  State,"transmit segment"),
			    transmit_stream(Socket,Segments,Bytes1,Window,
					    Closed,TcpOptions,State1)
		    end;
	       true -> {false,State}
	    end;
       is_reference(Data); is_function(Data,0) ->
	    transmit_stream(Socket,Segments,Bytes,Window,Closed,
			    TcpOptions,State)
    end;
transmit_stream(_Socket, [], _Bytes, _Window, _Closed, _TcpOptions, State) ->
    {false,State}.


transmit_tcp(Socket,Syn,Ack,Fin,Rst,Data,TcpOptions,State,Msg) ->
    SeqNo = (Socket#socket.ostream)#stream.seq,
    transmit_tcp(Socket,SeqNo,Syn,Ack,Fin,Rst,Data,TcpOptions,State,Msg).
    
transmit_tcp(Socket=#socket{ostream=Ostream, istream=Istream},SeqNo,
	     Syn,Ack,Fin,Rst,Data,TcpOptions,State,Msg) ->
    Window = Istream#stream.window - Istream#stream.bytes, %% input remain
    {Wsize,Wscale} = window_to_wss(Window),
    TcpOptions1 = if Wscale > 0 -> [{window_size_shift,Wscale}|TcpOptions];
		     true -> TcpOptions
		  end,
    TcpOptions2 = if Syn -> [{mss,Ostream#stream.mss}|TcpOptions1];
		     true -> TcpOptions1
		  end,
    Tcp = #tcp { src_port = Socket#socket.src_port,
		 dst_port = Socket#socket.dst_port,
		 seq_no   = SeqNo,
		 ack_no   = Istream#stream.seq,
		 data_offset=0,
		 reserved=0,
		 urg=false,ack=Ack,psh=(Data =/= <<>>),
		 rst=Rst,syn=Syn,fin=Fin,
		 window=Wsize,
		 csum=correct,
		 urg_pointer=0,
		 options = TcpOptions2,
		 data = Data},
    transmit_ip(Socket, tcp, Tcp, State, Msg).
    
transmit_ip(Socket, Proto, Data, State, Mesg) ->
    Ip  = #ipv4 { src=Socket#socket.src,
		  dst=Socket#socket.dst,
		  proto=Proto, data=Data },
    %% fixme!!!
    DstMac = cache_lookup(Socket#socket.dst, State),
    Eth = #eth { src=Socket#socket.mac, dst=DstMac,type=ipv4,data=Ip },
    ?dbg("~s: ~p", [Mesg, Eth]),
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

%% calculte mss given protocol and interface mtu 
calc_mss(IP,State) when tuple_size(IP) =:= 4 ->
    if State#state.mtu > ?TCP_IPV4_HEADER_MIN_LEN ->
	    State#state.mtu-?TCP_IPV4_HEADER_MIN_LEN;
       true -> 1500 - ?TCP_IPV4_HEADER_MIN_LEN
    end;
calc_mss(IP,State) when tuple_size(IP) =:= 8 ->
    if State#state.mtu > ?TCP_IPV6_HEADER_MIN_LEN ->
	    State#state.mtu-?TCP_IPV6_HEADER_MIN_LEN;
       true -> 1500 - ?TCP_IPV6_HEADER_MIN_LEN
    end.

%% calculate size and scale on transmission window
wss_to_window({Window,Scale}) ->
    wss_to_window(Window, Scale).

wss_to_window(Wsize,WScale) ->
    Wsize bsl WScale.

window_to_wss(Window) ->
    window_to_wss(Window, 0).

%% fixme: make sure Scale <= 14!
window_to_wss(Window, Scale) ->
    if Window > 16#ffff -> window_to_wss(Window bsr 1, Scale+1);
       true  -> {Window,Scale}
    end.

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
