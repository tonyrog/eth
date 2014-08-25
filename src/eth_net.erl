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
-export([tcp_listen/4, tcp_accept/2, tcp_connect/6, tcp_send/3,
	 tcp_shutdown/2, tcp_close/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

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

-define(TCP_NULL, null).
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

-define(FIN, fin). %% easy to find

-type tcp_state() ::
	?TCP_NULL |
	?TCP_LISTEN | ?TCP_SYN_RCVD  | ?TCP_SYN_SENT | ?TCP_ESTABLISHED |
	?TCP_FIN_WAIT1 | ?TCP_FIN_WAIT2 | ?TCP_CLOSING  | ?TCP_TIME_WAIT |
	?TCP_CLOSE_WAIT | ?TCP_LAST_ACK  | ?TCP_CLOSED.


%%
%% input stream window = wsize*(1<<wscale ) our own anounced input size
%%
%% output stream window = wsize*(1<<wscale) other sides input size
%%                        as used for transmission

-define(is_segment(X),
	(is_binary((X)) orelse is_reference((X)) orelse ((X) =:= ?FIN))).

-type sdata() :: ?FIN | reference() | binary().

-record(segment,
	{
	  seq :: uint32(),
	  status = none :: none | send | waitack | ack,
	  data :: sdata()
	}).

-record(stream,
	{
	  window=65535,          %% current announced window size
	  mss :: uint16(),       %% maximum segment size used
	  bytes = 0 :: uint32(), %% number bytes sent / received in window
	  seq = 0 :: uint32(),   %% current seqeuence number
	  closed = false :: pushed | boolean(),
	  %% unacked output segments / undelivered input segments
	  segments = []  :: [#segment{}]
	}).

-record(lst_socket,  %% listen sockets
	{
	  ref      :: reference(),
	  key      :: socket_key(),
	  mac      :: ethernet_address(),
	  src      :: ip_address(),
	  dst      :: ip_address(),
	  src_port :: port_no(),
	  dst_port :: port_no(),
	  owner    :: pid(),
	  %% add syn queue .
	  aqueue = [] :: [{reference(),pid()}]   %% accept queue
	}).

%% RFC 6298, 1323
-define(MIN_RTO, 1.0).
-define(MAX_RTO, 60.0).
-define(START_RTO, 1.0).
-define(SYN_LOST_RTO, 3.0).    %% set if SYN is lost when established
-define(GRANULARITY_RTO, 0.1). %% clock granualarity G = 100ms = 0.1s

-define(MSL, 1000).  %% fixme. (could be upto 2*120 sec = 4 minutes)

-record(tcp_socket,
	{
	  ref      :: reference(),
	  key      :: socket_key(),
	  tcp_state = ?TCP_NULL :: tcp_state(),
	  mac      :: ethernet_address(),
	  src      :: ip_address(),
	  dst      :: ip_address(),
	  src_port :: port_no(),
	  dst_port :: port_no(),
	  owner    :: pid(),
	  tsecr = 0 :: non_neg_integer(), %% timestamp echo reply
	  rto = ?START_RTO :: float(),    %% retransmit timeout
	  srtt      :: float(),
	  rttvar    :: float(),
	  rt        :: reference(),       %% retransmit timer
	  ostream :: #stream{},
	  istream :: #stream{}
	}).

-record(udp_socket,
	{
	  ref      :: reference(),
	  key      :: socket_key(),
	  mac      :: ethernet_address(),
	  src      :: ip_address(),
	  dst      :: ip_address(),   %% set if connected
	  src_port :: port_no(),
	  dst_port :: port_no(),      %% set if connected
	  owner    :: pid()
	}).

-type socket() :: #tcp_socket{} | #udp_socket{} | #lst_socket{}.


-record(state,
	{
	  name :: string(),  %% name of interface (like "tap0", "en1", "eth0")
	  eth,       %% interface handler
	  mtu,       %% mtu size of interface / minimum mtu usable
	  mac :: ethernet_address(),       %% the mac address on interface
	  ipmac :: dict:dict(ip_address(),ethernet_address()),
	  macs :: sets:set(ethernet_address()),
	  cache :: dict:dict(ip_address(),ethernet_address()),
	  sockets :: dict:dict(socket_key(), socket()),
	  sockref :: dict:dict(reference(), socket_key())
	}).

-define(u32(X), ((X)  band 16#ffffffff)).
-define(seq_next(X), ?u32((X)+1)).
-define(seq_lte(X,Y), (?u32((Y)-(X)) < 16#40000000)).

%%%===================================================================
%%% API
%%%===================================================================


start(Interface) ->
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
%%
%% tcp interface
%%

tcp_listen(Net, SrcIP, SrcPort, Options) ->
    gen_server:call(Net, {tcp_listen, self(), SrcIP, SrcPort, Options}).

tcp_accept(Net, ListenRef) ->
    gen_server:call(Net, {tcp_accept, ListenRef, self()}).

tcp_connect(Net, SrcIP, SrcPort, DstIP, DstPort, Options) ->
    gen_server:call(Net, {tcp_connect, self(),
			  SrcIP, SrcPort, DstIP, DstPort, Options}).

%% send binary data or if a list of binaries, send each binary as
%% one or more segments.
tcp_send(Net, TcpRef, Data) when ?is_segment(Data);
				 ?is_segment(hd(Data)) ->
    gen_server:call(Net, {tcp_send, TcpRef, Data}).

%% send FIN and terminate gracefully
tcp_shutdown(Net, TcpRef) ->
    gen_server:call(Net, {tcp_shutdown, TcpRef}).

%% send FIN and terminate the stop the reciving part, RST if neede
tcp_close(Net, TcpRef) ->
    gen_server:call(Net, {tcp_close, TcpRef}).

%% async tcp interface
%%    Net ! {tcp,S,Data}    - enqueue socket data
%%    Net ! {close,S}       - enqueue FIN
%%
%%    {tcp,S,Data}
%%         data from socket
%%    {tcp_closed,S}
%%         FIN from socket (call tcp_close(Net,S) to terminate socket)
%%    {tcp_connected,S,SrcIP,SrcPort}
%%         Socket is connected after calling accept or connect
%%    {tcp_event,S,EventRef}
%%         Syncronisation, the EventRef was acked meaning that data
%%         queued before EventRef is received by other side.
%%

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
    case eth_devices:find(Interface) of
	{ok,Port} ->
	    %% erlang:monitor(port, Port) please !
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
	    {ok,Name} = eth_devices:get_name(Port),
	    {ok,Mac} = eth_devices:get_address(Name),
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
		    Socket = #udp_socket { ref=Ref, key=Key, mac=SrcMac,
					   src=SrcIP, src_port=SrcPort,
					   owner=Owner },
		    State1 = add_socket(Socket, State),
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
	    {Reply,State1} = close_session(SockKey,State),
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
		    Socket = #lst_socket { ref=Ref, key=Key,
					   mac = SrcMac,
					   src = SrcIP,
					   src_port = SrcPort,
					   owner = Owner },
		    State1 = add_socket(Socket, State),

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
	    AQueue = Socket#lst_socket.aqueue ++ [{Ref,Acceptor}],
	    Socket1 = Socket#lst_socket { aqueue = AQueue },
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
		    Socket = #tcp_socket { ref=Ref, key=Key, mac = SrcMac,
					   src = SrcIP,src_port = SrcPort,
					   dst = DstIP,dst_port = DstPort,
					   tcp_state = ?TCP_SYN_SENT,
					   ostream = Ostream,
					   istream = Istream,
					   owner = Owner },
		    Socket1 = transmit_syn(Socket,State),
		    State1 = add_socket(Socket1, State),
		    {reply, {ok,Ref}, State1}
	    end;
	{ok,_Socket} ->
	    {reply, {error,ealready}, State}
    end;

handle_call({tcp_send,Ref,Data}, _From, State) ->
    case enqueue_data(Ref, Data, State) of
	{ok,Socket} ->
	    Socket1 = send_data(Socket,State),
	    State1 = store_socket(Socket1,State),
	    {reply, ok, State1};
	Error ->
	    {reply, Error, State}
    end;

handle_call({tcp_shutdown,Ref}, _From, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {reply, {error, einval},  State};
	{ok, _SockKey={tcp,_IP,_Port}} ->
	    {reply, {error, einval},  State};
	{ok, _SockKey={tcp_a,_IP,_Port}} ->
	    {reply, {error, einval},  State};
	{ok, SockKey={tcp,_SrcIP,_SrcPort,_DstIP,_DstPort}} ->
	    {Reply,State1} = close_session(SockKey,State),
	    {reply, Reply, State1};
	{ok, _SockKey} ->
	    ?dbg("try to tcp_close on ~w", [_SockKey]),
	    {reply, {error, einval},  State}
    end;

handle_call({tcp_close,Ref}, _From, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {reply, {error, einval},  State};
	{ok, Key={tcp,_IP,_Port}} ->
	    {Reply,State1} = close_listen_socket(Ref,Key,State),
	    {reply, Reply, State1};
	{ok, Key={tcp_a,_IP,_Port}} ->
	    {Reply,State1} = close_accept_socket(Ref,Key,State),
	    {reply, Reply, State1};
	{ok, Key={tcp,_SrcIP,_SrcPort,_DstIP,_DstPort}} ->
	    %% fixme: disconnect owner, send RST if needed!
	    {Reply,State1} = close_session(Key,State),
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
	{ok,Socket} ->
	    Socket1 = send_data(Socket,State),
	    State1 = store_socket(Socket1,State),
	    {noreply, State1};
	Error ->
	    ?dbg("unable to queue segments: ~p", [Error]),
	    {noreply, State}
    end;
handle_info({timeout,_TRef,{close,Ref}}, State) ->
    case dict:find(Ref, State#state.sockref) of
	error -> {noreply, State};
	{ok,Key} ->
	    case dict:find(Key,State#state.sockets) of
		error -> {noreply, State};
		{ok,Socket=#tcp_socket{tcp_state=?TCP_TIME_WAIT}} ->
		    ?dbg("time_wait done killing socket ~p", [Socket]),
		    State1 = erase_socket(Socket, State),
		    {noreply,State1};
		{ok,_} ->
		    {noreply,State}
	    end
    end;
handle_info({close,Ref}, State) ->
    case enqueue_data(Ref, ?FIN, State) of
	{ok,Socket} ->
	    Socket1 = send_data(Socket,State),
	    State1 = store_socket(Socket1,State),
	    {noreply, State1};
	Error ->
	    ?dbg("unable to queue fin segments: ~p", [Error]),
	    {noreply, State}
    end;

handle_info({'DOWN', Ref, process, _Pid, _Reason}, State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {noreply, State};
	{ok, Key={tcp,_IP,_Port}} ->
	    {_Reply,State1} = close_listen_socket(Ref,Key,State),
	    {noreply, State1};
	{ok, Key={tcp_a,_IP,_Port}} ->
	    {_Reply,State1} = close_accept_socket(Ref,Key,State),
	    {noreply, State1};
	{ok, Key} -> %% tcp/udp
	    {_Reply,State1} = close_session(Key,State),
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

socket_key(#tcp_socket { key=Key }) -> Key;
socket_key(#udp_socket { key=Key }) -> Key;
socket_key(#lst_socket { key=Key }) -> Key.

socket_ref(#tcp_socket { ref=Ref }) -> Ref;
socket_ref(#udp_socket { ref=Ref }) -> Ref;
socket_ref(#lst_socket { ref=Ref }) -> Ref.

add_socket(Socket, State) ->
    Key = socket_key(Socket),
    Ref = socket_ref(Socket),
    Sockets = dict:store(Key,Socket,State#state.sockets),
    SockRef = dict:store(Ref,Key,State#state.sockref),
    State#state { sockets = Sockets, sockref = SockRef }.

erase_socket(Socket, State) ->
    Ref = socket_ref(Socket),
    erlang:demonitor(Ref, [flush]),
    SockRef = dict:erase(Ref, State#state.sockref),
    Sockets = dict:erase(socket_key(Socket), State#state.sockets),
    State#state { sockref=SockRef, sockets=Sockets}.

store_socket(Socket, State) ->
    Sockets = dict:store(socket_key(Socket), Socket, State#state.sockets),
    State#state { sockets = Sockets }.


close_listen_socket(Ref, SockKey, State) ->
    case dict:find(SockKey, State#state.sockets) of
	{ok,Socket} -> %% close queued accepter processes
	    ?dbg("closing socket ~p", [Socket]),
	    SockRef1 = lists:foldl(
			 fun({ARef,Pid},SockRef) ->
				 Pid ! {tcp_closed,ARef},
				 dict:erase(ARef, SockRef)
			 end, State#state.sockref, Socket#lst_socket.aqueue),
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
	    AQueue = Socket#lst_socket.aqueue,
	    case lists:keytake(1,Ref,AQueue) of
		false ->
		    {{error,enoent}, State};
		{value,_,AQueue1} -> %% close acceptor
		    erlang:demonitor(Ref, [flush]),
		    Socket1 = Socket#lst_socket { aqueue=AQueue1 },
		    Sockets1 = dict:store(LKey, Socket1, State#state.sockets),
		    SockRef1 = dict:erase(Ref, State#state.sockref),
		    {ok,State#state { sockets=Sockets1, sockref = SockRef1 }}
	    end;
	error ->
	    {{error,einval}, State}
    end.

close_session(Key, State) ->
    case dict:find(Key, State#state.sockets) of
	error ->
	    {{error,einval}, State};
	{ok,Socket} ->
	    if Socket#tcp_socket.tcp_state =:= ?TCP_ESTABLISHED;
	       Socket#tcp_socket.tcp_state =:= ?TCP_CLOSE_WAIT ->
		    Socket2 = case enqueue_socket_data(Socket,?FIN) of
				  {ok,Socket1} ->
				      send_data(Socket1,State);
				  _Error ->
				      Socket
			      end,
		    State1 = store_socket(Socket2, State),
		    {ok, State1};
	       Socket#tcp_socket.tcp_state =:= ?TCP_TIME_WAIT ->
		    {ok, State};
	       Socket#tcp_socket.tcp_state =:= ?TCP_FIN_WAIT1;
	       Socket#tcp_socket.tcp_state =:= ?TCP_FIN_WAIT2;
	       Socket#tcp_socket.tcp_state =:= ?TCP_CLOSING ->
		    {{error,einprogress}, State};
	       true ->
		    ?dbg("killing socket ~p", [Socket]),
		    State1 = erase_socket(Socket, State),
		    {ok, State1}
	    end
    end.

handle_frame(Eth=#eth { data = Arp = #arp {}}, State) ->
    handle_arp(Arp,Eth,State);
handle_frame(Eth=#eth { data = IP = #ipv4 {}}, State) ->
    %% FIXME: right now we update cache with latest info, this
    %% is probably not what we want ?
    State1 = insert_cache(IP#ipv4.src, Eth#eth.src, State),
    handle_ipv4(IP,Eth,State1);
handle_frame(_Frame, State) ->
    ?dbg("handle_frame: not handled: ~s", [eth_packet:fmt_erl(_Frame)]),
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
    ?dbg("handle_ipv4: not handled: ~s", [eth_packet:fmt_erl(_IP)]),
    State.

handle_icmp(#icmp { type=echo_request,id=ID,seq=Seq,data=Data},IP,Eth,State) ->
    Icmp1 = #icmp { type=echo_reply, id=ID, seq=Seq, data=Data},
    IP1  = #ipv4 { src=IP#ipv4.dst, dst=IP#ipv4.src, proto=icmp, data=Icmp1 },
    Eth1 = #eth { src=Eth#eth.dst, dst=Eth#eth.src, type=ipv4, data=IP1},
    transmit_frame(Eth1, State),
    State;
handle_icmp(_Icmp,_IP,_Eth,State) ->
    ?dbg("handle_icmp: not handled: ~s", [eth_packet:fmt_erl(_Icmp)]),
    State.

handle_udp(_Udp=#udp { src_port = SrcPort, dst_port = DstPort, data=Data },
	   IP, _Eth, State) ->
    case dict:find({udp,IP#ipv4.dst,DstPort},State#state.sockets) of
	error ->
	    ?dbg("handle_udp: not handled: ~s", [eth_packet:fmt_erl(_Udp)]),
	    %% icmp error?
	    State;
	{ok,#udp_socket{ref=Ref,owner=Pid}} ->
	    Pid  ! {udp,Ref,IP#ipv4.src,SrcPort,Data},
	    State
    end;
handle_udp(_Udp,_IP,_Eth,State) ->
    ?dbg("handle_udp: not handled: ~s", [eth_packet:fmt_erl(_Udp)]),
    State.


handle_tcp(Tcp=#tcp { src_port = SrcPort, dst_port = DstPort },
	   IP, Eth, State) ->
    Key = {tcp,IP#ipv4.dst,DstPort,IP#ipv4.src,SrcPort},
    case dict:find(Key, State#state.sockets) of
	error ->
	    LKey = {tcp,IP#ipv4.dst,DstPort},
	    case dict:find(LKey,State#state.sockets) of
		error ->
		    ?dbg("handle_tcp: not handled: ~s",
			 [eth_packet:fmt_erl(Tcp)]),
		    %% icmp error?
		    State;
		{ok,LSocket} ->
		    log_tcp(LSocket, Tcp, "<"),
		    case handle_accept(LSocket,Tcp,IP,Eth,State) of
			false ->
			    State;
			{LSocket1,Socket} ->
			    State1 = store_socket(LSocket1,State),
			    add_socket(Socket,State1)
		    end
	    end;
	{ok,Socket} ->
	    log_tcp(Socket, Tcp, "<"),
	    case tcp_fsm(Socket#tcp_socket.tcp_state,Socket,Tcp,IP,Eth,State) of
		false ->
		    State;
		undefined ->
		    ?dbg("killing socket ~p", [Socket]),
		    erase_socket(Socket, State);
		Socket1 ->
		    store_socket(Socket1, State)
	    end
    end;
handle_tcp(_Tcp,_IP,_Eth,State) ->
    ?dbg("handle_tcp: not handled: ~s", [eth_packet:fmt_erl(_Tcp)]),
    State.

%% Handle SYN packets when someone is willing to accept. fixme flow control!
handle_accept(LSocket,Tcp,IP,Eth,State) ->
    case Tcp of
	#tcp { urg=false,ack=false,psh=false,rst=false,syn=true,fin=false,
	       window=Wsize,options=Options,data= <<>> } ->
	    case LSocket#lst_socket.aqueue of
		[{Ref,Pid}|AQueue] ->
		    Key = {tcp,IP#ipv4.dst,Tcp#tcp.dst_port,
			   IP#ipv4.src,Tcp#tcp.src_port},
		    Mss = calc_mss(IP#ipv4.dst, State),
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Window = wss_to_window(Wsize,Wscale),
		    Ostream = #stream { window=Window,mss=Mss,seq=random_32() },
		    Istream = #stream { seq=?seq_next(Tcp#tcp.seq_no) },

		    Socket = #tcp_socket { ref=Ref, key=Key, mac=Eth#eth.dst,
					   src = IP#ipv4.dst,
					   src_port=Tcp#tcp.dst_port,
					   dst = IP#ipv4.src,
					   dst_port = Tcp#tcp.src_port,
					   tcp_state = ?TCP_SYN_RCVD,
					   owner = Pid,
					   istream = Istream,
					   ostream = Ostream
					 },
		    ?dbg("socket syn_rcvd = ~w", [Socket]),
		    Socket1 = transmit_syn_ack(Socket,State),
		    LSocket1 = LSocket#lst_socket { aqueue = AQueue },
		    {LSocket1,Socket1};
		[] ->
		    ?dbg("handle_tcp_input(listen): no acceptor:\n~s\n",
			 [eth_packet:fmt_erl(Tcp)]),
		    false
	    end;
	_ ->
	    ?dbg("handle_tcp_input(listen): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end.

%%
%% tcp_fsm - tcp state machine
%%
tcp_fsm(?TCP_SYN_RCVD,Socket=#tcp_socket{istream=Istream,ostream=Ostream},
	Tcp,IP,_Eth,_State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=Wsize,options=Options,data= <<>> } when
	      AckNo =:= ?seq_next(Ostream#stream.seq) ->
	    tcp_report_connected(Socket, IP#ipv4.src, Tcp#tcp.src_port),
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Window = wss_to_window(Wsize,Wscale),
	    Ostream1 = Ostream#stream {	seq=AckNo, window=Window },
	    Istream1 = Istream#stream { seq=Seq }, %% ?seq_next(Seq) },
	    Socket#tcp_socket { tcp_state = ?TCP_ESTABLISHED,
				istream = Istream1,
				ostream = Ostream1 };
	_ ->
	    ?dbg("tcp_fsm(syn_rcvd): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_SYN_SENT,Socket=#tcp_socket{ istream=Istream, ostream=Ostream },
	Tcp,IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=true,fin=false,
	       window=Wsize,options=Options,data= <<>> } when
	      AckNo =:= ?seq_next(Ostream#stream.seq) ->
	    tcp_report_connected(Socket, IP#ipv4.src, Tcp#tcp.src_port),
	    Mss = proplists:get_value(mss, Options,
				      1500-?TCP_IPV4_HEADER_MIN_LEN),
	    Wscale = proplists:get_value(window_size_shift,Options,0),
	    Window = wss_to_window(Wsize,Wscale),
	    Ostream1 = Ostream#stream { seq=AckNo },
	    Istream1 = Istream#stream { window=Window,mss=Mss,bytes=0,
					seq=?seq_next(Seq), segments=[]},
	    Socket1 = Socket#tcp_socket { tcp_state = ?TCP_ESTABLISHED,
					  ostream=Ostream1,
					  istream=Istream1 },
	    transmit_ack(Socket1,State);
	_ ->
	    ?dbg("tcp_fsm(syn_sent): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_ESTABLISHED, Socket=#tcp_socket{ istream=Istream,ostream=Ostream },
	Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=Ack,psh=_IsPsh,
	       rst=false,syn=false,fin=Fin,
	       window=Wsize,options=Options,data=Data } ->
	    Ostream1 = ack_output_data(Ack, AckNo, Socket, Ostream),
	    %% FIXME: a lot of code here for handling out-of-order
	    %%        reception, sack etc.
	    if Seq =:= Istream#stream.seq ->
		    Len = byte_size(Data),
		    tcp_report_data(Socket, Data),
		    TcpState = if Fin -> tcp_report_closed(Socket),
					 ?TCP_CLOSE_WAIT;
				  true -> ?TCP_ESTABLISHED
			       end,
		    Wscale = proplists:get_value(window_size_shift,Options,0),
		    Window = wss_to_window(Wsize,Wscale),
		    ISeq = if Fin -> ?u32(Seq+Len+1); true -> ?u32(Seq+Len) end,
		    Istream1 = Istream#stream { window=Window,
						closed=Fin,
						seq=ISeq,
						segments=[] },
		    Socket1 = Socket#tcp_socket { tcp_state=TcpState,
						  ostream=Ostream1,
						  istream=Istream1 },
		    case transmit_data(Socket1,State) of
			{false,Socket2} ->
			    Socket2;
			{true,Socket2} -> %% we sent FIN in transmit data
			    TcpState1 =
				if TcpState =:= ?TCP_CLOSE_WAIT ->
					?TCP_LAST_ACK;
				   true -> TcpState
				end,
			    Socket2#tcp_socket { tcp_state=TcpState1 }
		    end;
	       true ->
		    %% Ack last known sequence number
		    io:format("istrem.seq=~w mismatch seq=~w\n",
			      [Istream#stream.seq, Seq]),
		    Socket1 = Socket#tcp_socket { ostream=Ostream1 },
		    send_data(Socket1,State)
	    end;
	_ ->
	    ?dbg("tcp_fsm(established): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_FIN_WAIT1, Socket=#tcp_socket{ istream=Istream, ostream=Ostream},
	Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=Ack,psh=_IsPsh,
	       rst=false,syn=false,fin=Fin,
	       window=_Wsize,options=_Options,data=Data } ->
	    Ostream1 = ack_output_data(Ack, AckNo, Socket, Ostream),
	    %% we must stay in FIN_WAIT1 until Ostream1.close /= true
	    %% that is until the FIN is acknowledged.
	    OutFinAck = Ostream1#stream.closed =:= true,
	    TcpState =
		if Fin,OutFinAck -> start_msl_timer(Socket), ?TCP_TIME_WAIT;
		   Fin -> ?TCP_CLOSING;
		   OutFinAck -> ?TCP_FIN_WAIT2;
		   true -> ?TCP_FIN_WAIT1
		end,
	    Socket1 = if Seq =:= Istream#stream.seq ->
			      Len = byte_size(Data),
			      tcp_report_data(Socket, Data),
			      tcp_report_closed(Socket,Fin),
			      ISeq = if Fin -> ?u32(Seq+Len+1);
					true -> ?u32(Seq+Len) end,
			      Istream1 = Istream#stream { seq=ISeq,
							  closed=Fin,
							  segments=[] },
			      Socket#tcp_socket { tcp_state=TcpState,
						  ostream=Ostream1,
						  istream=Istream1 };
			 true ->
			      %% lost packet - retransmit?
			      io:format("seq not matched ~w != ~w\n",
					[Seq, Istream#stream.seq]),
			      Socket#tcp_socket { tcp_state=TcpState,
						  ostream=Ostream1 }
		      end,
	    if TcpState =:= ?TCP_FIN_WAIT2 ->
		    Socket1; %% wait for FIN
	       true ->
		    transmit_ack(Socket1,State)
	    end;
	_ ->
	    ?dbg("tcp_fsm(fin_wait1): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_FIN_WAIT2,Socket=#tcp_socket{istream=Istream},
	Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=_AckNo,urg=false,ack=_Ack,psh=_IsPsh,
	       rst=false,syn=false,fin=true,
	       window=_Wsize,options=_Options,data = <<>> } ->
	    if Seq =:= Istream#stream.seq ->
		    ISeq = ?u32(Seq+1),
		    TcpState = ?TCP_TIME_WAIT,
		    start_msl_timer(Socket),
		    tcp_report_closed(Socket),
		    Istream1 = Istream#stream { seq=ISeq,closed=true,
						segments=[] },
		    Socket1 = Socket#tcp_socket { tcp_state=TcpState,
						  istream=Istream1 },
		    transmit_ack(Socket1,State);
	       true ->
		    %% lost packet - retransmit?
		    io:format("seq not matched ~w != ~w\n",
			      [Seq, Istream#stream.seq]),
		    false
	    end;
	_ ->
	    ?dbg("tcp_fsm(fin_wait2): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_CLOSING,Socket=#tcp_socket{ostream=Ostream},
	Tcp,_IP,_Eth,_State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=Ack,psh=false,
	       rst=false,syn=false,fin=_Fin,
	       window=_Wsize,options=_Options,data= <<>> } ->
	    Ostream1 = ack_output_data(Ack, AckNo, Socket, Ostream),
	    OutFinAck = Ostream1#stream.closed =:= true,
	    if OutFinAck ->
		    Socket#tcp_socket { tcp_state = ?TCP_TIME_WAIT,
					ostream = Ostream1 };
	       true ->
		    ?dbg("tcp_fsm(closing): (seq=~w) tcp dropped:\n~s\n",
			 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
		    Socket#tcp_socket { ostream = Ostream1 }
	    end
    end;
tcp_fsm(?TCP_TIME_WAIT,#tcp_socket{ostream=Ostream},
	Tcp,_IP,_Eth,_State) ->
    ?dbg("tcp_fsm(time_wait): (seq=~w) tcp dropped:\n~s\n",
	 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
    false;
tcp_fsm(?TCP_CLOSE_WAIT,Socket=#tcp_socket{ostream=Ostream},
	Tcp,_IP,_Eth,State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=_Fin,
	       window=_Wsize,options=_Options,data= <<>> } when
	      AckNo =:= Ostream#stream.seq ->
	    case transmit_data(Socket,State) of
		{false, Socket1} -> Socket1;
		{true, Socket1} -> %% now it is closed both ways
		    Socket1#tcp_socket { tcp_state=?TCP_LAST_ACK }
	    end;
	_ ->
	    ?dbg("tcp_fsm(close_wait): (seq=~w) tcp dropped:\n~s\n",
		 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_LAST_ACK,_Socket=#tcp_socket{ostream=Ostream},
	Tcp,_IP,_Eth,_State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=_Wsize,options=_Options,data= <<>> } when
	      AckNo =:= Ostream#stream.seq ->
	    undefined; %% done
	_ ->
	    ?dbg("tcp_fsm(last_ack): (seq=~w) tcp dropped:\n~s\n",
		 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(TcpState,Socket,Tcp,_IP,_Eth,_State) ->
    ?dbg("tcp_fsm(~s): (seq=~w) not handled:\n~s\n",
	 [TcpState,(Socket#tcp_socket.ostream)#stream.seq,
	  eth_packet:fmt_erl(Tcp)]),
    false.

%% start MSL (maximum segment lifetime) timer to kill socket in TIME_WAIT
start_msl_timer(Socket) ->
    erlang:start_timer(?MSL, self(), {close,Socket#tcp_socket.ref}).

%% report stuff to socket owner
tcp_report_closed(Socket,true) -> tcp_report_closed(Socket);
tcp_report_closed(_Socket,false) -> ok.

tcp_report_closed(Socket) ->
    Socket#tcp_socket.owner ! {tcp_closed, Socket#tcp_socket.ref}.

tcp_report_event(Socket,Event) ->
    Socket#tcp_socket.owner ! {tcp_event, Socket#tcp_socket.ref, Event}.

tcp_report_connected(Socket, IP, Port) ->
    Socket#tcp_socket.owner ! {tcp_connected, Socket#tcp_socket.ref, IP, Port}.

tcp_report_data(_Socket, <<>>) -> %% do not report empty segments
    ok;
tcp_report_data(Socket, Data) ->
    Socket#tcp_socket.owner ! {tcp, Socket#tcp_socket.ref, Data}.


%% respon or cache arp entries
handle_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIP},
		       target = {TargetMac, TargetIP}},_Eth,State) ->
    ?dbg("cache arp: ~s", [eth_packet:fmt_erl(_Arp)]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIP, SenderMac, State),
    State2 = insert_cache(TargetIP, TargetMac, State1),
    State2;
handle_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIP},
		      target = {TargetMac, TargetIP}},Eth,State) ->
    ?dbg("handle arp request: ~s", [eth_packet:fmt_erl(Arp)]),
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
ack_output_data(true,AckNo,Socket,Ostream) ->
    ack_segments(Ostream#stream.segments,AckNo,Socket,Ostream);
ack_output_data(false,_AckNo,_Socket,Ostream) ->
    Ostream.

ack_segments(Segments0=[#segment{seq=Seq,data=Data}|Segments],
	     AckNo,Socket,Stream) ->
    Seq1 = ?u32(Seq+segment_size(Data)),
    case ?seq_lte(Seq1, AckNo) of
	true ->
	    if is_reference(Data) ->
		    tcp_report_event(Socket,Data),
		    ack_segments(Segments,AckNo,Socket,Stream);
	       Data =:= ?FIN ->
		    Stream1 = Stream#stream { closed = true },
		    ack_segments(Segments,AckNo,Socket,Stream1);
	       true ->
		    ack_segments(Segments,AckNo,Socket,Stream)
	    end;
	false ->
	    Stream#stream { seq = AckNo, segments=Segments0 }
    end;
ack_segments([],AckNo,_Socket,Stream) ->
    Stream#stream { seq = AckNo, segments=[] }.

%% put data onto output segment queue
%%   item() = binary() | 'fin' | reference()
%%   Data = item() | [item()]
%%
-spec enqueue_data(Ref::reference, Data::[sdata()], State::#state{}) ->
			  {ok,#tcp_socket{}} | {error, Reason::atom()}.

enqueue_data(Ref, Data, State) ->
    case dict:find(Ref, State#state.sockref) of
	{ok,Key} ->
	    case dict:find(Key,State#state.sockets) of
		error ->
		    {error, einval};
		{ok,Socket} ->
		    enqueue_socket_data(Socket,Data)
	    end;
	_ ->
	    {error, einval}
    end.

-spec enqueue_socket_data(Socket::#tcp_socket{},
			  Data::[sdata()]) ->
				 {ok,#tcp_socket{}} | {error, Reason::atom()}.

enqueue_socket_data(Socket=#tcp_socket { tcp_state=TcpState,ostream=Ostream },
		    Data) when
      TcpState =:= ?TCP_ESTABLISHED;
      ((TcpState =:= ?TCP_SYN_RCVD) andalso Data =:= ?FIN) ->
    if Data =:= ?FIN, Ostream#stream.closed =/= false ->
	    {ok, Socket};  %% already pushed or sent
       true ->
	    case enqueue_stream(Ostream, Data) of
		{ok,Ostream1} ->
		    {ok, Socket#tcp_socket { ostream = Ostream1 }};
		Error ->
		    Error
	    end
    end;
enqueue_socket_data(_Socket,_Data) ->
    {error, einval}.

%% put data onto segments list

enqueue_stream(Stream=#stream{closed=Closed,mss=Mss,segments=Segments},Data) ->
    LastSeq = next_sequence_no(Stream),
    try make_segment_list_(LastSeq, Mss, Closed, Data, [], []) of
	{Closed1,MoreSegments} ->
	    Segments1 = Segments++MoreSegments,
	    {ok,Stream#stream { closed=Closed1,segments=Segments1}}
    catch
	error:_ ->  %% invalid data!
	    {error,einval}
    end.

%% store this in stream?
next_sequence_no(#stream { seq=Seq,segments=[] }) -> Seq;
next_sequence_no(#stream { segments=Segments }) ->
    #segment{seq=Seq,data=Data} = lists:last(Segments),
    ?u32(Seq+segment_size(Data)).

segment_size(Data) when is_binary(Data) -> byte_size(Data);
segment_size(Data) when is_reference(Data) -> 0;
segment_size(?FIN) -> 1.

%% Handle lists of segment data. This version does not try to merge
%% binaries because of testing purposes. User decide how segments are
%% handled (may require to be able to read mss).

make_segment_list_(Seq, Mss, Closed, Data, Cont, Acc) when
      byte_size(Data) =< Mss ->
    Seq1 = ?u32(Seq + segment_size(Data)),
    Segment = #segment { seq=Seq, status=send, data=Data},
    make_segment_list_cont_(Seq1, Mss, Closed, Cont, [Segment|Acc]);
make_segment_list_(Seq, Mss, Closed, Data, Cont, Acc) when is_binary(Data) ->
    {Data1,Rest} = erlang:split_binary(Data, Mss),
    Seq1 = ?u32(Seq + Mss),
    Segment = #segment { seq=Seq, status=send, data=Data1},
    make_segment_list_(Seq1, Mss, Closed, Rest, Cont, [Segment|Acc]);
make_segment_list_(Seq, Mss, Closed, [Data|Ds], Cont, Acc) ->
    make_segment_list_(Seq, Mss, Closed, Data, [Ds|Cont], Acc);
make_segment_list_(Seq, Mss, Closed, [], Cont, Acc) ->
    make_segment_list_cont_(Seq, Mss, Closed, Cont, Acc);
make_segment_list_(Seq, Mss, Closed, Mark, Cont, Acc) when is_reference(Mark) ->
    Segment = #segment { seq=Seq, status=waitack, data=Mark},
    make_segment_list_cont_(Seq, Mss, Closed, Cont, [Segment|Acc]);
make_segment_list_(Seq, Mss, _Closed, ?FIN, Cont, Acc) ->
    Segment = #segment { seq=Seq, status=send, data=?FIN},
    make_segment_list_cont_(Seq, Mss, pushed, Cont, [Segment|Acc]).

make_segment_list_cont_(Seq, Mss, Closed, [Data|Cont1], Acc) ->
    make_segment_list_(Seq, Mss, Closed, Data, Cont1, Acc);
make_segment_list_cont_(_Seq, _Mss, Closed, [], Acc) ->
    {Closed, lists:reverse(Acc)}.

transmit_arp(Dst,Src,Arp,State) ->
    Frame=#eth { src=Src, dst=Dst, type=arp, data=Arp},
    transmit_frame(Frame, State).

transmit_udp(Ref,DstIP,DstPort,Data,State) ->
    case dict:find(Ref, State#state.sockref) of
	error ->
	    {{error, einval}, State};
	{ok, Key} ->
	    case dict:find(Key, State#state.sockets) of
		{ok, Socket} when is_record(Socket,udp_socket)->
		    Udp = #udp { src_port = Socket#udp_socket.src_port,
				 dst_port = DstPort,
				 data = Data },
		    Ip  = #ipv4 { src=Socket#udp_socket.src,
				  dst=DstIP, proto=udp, data=Udp },
		    %% this lookup should be placed before udp_send!
		    DstMac = cache_lookup(DstIP, State),
		    Eth = #eth { src=Socket#udp_socket.mac, dst=DstMac,
				 type=ipv4,data=Ip },
		    transmit_frame(Eth, State),
		    {ok, State};
		_ ->
		    {{error, einval}, State}
	    end
    end.

%% not called when doing close_wait etc (may change state!)
send_data(Socket,State) ->
    case transmit_data(Socket,State) of
	{true,Socket1} ->
	    if Socket1#tcp_socket.tcp_state =:= ?TCP_CLOSE_WAIT ->
		    Socket1#tcp_socket { tcp_state = ?TCP_LAST_ACK };
	       true ->
		    Socket1#tcp_socket { tcp_state = ?TCP_FIN_WAIT1 }
	    end;
	{false,Socket1} ->
	    Socket1
    end.

transmit_data(Socket=#tcp_socket{ostream=Ostream},State) ->
    #stream { closed=SentFin,bytes=Bytes,window=Window,segments=Segments } =
	Ostream,
    {SentFin1,Socket1,Segments1} =
	transmit_stream(Socket,Segments,[],Bytes,Window,SentFin,State),
    Ostream1 = Ostream#stream { closed=SentFin,segments = Segments1 },
    {SentFin1,Socket1#tcp_socket { ostream = Ostream1 }}.

%%
%% here we may optimes and merge packets, mss will not change while
%% we are established, but we may join bits if we want.
%%
transmit_stream(Socket,
		Segments0=[S=#segment{seq=Seq,status=Stat,data=Data}|Segments],
		Acc,Bytes,Window,SentFin,State) ->
    if is_binary(Data) ->
	    Bytes1 = Bytes + byte_size(Data),
	    if Bytes1 =< Window ->
		    if Stat =:= send ->
			    Socket1=transmit_tcp(Socket,Seq,false,true,
						 false,false,Data,State),
			    Acc1 = [S#segment{status=waitack}|Acc],
			    transmit_stream(Socket1,Segments,Acc1,Bytes1,Window,
					    SentFin,State);
		       true ->
			    transmit_stream(Socket,Segments,[S|Acc],
					    Bytes1,Window,
					    SentFin,State)
		    end;
	       true ->
		    {SentFin,Socket,lists:reverse(Acc)++Segments0}
	    end;
       is_reference(Data) ->
	    transmit_stream(Socket,Segments,[S|Acc],Bytes,Window,SentFin,
			    State);
       Data =:= ?FIN ->
	    if Stat =:= send ->
		    Socket1 = transmit_fin(Socket,Seq,State),
		    Acc1 = [S#segment{status=waitack}|Acc],
		    %% handle event refs etc, must not send more data
		    transmit_stream(Socket1,Segments,Acc1,Bytes,Window,true,
				    State);
	       true ->
		    transmit_stream(Socket,Segments,[S|Acc],Bytes,Window,true,
				    State)
	    end
    end;
transmit_stream(Socket,[],Acc,_Bytes,_Window,SentFin,_State) ->
    {SentFin,Socket,lists:reverse(Acc)}.


transmit_syn(Socket,State) ->
    transmit_tcp(Socket,true,false,false,false,<<>>,State).

transmit_syn_ack(Socket,State) ->
    transmit_tcp(Socket,true,true,false,false,<<>>,State).

transmit_ack(Socket,State) ->
    transmit_tcp(Socket,false,true,false,false,<<>>,State).

transmit_tcp(Socket,Syn,Ack,Fin,Rst,Data,State) ->
    SeqNo = (Socket#tcp_socket.ostream)#stream.seq,
    transmit_tcp(Socket,SeqNo,Syn,Ack,Fin,Rst,Data,State).

transmit_fin(Socket,SeqNo,State) ->
    transmit_tcp(Socket,SeqNo,false,false,true,false,<<>>,State).

transmit_tcp(Socket=#tcp_socket{ostream=Ostream, istream=Istream},SeqNo,
	     Syn,Ack,Fin,Rst,Data,State) ->
    Window = Istream#stream.window - Istream#stream.bytes, %% input remain
    {Wsize,Wscale} = window_to_wss(Window),
    TcpOptions = [],
    TcpOptions1 = if Wscale > 0 -> [{window_size_shift,Wscale}|TcpOptions];
		     true -> TcpOptions
		  end,
    TcpOptions2 = if Syn -> [{mss,Ostream#stream.mss}|TcpOptions1];
		     true -> TcpOptions1
		  end,
    Tcp = #tcp { src_port = Socket#tcp_socket.src_port,
		 dst_port = Socket#tcp_socket.dst_port,
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
    log_tcp(Socket, Tcp, ">"),
    transmit_ip(Socket, tcp, Tcp, State).

transmit_ip(Socket, Proto, Data, State) ->
    Ip  = #ipv4 { src=Socket#tcp_socket.src,
		  dst=Socket#tcp_socket.dst,
		  proto=Proto, data=Data },
    DstMac = cache_lookup(Socket#tcp_socket.dst, State),
    Eth = #eth { src=Socket#tcp_socket.mac, dst=DstMac,type=ipv4,data=Ip },
    transmit_frame(Eth, State),
    Socket.

transmit_frame(Frame, State) ->
    Data=enet_eth:encode(Frame, []),
    eth_devices:send(State#state.eth, Data).

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

%% update rto according to rfc 6298
-define(K, 4).
-define(alpha, 0.125).  %% 1/8
-define(beta,  0.25).   %% 1/4

-spec rto(#tcp_socket{}) -> non_neg_integer().
%% return rto as number of milliseconds
rto(#tcp_socket{rto=RTO}) ->
    trunc(max(?MIN_RTO, min(?MAX_RTO, RTO))*1000).

%% the RTO timer trigger, we must "back off"
rto_backoff(Socket=#tcp_socket { rto = RTO }) when RTO < ?MAX_RTO ->
    Socket#tcp_socket { rto = RTO*2 };
rto_backoff(Socket) -> Socket.

%% update rto with roundtrip sample R (in seconds)
rto_update(Socket, R) ->
    case Socket of
	#tcp_socket { srtt = undefined } ->  %% first measurement
	    SRTT = R,
	    RTTVAR = R / 2,
	    Socket#tcp_socket { srtt = SRTT,
				rttvar = RTTVAR,
				rto = SRTT + max(?GRANULARITY_RTO, ?K*RTTVAR) };
	#tcp_socket { srtt = SRTT0, rttvar = RTTVAR0 } ->
	    RTTVAR = (1-?beta)*RTTVAR0 + ?beta*abs(SRTT0 - R),
	    SRTT = (1-?alpha)*SRTT0 + ?alpha*R,
	    Socket#tcp_socket {  srtt = SRTT,
				 rttvar = RTTVAR,
				 rto = SRTT + max(?GRANULARITY_RTO, ?K*RTTVAR) }
    end.

%% generate a timestamp for the packet (using ms)
timestamp() ->
    now_to_ms(os:timestamp()).

now_to_ms({_,S,U}) ->
    (S*1000 + (U div 1000)) band 16#ffffffff.

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


%% debug transmit:
log_tcp(Socket, Tcp, ">") when is_record(Socket,tcp_socket) ->
    log_tcp(Socket#tcp_socket.tcp_state,
	    Socket#tcp_socket.src, Tcp#tcp.src_port,
	    Socket#tcp_socket.dst, Tcp#tcp.dst_port, Tcp, ">");
log_tcp(Socket, Tcp, "<") when is_record(Socket,tcp_socket) ->
    log_tcp(Socket#tcp_socket.tcp_state,
	    Socket#tcp_socket.src, Tcp#tcp.dst_port,
	    Socket#tcp_socket.dst, Tcp#tcp.src_port, Tcp, "<");
log_tcp(Socket, Tcp, ">") when is_record(Socket,lst_socket) ->
    log_tcp(?TCP_LISTEN,
	    Socket#lst_socket.src, Tcp#tcp.src_port,
	    Socket#lst_socket.dst, Tcp#tcp.dst_port, Tcp, ">");
log_tcp(Socket, Tcp, "<") when is_record(Socket,lst_socket) ->
    log_tcp(?TCP_LISTEN,
	    Socket#lst_socket.src, Tcp#tcp.dst_port,
	    Socket#lst_socket.dst, Tcp#tcp.src_port, Tcp, "<").


log_tcp(TcpState,Src,SrcPort,Dst,DstPort,Tcp,Dir) ->
    io:format("tcp[~s]: ~s:~w ~s ~s:~w: ~w ~s ack=~w : ~s\n",
	      [TcpState,
	       format_ip_addr(Src), SrcPort,
	       Dir,
	       format_ip_addr(Dst), DstPort,
	       Tcp#tcp.seq_no,
	       format_tcp_flags(Tcp),
	       Tcp#tcp.ack_no,
	       format_tcp_data(Tcp#tcp.data, 20)]).

format_ip_addr({A,B,C,D}) ->
    io_lib:format("~w.~w.~w.~w", [A,B,C,D]);
format_ip_addr(undefined) ->
    "".

format_tcp_data(Binary,Max) when is_binary(Binary) ->
    case list_to_binary(io_lib:format("~p", [Binary])) of
	<<Bin:Max/binary, _/binary>> -> Bin;
	Bin -> Bin
    end.

format_tcp_flags(Tcp) ->
    case lists:append([if Tcp#tcp.urg -> "U"; true -> "" end,
		       if Tcp#tcp.ack -> "."; true -> "" end,
		       if Tcp#tcp.psh -> "P"; true -> "" end,
		       if Tcp#tcp.rst -> "R"; true -> "" end,
		       if Tcp#tcp.syn -> "S"; true -> "" end,
		       if Tcp#tcp.fin -> "F"; true -> "" end]) of
	"" -> "-";
	Fs -> Fs
    end.
