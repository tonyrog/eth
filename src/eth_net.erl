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
-export([set_gw/2]).

%% ICMP
-export([ping/4]).

%% UDP
-export([udp_open/4, udp_close/2, udp_send/5]).
%% TCP
-export([tcp_listen/4, tcp_accept/2, tcp_connect/6, tcp_send/3,
	 tcp_shutdown/2, tcp_close/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(debug(F,A), io:format("~s:~w: "++(F)++"\r\n",[?FILE,?LINE|(A)])).
%% -define(debug(F,A), ok).

%% -define(debug_arp(F,A), io:format("~s:~w: "++(F)++"\r\n",[?FILE,?LINE|(A)])).
-define(debug_arp(F,A), ok).

-compile(export_all).

-include_lib("enet/include/enet_types.hrl").

-define(BROADCAST, {16#ff,16#ff,16#ff,16#ff,16#ff,16#ff}).
-define(ZERO,      {16#00,16#00,16#00,16#00,16#00,16#00}).

-define(TCP_HEADER_MIN_LEN,   20).
-define(IPV4_HEADER_MIN_LEN,  20).
-define(IPV6_HEADER_MIN_LEN,  40).
-define(TCP_IPV4_HEADER_MIN_LEN, (?IPV4_HEADER_MIN_LEN+?TCP_HEADER_MIN_LEN)).
-define(TCP_IPV6_HEADER_MIN_LEN, (?IPV6_HEADER_MIN_LEN+?TCP_HEADER_MIN_LEN)).

-define(IPV4_MIN_SIZE, 576).
-define(IPV6_MIN_SIZE, 576).
-define(TCP_DEFAULT_IPV4_MSS, (?IPV4_MIN_SIZE - ?TCP_IPV4_HEADER_MIN_LEN)).
-define(TCP_DEFAULT_IPV6_MSS, (?IPV6_MIN_SIZE - ?TCP_IPV6_HEADER_MIN_LEN)).


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

-define(is_block(X),
	(is_binary((X)) orelse is_reference((X)) orelse ((X) =:= ?FIN))).

-type sdata() :: ?FIN | reference() | binary().

-record(block,
	{
	  seq :: uint32(),
	  status = none :: none | send | waitack | ack,
	  data :: sdata()
	}).

-record(stream,
	{
	  window=65535 :: non_neg_integer(), %% current announced window size
	  wss = 0 :: 0..14,      %% window scale shift, if supported
	  mss :: uint16(),       %% maximum segment size used
	  bytes = 0 :: uint32(), %% number bytes sent / received in window
	  seq = 0 :: uint32(),   %% current seqeuence number
	  closed = false :: pushed | boolean(),
	  blocks = []  :: [#block{}]
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
	  options  :: [{atom(),term()}],  %% listen options
	  %% add syn queue .
	  aqueue = [] :: [{reference(),pid()}]   %% accept queue
	}).

%% http://en.wikipedia.org/wiki/Transmission_Control_Protocol
%%
%% flags for tcp option support (roughly the option number as a bit)
-define(TCP_OPT_NONE,         16#0000).

%% RFC 793 - TRANSMISSION CONTROL PROTOCOL
%% RFC 879 - TCP Options and Maximum Segment Size (MSS)
-define(TCP_OPT_MSS,          16#0004).  %% (1 bsl 2), Kind = 2
%% SACK - RFC 2018 - Kind = 4 (+ 5)
-define(TCP_OPT_SACK,         16#0010).  %% (1 bsl 4), Kind = 4
%% RFC 1323 - TCP Extensions for High Performance
-define(TCP_OPT_WSS,          16#0008).  %% (1 bsl 3), Kind = 3
-define(TCP_OPT_TIMESTAMP,    16#0100).  %% (1 bsl 8), Kind = 8

-type tcp_syn_options() :: uint16().

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
	  tcp_opts  :: tcp_syn_options(), %% flags
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

-define(DEFAULT_TCP_OPTIONS,
	?TCP_OPT_MSS bor ?TCP_OPT_TIMESTAMP).

-record(state,
	{
	  name :: string(),  %% name of interface (like "tap0", "en1", "eth0")
	  eth,       %% interface handler
	  mtu,       %% mtu size of interface / minimum mtu usable
	  mac :: ethernet_address(),          %% the mac address on interface
	  gw  :: ip_address(),                %% the gateway ip address
	  gw_mac = ?ZERO :: ethernet_address(), %% the gateway mac address
	  %% options offered & allowed in syn packets
	  tcp_opts = ?DEFAULT_TCP_OPTIONS :: tcp_syn_options(),
	  wssdflt = 0,   %% window scaling shift (0..14)
	  mssdflt   = ?TCP_DEFAULT_IPV4_MSS,
	  v6mssdflt = ?TCP_DEFAULT_IPV6_MSS,
	  ipmac :: dict:dict(ip_address(),ethernet_address()),
	  macs :: sets:set(ethernet_address()),
	  cache :: dict:dict(ip_address(),ethernet_address()),
	  sockets :: dict:dict(socket_key(), socket()),
	  sockref :: dict:dict(reference(), socket_key())
	}).

-define(u32(X), ((X)  band 16#ffffffff)).
-define(seq_next(X), ?u32((X)+1)).
-define(seq_lte(X,Y), (?u32((Y)-(X)) < 16#40000000)).
-define(seq_lt(X,Y), (?u32((Y)-(X)-1) < 16#40000000)).
-define(seq_gt(X,Y), (not ?seq_lte((X),(Y)))).
-define(seq_gte(X,Y), (not ?seq_lt((X),(Y)))).

%%%===================================================================
%%% API
%%%===================================================================

start(Interface) ->
    gen_server:start(?MODULE, [Interface], []).

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Net) ->
    gen_server:call(Net, stop).

dump(Net) ->
    gen_server:call(Net, dump).

%% icmp ping
ping(Net, ID, SrcIP, DstIP) ->
    gen_server:call(Net, {ping, ID, SrcIP, DstIP}).

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
%% current tcp options include:
%%  {mss,Mss}   -- announced mss value, limited by interface however.
%%  {send_mss,Mss}  -- forced send mss, used mainliy for testing,
%%                     never bigger than remotliy announced value
%%  {wss,Wss}       -- window scaling factor shift factor override
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
tcp_send(Net, Ref, Data) when ?is_block(Data);
			      ?is_block(hd(Data)) ->
    gen_server:call(Net, {tcp_send, Ref, Data}).

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

set_gw(Net, Gw) when tuple_size(Gw) =:= 4; tuple_size(Gw) =:= 8 ->
    gen_server:call(Net, {set_gw,Gw}).

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
handle_call({ping, ID, SrcIP, DstIP}, _From, State) ->
    case dict:find(SrcIP, State#state.ipmac) of
	error ->
	    {reply, {error, einval}, State};
	{ok,SrcMac} ->
	    DstMac = route_lookup(DstIP, State),
	    Data = <<0:56/unit:8>>,
	    Icmp = #icmp { type=echo_request, id=ID, seq=0, data=Data},
	    IP  = #ipv4 { src=SrcIP, dst=DstIP, proto=icmp, data=Icmp },
	    Eth = #eth { src=SrcMac, dst=DstMac, type=ipv4, data=IP},
	    transmit_frame(Eth, State),
	    {reply, ok, State}
    end;
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
	    ?debug("try to udp_close on ~w", [_SockKey]),
	    {reply, {error, einval},  State}
    end;
handle_call({udp_send,Ref,DstIP,DstPort,Data}, _From, State) ->
    {Result,State1} = transmit_udp(Ref,DstIP,DstPort,Data, State),
    {reply,Result,State1};

handle_call({tcp_listen,Owner,SrcIP,SrcPort,Options}, _From, State) ->
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
					   owner = Owner,
					   options = Options
					 },
		    State1 = add_socket(Socket, State),
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
	    LSocket = dict:fetch(Key, State#state.sockets),
	    AQueue = LSocket#lst_socket.aqueue ++ [{Ref,Acceptor}],
	    LSocket1 = LSocket#lst_socket { aqueue = AQueue },
	    Sockets = dict:store(Key, LSocket1, State#state.sockets),
	    SockRef = dict:store(Ref, AKey, State#state.sockref),
	    State1 = State#state { sockets=Sockets, sockref=SockRef },
	    {reply, {ok,Ref}, State1};
	{ok,_OtherKey} ->
	    {reply, {error, einval},  State}
    end;

handle_call({tcp_connect,Owner,SrcIP,SrcPort,DstIP,DstPort,Options},
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
		    OMss = proplists:get_value(mss, Options,
					      calc_mss(SrcIP, State)),
		    OWss = proplists:get_value(wss,Options,State#state.wssdflt),
		    IMss = case proplists:get_value(send_mss,Options) of
			       undefined -> default_mss(SrcIP,State);
			       SendMss -> {force,SendMss}
			   end,
		    Ostream = #stream { mss=OMss, wss=OWss, seq=random_32() },
		    Istream = #stream { mss=IMss },

		    Socket = #tcp_socket { ref=Ref, key=Key,
					   tcp_state = ?TCP_SYN_SENT,
					   mac = SrcMac,
					   src = SrcIP,src_port = SrcPort,
					   dst = DstIP,dst_port = DstPort,
					   tcp_opts = State#state.tcp_opts,
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
	    ?debug("try to tcp_close on ~w", [_SockKey]),
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
	    ?debug("try to tcp_close on ~w", [_SockKey]),
	    {reply, {error, einval},  State}
    end;

handle_call({add_ip,IP,Mac}, _From, State) ->
    IPMac = dict:store(IP, Mac, State#state.ipmac),
    Macs = sets:add_element(Mac, State#state.macs),
    %% inform network about this fact, gratuitous ARP
    send_arp(reply,Mac,?BROADCAST,IP,IP,State),
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
	    send_arp(request,State#state.mac,?ZERO,LocalIP,IP,State),
	    {reply, ok, State};
	Error ->
	    {reply, Error, State}
    end;
handle_call({set_gw,Gw}, _From, State) ->
    case dict:find(Gw, State#state.cache) of
	error ->
	    case dict:find(Gw, State#state.ipmac) of
		error ->
		    {reply, {error,enoent}, State#state{gw=Gw,gw_mac=?ZERO}};
		{ok,Mac} ->
		    {reply, {ok,Mac}, State#state{gw=Gw,gw_mac=Mac}}
	    end;
	{ok,Mac} ->
	    {reply, {ok,Mac}, State#state{gw=Gw,gw_mac=Mac}}
    end;
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(dump, _From, State) ->
    dump_sockets(State),
    {reply, ok, State};
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
	    ?debug("unable to queue segments: ~p", [Error]),
	    {noreply, State}
    end;

handle_info({timeout,_TRef,{retransmit,Ref}}, State) ->
    case dict:find(Ref, State#state.sockref) of
	error -> {noreply, State};
	{ok,Key} ->
	    case dict:find(Key,State#state.sockets) of
		error -> {noreply, State};
		{ok,Socket} ->
		    ?debug("retransmit socket ~p", [Socket]),
		    Socket1 = rto_backoff(Socket),
		    Socket2 = send_data(Socket1,State),
		    State1 = store_socket(Socket2,State),
		    {noreply, State1}
	    end
    end;

handle_info({timeout,_TRef,{close,Ref}}, State) ->
    case dict:find(Ref, State#state.sockref) of
	error -> {noreply, State};
	{ok,Key} ->
	    case dict:find(Key,State#state.sockets) of
		error -> {noreply, State};
		{ok,Socket=#tcp_socket{tcp_state=?TCP_TIME_WAIT}} ->
		    ?debug("time_wait done killing socket ~p", [Socket]),
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
	    ?debug("unable to queue fin segments: ~p", [Error]),
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
    ?debug("got info: ~p", [_Info]),
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
	    ?debug("closing socket ~p", [Socket]),
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
	    ?debug("closing accept on socket ~p", [Socket]),
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
		    ?debug("killing socket ~p", [Socket]),
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
    ?debug("handle_frame: not handled: ~s", [eth_packet:fmt_erl(_Frame)]),
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
    ?debug("handle_ipv4: not handled: ~s", [eth_packet:fmt_erl(_IP)]),
    State.

handle_icmp(#icmp { type=echo_request,id=ID,seq=Seq,data=Data},IP,Eth,State) ->
    Icmp1 = #icmp { type=echo_reply, id=ID, seq=Seq, data=Data},
    IP1  = #ipv4 { src=IP#ipv4.dst, dst=IP#ipv4.src, proto=icmp, data=Icmp1 },
    Eth1 = #eth { src=Eth#eth.dst, dst=Eth#eth.src, type=ipv4, data=IP1},
    transmit_frame(Eth1, State),
    State;
handle_icmp(_Icmp,_IP,_Eth,State) ->
    ?debug("handle_icmp: not handled: ~s", [eth_packet:fmt_erl(_Icmp)]),
    State.

handle_udp(_Udp=#udp { src_port = SrcPort, dst_port = DstPort, data=Data },
	   IP, _Eth, State) ->
    case dict:find({udp,IP#ipv4.dst,DstPort},State#state.sockets) of
	error ->
	    ?debug("handle_udp: not handled: ~s", [eth_packet:fmt_erl(_Udp)]),
	    %% icmp error?
	    State;
	{ok,#udp_socket{ref=Ref,owner=Pid}} ->
	    Pid  ! {udp,Ref,IP#ipv4.src,SrcPort,Data},
	    State
    end;
handle_udp(_Udp,_IP,_Eth,State) ->
    ?debug("handle_udp: not handled: ~s", [eth_packet:fmt_erl(_Udp)]),
    State.


handle_tcp(Tcp=#tcp { src_port = SrcPort, dst_port = DstPort },
	   IP, Eth, State) ->
    Key = {tcp,IP#ipv4.dst,DstPort,IP#ipv4.src,SrcPort},
    case dict:find(Key, State#state.sockets) of
	error ->
	    ?debug("session not found: ~w\n", [Key]),
	    LKey = {tcp,IP#ipv4.dst,DstPort},
	    
	    case dict:find(LKey,State#state.sockets) of
		error ->
		    ?debug("handle_tcp: not handled: ip=~w:~w, ~s",
			   [IP#ipv4.dst,DstPort,eth_packet:fmt_erl(Tcp)]),
		    %% dump_sockets(State),
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
	    Socket1 = handle_timestamp(Socket, Tcp),
	    case tcp_fsm(Socket1#tcp_socket.tcp_state,Socket1,Tcp,State) of
		false ->
		    State;
		undefined ->
		    ?debug("killing socket ~p", [Socket]),
		    erase_socket(Socket1, State);
		Socket2 ->
		    store_socket(Socket2, State)
	    end
    end;
handle_tcp(_Tcp,_IP,_Eth,State) ->
    ?debug("handle_tcp: not handled: ~s", [eth_packet:fmt_erl(_Tcp)]),
    State.

handle_accept(LSocket,Tcp,IP,Eth,State) ->
    case Tcp of
	#tcp { urg=false,ack=false,psh=false,rst=false,syn=true,fin=false,
	       window=Wsize,options=TcpOptions,data= <<>> } ->
	    case LSocket#lst_socket.aqueue of
		[{Ref,Pid}|AQueue] ->
		    Key = {tcp,IP#ipv4.dst,Tcp#tcp.dst_port,
			   IP#ipv4.src,Tcp#tcp.src_port},
		    Options = LSocket#lst_socket.options,
		    OMss = proplists:get_value(mss,Options,
					      calc_mss(IP#ipv4.dst, State)),
		    OWss = proplists:get_value(wss,Options,State#state.wssdflt),
		    IMss = case proplists:get_value(send_mss,Options) of
			       undefined -> default_mss(IP#ipv4.dst,State);
			       SendMss -> {force,SendMss}
			   end,
		    Ostream = #stream { window=Wsize,mss=OMss,wss=OWss,
					seq=random_32() },
		    Istream = #stream { mss=IMss,seq=?seq_next(Tcp#tcp.seq_no)},
		    Socket = #tcp_socket { ref=Ref, key=Key, mac=Eth#eth.dst,
					   src = IP#ipv4.dst,
					   src_port=Tcp#tcp.dst_port,
					   dst = IP#ipv4.src,
					   dst_port = Tcp#tcp.src_port,
					   tcp_state = ?TCP_SYN_RCVD,
					   tcp_opts = State#state.tcp_opts,
					   tsecr = 0,
					   owner = Pid,
					   istream = Istream,
					   ostream = Ostream
					 },
		    Socket1 = accept_syn_options(TcpOptions,Socket,State),
		    ?debug("socket syn_rcvd = ~w", [Socket1]),
		    Socket2 = transmit_syn_ack(Socket1,State),
		    LSocket1 = LSocket#lst_socket { aqueue = AQueue },
		    {LSocket1,Socket2};
		[] ->
		    ?debug("handle_tcp_input(listen): no acceptor:\n~s\n",
			 [eth_packet:fmt_erl(Tcp)]),
		    false
	    end;
	_ ->
	    ?debug("handle_tcp_input(listen): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end.

%%
%% tcp_fsm - tcp state machine
%%
tcp_fsm(?TCP_SYN_RCVD,Socket=#tcp_socket{istream=Istream,ostream=Ostream},
	Tcp,_State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=Wsize,options=_TcpOptions,data= <<>> } when
	      AckNo =:= ?seq_next(Ostream#stream.seq) ->
	    tcp_report_connected(Socket),
	    Window = Wsize bsl Istream#stream.wss,
	    Ostream1 = Ostream#stream {	seq=AckNo, window=Window },
	    Istream1 = Istream#stream { seq=Seq },
	    Socket#tcp_socket { tcp_state = ?TCP_ESTABLISHED,
				istream = Istream1,
				ostream = Ostream1 };
	_ ->
	    ?debug("tcp_fsm(syn_rcvd): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_SYN_SENT,Socket=#tcp_socket{ istream=Istream, ostream=Ostream },
	Tcp,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=true,fin=false,
	       window=Wsize,options=TcpOptions,data= <<>> } when
	      AckNo =:= ?seq_next(Ostream#stream.seq) ->
	    tcp_report_connected(Socket),
	    Ostream1 = Ostream#stream { seq=AckNo, window=Wsize },
	    Istream1 = Istream#stream { bytes=0,seq=?seq_next(Seq),blocks=[]},
	    Socket1 = Socket#tcp_socket { tcp_state = ?TCP_ESTABLISHED,
					  ostream=Ostream1,
					  istream=Istream1 },
	    Socket2 = accept_syn_options(TcpOptions,Socket1,State),
	    transmit_ack(Socket2,State);
	_ ->
	    ?debug("tcp_fsm(syn_sent): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_ESTABLISHED, Socket=#tcp_socket{ istream=Istream,ostream=Ostream },
	Tcp,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=Ack,psh=Psh,
	       rst=false,syn=false,fin=Fin,
	       window=Wsize,options=TcpOptions,data=Data } ->
	    Istream0 = insert_segment(Psh,Seq,Data,Istream),
	    {AckBytes,Ostream0} = ack_data(Ack,AckNo,TcpOptions,Socket,Ostream),
	    Istream1 = deliver_data(Istream0,Socket),
	    TcpState = if Fin -> tcp_report_closed(Socket),
				 ?TCP_CLOSE_WAIT;
			  true -> ?TCP_ESTABLISHED
		       end,
	    Window = Wsize bsl Istream#stream.wss,
	    ISeq = if Fin -> ?u32(Istream1#stream.seq+1);
		      true -> Istream1#stream.seq
		   end,
	    %% fixme: insert Fin packet on the stream block!
	    Istream2 = Istream#stream { seq=ISeq,closed=Fin },
	    Ostream1 = Ostream0#stream { window=Window },
	    Socket1 = Socket#tcp_socket { tcp_state=TcpState,
					  ostream=Ostream1,
					  istream=Istream2 },
	    case transmit_data(Socket1,State) of
		{false,Sent,Socket2} ->
		    start_rt_timer(AckBytes,Sent,Socket2);
		{true,Sent,Socket2} -> %% we sent FIN in transmit data
		    TcpState1 =
			if TcpState =:= ?TCP_CLOSE_WAIT ->
				?TCP_LAST_ACK;
			   true -> TcpState
			end,
		    Socket3 = Socket2#tcp_socket { tcp_state=TcpState1 },
		    start_rt_timer(AckBytes,Sent,Socket3)
	    end;
	_ ->
	    ?debug("tcp_fsm(established): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_FIN_WAIT1, Socket=#tcp_socket{ istream=Istream, ostream=Ostream},
	Tcp,State) ->
    case Tcp of
	#tcp { seq_no=Seq,ack_no=AckNo,urg=false,ack=Ack,psh=Psh,
	       rst=false,syn=false,fin=Fin,
	       window=_Wsize,options=TcpOptions,data=Data } ->
	    Istream0 = insert_segment(Psh, Seq, Data, Istream),
	    {AckBytes,Ostream1} = ack_data(Ack,AckNo,TcpOptions,Socket,Ostream),
	    OutFinAck = Ostream1#stream.closed =:= true,
	    TcpState =
		if Fin,OutFinAck -> start_msl_timer(Socket), ?TCP_TIME_WAIT;
		   Fin -> ?TCP_CLOSING;
		   OutFinAck -> ?TCP_FIN_WAIT2;
		   true -> ?TCP_FIN_WAIT1
		end,
	    Istream1 = deliver_data(Istream0, Socket),
	    tcp_report_closed(Socket,Fin),
	    %% fixme: insert Fin packet on the stream block!
	    ISeq = if Fin -> ?u32(Istream1#stream.seq+1);
		      true -> Istream1#stream.seq
		   end,
	    Istream2 = Istream1#stream { seq=ISeq,closed=Fin },
	    Socket1 = Socket#tcp_socket { tcp_state=TcpState,
					  ostream=Ostream1,
					  istream=Istream2 },
	    if TcpState =:= ?TCP_FIN_WAIT2 ->
		    start_rt_timer(AckBytes,0,Socket1);
	       true ->
		    Socket2 = transmit_ack(Socket1,State),
		    start_rt_timer(AckBytes,0,Socket2)
	    end;
	_ ->
	    ?debug("tcp_fsm(fin_wait1): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_FIN_WAIT2,Socket=#tcp_socket{istream=Istream},
	Tcp,State) ->
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
						blocks=[] },
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
	    ?debug("tcp_fsm(fin_wait2): tcp dropped:\n~s\n",
		 [eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_CLOSING,Socket=#tcp_socket{ostream=Ostream},
	Tcp,_State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=Ack,psh=false,
	       rst=false,syn=false,fin=_Fin,
	       window=_Wsize,options=TcpOptions,data= <<>> } ->
	    {AckBytes,Ostream1} = ack_data(Ack,AckNo,TcpOptions,Socket,Ostream),
	    OutFinAck = Ostream1#stream.closed =:= true,
	    if OutFinAck ->
		    Socket1 = Socket#tcp_socket { tcp_state = ?TCP_TIME_WAIT,
						  ostream = Ostream1 },
		    start_rt_timer(AckBytes,0,Socket1);
	       true ->
		    ?debug("tcp_fsm(closing): (seq=~w) tcp dropped:\n~s\n",
			 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
		    Socket1 = Socket#tcp_socket { ostream = Ostream1 },
		    start_rt_timer(AckBytes,0,Socket1)
	    end
    end;
tcp_fsm(?TCP_TIME_WAIT,#tcp_socket{ostream=Ostream},
	Tcp,_State) ->
    ?debug("tcp_fsm(time_wait): (seq=~w) tcp dropped:\n~s\n",
	 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
    false;
tcp_fsm(?TCP_CLOSE_WAIT,Socket=#tcp_socket{ostream=Ostream},
	Tcp,State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=_Fin,
	       window=_Wsize,options=_Options,data= <<>> } when
	      AckNo =:= Ostream#stream.seq ->
	    case transmit_data(Socket,State) of
		{false, Sent, Socket1} ->
		    start_rt_timer(0,Sent,Socket1);
		{true, Sent, Socket1} -> %% now it is closed both ways
		    Socket2 = Socket1#tcp_socket { tcp_state=?TCP_LAST_ACK },
		    start_rt_timer(0,Sent,Socket2)
	    end;
	_ ->
	    ?debug("tcp_fsm(close_wait): (seq=~w) tcp dropped:\n~s\n",
		 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(?TCP_LAST_ACK,_Socket=#tcp_socket{ostream=Ostream},
	Tcp,_State) ->
    case Tcp of
	#tcp { seq_no=_Seq,ack_no=AckNo,urg=false,ack=true,psh=false,
	       rst=false,syn=false,fin=false,
	       window=_Wsize,options=_Options,data= <<>> } when
	      AckNo =:= Ostream#stream.seq ->
	    undefined; %% done
	_ ->
	    ?debug("tcp_fsm(last_ack): (seq=~w) tcp dropped:\n~s\n",
		 [Ostream#stream.seq, eth_packet:fmt_erl(Tcp)]),
	    false
    end;
tcp_fsm(TcpState,Socket,Tcp,_State) ->
    ?debug("tcp_fsm(~s): (seq=~w) not handled:\n~s\n",
	 [TcpState,(Socket#tcp_socket.ostream)#stream.seq,
	  eth_packet:fmt_erl(Tcp)]),
    false.

%% start MSL (maximum segment lifetime) timer to kill socket in TIME_WAIT
start_msl_timer(Socket) ->
    erlang:start_timer(?MSL, self(), {close,Socket#tcp_socket.ref}).

start_rt_timer(AckBytes, Sent, Socket) ->
    if AckBytes > 0;
       Sent > 0, Socket#tcp_socket.rt =:= undefined ->
	    stop_timer_(Socket#tcp_socket.rt),
	    Rt = erlang:start_timer(rto(Socket), self(), 
				    {retransmit, Socket#tcp_socket.ref}),
	    Socket#tcp_socket { rt = Rt };
       AckBytes < 0 -> %% all segments acked, no new sent
	    stop_rt_timer(Socket);
       true ->
	    Socket
    end.

stop_rt_timer(Socket = #tcp_socket { rt = Timer }) ->
    Socket#tcp_socket { rt = stop_timer_(Timer) }.

stop_timer_(undefined) ->
    undefined;
stop_timer_(Timer) when is_reference(Timer) ->
    erlang:cancel_timer(Timer, [{async, true}]),
    undefined.

%% report stuff to socket owner
tcp_report_closed(Socket,true) -> tcp_report_closed(Socket);
tcp_report_closed(_Socket,false) -> ok.

tcp_report_closed(Socket) ->
    Socket#tcp_socket.owner ! {tcp_closed, Socket#tcp_socket.ref}.

tcp_report_event(Socket,Event) ->
    Socket#tcp_socket.owner ! {tcp_event, Socket#tcp_socket.ref, Event}.

tcp_report_connected(Socket=#tcp_socket{dst=IP, dst_port=Port}) ->
    Socket#tcp_socket.owner ! {tcp_connected, Socket#tcp_socket.ref, IP, Port}.

tcp_report_data(_Socket, <<>>) -> %% do not report empty segments
    ok;
tcp_report_data(Socket, Data) ->
    Socket#tcp_socket.owner ! {tcp, Socket#tcp_socket.ref, Data}.


%% respon or cache arp entries
handle_arp(_Arp=#arp { op = reply,
		       sender = {SenderMac, SenderIP},
		       target = {TargetMac, TargetIP}},_Eth,State) ->
    ?debug("cache arp: ~s", [eth_packet:fmt_erl(_Arp)]),
    %% cache only on reply and gratuitous arp?
    State1 = insert_cache(SenderIP, SenderMac, State),
    State2 = insert_cache(TargetIP, TargetMac, State1),
    State2;
handle_arp(Arp=#arp { op = request,
		      sender = {SenderMac, SenderIP},
		      target = {TargetMac, TargetIP}},Eth,State) ->
    ?debug_arp("handle arp request: ~s", [eth_packet:fmt_erl(Arp)]),
    case (TargetMac =:= ?ZERO) orelse
	sets:is_element(TargetMac,State#state.macs) of
	true ->
	    case dict:find(TargetIP, State#state.ipmac) of
		error ->
		    State;
		{ok,TargetMac1} ->
		    ?debug_arp("handle arp reply with mac=~w", [TargetMac1]),
		    transmit_arp(Eth#eth.src,Eth#eth.dst,
				 Arp#arp { op=reply,
					   sender={TargetMac1,TargetIP},
					   target={SenderMac,SenderIP}}, State),
		    State
	    end;
	false ->
	    State
    end;
handle_arp(_Arp,_Eth,State) ->
    ?debug_arp("handle_arp: not handled: ~p", [_Arp]),
    State.

%% deliver ready data to the socket owner
deliver_data(Stream, Socket) ->
    deliver_blocks(Stream#stream.blocks, Socket, Stream).

deliver_blocks([#block { seq=Seq,data=Data}|Bs],Socket,Stream)
  when Seq =:= Stream#stream.seq ->
    tcp_report_data(Socket, Data),
    Len = byte_size(Data),
    deliver_blocks(Bs, Socket, Stream#stream { seq=?u32(Seq+Len) });
deliver_blocks(Bs, _Socket, Stream) ->
    Stream#stream { blocks = Bs }.

%% insert segment data in input buffer
insert_segment(_Psh, _Seq, <<>>, Stream) ->
    Stream;
insert_segment(Psh, Seq, Data, Stream) ->
    case Stream#stream.blocks of
	[#block{seq=Seq}|_] ->
	    %% fixme: check that the block is the same as last one,
	    %% maybe mtu is increased ?
	    Stream;
	[] ->
	    %% fixme: check that block is within window
	    Bs1 = [#block{seq=Seq,status=Psh,data=Data}],
	    Stream#stream { blocks=Bs1 };
	Bs ->
	    %% fixme: only check that segment is in the window!
	    case ?seq_gt(Seq, Stream#stream.seq) of
		true ->
		    Bs1 = insert_segment_block(Psh,Seq,Data,Bs),
		    Stream#stream { blocks=Bs1 };
		false ->
		    Stream
	    end
    end.

%% a lot of fixme: check that retransmitted blocks are the same
%% check overlaps etc.
insert_segment_block(Psh,Seq,Data,Bs0=[B|Bs]) ->
    case ?seq_gt(Seq, B#block.seq) of
	true ->
	    [B|insert_segment_block(Psh,Seq,Data,Bs)];
	false ->
	    if Seq =:= B#block.seq -> %% assume retransmit, fixme check!
		    Bs0;
	       true ->
		    [#block{seq=Seq,status=Psh,data=Data}|Bs0]
	    end
    end;
insert_segment_block(Psh,Seq,Data,[]) ->
    [#block{seq=Seq,status=Psh,data=Data}].


%% Handle ack of output data (fixme handle sack)
ack_data(true,AckNo,_TcpOptions,Socket,Ostream) ->
    ack_blocks(Ostream#stream.blocks,AckNo,0,Socket,Ostream);
ack_data(false,_AckNo,_TcpOptions,_Socket,Ostream) ->
    {0, Ostream}.

ack_blocks(Bs0=[#block{seq=Seq,data=Data}|Bs],AckNo,AckBytes,Socket,Stream) ->
    SegSize = segment_size(Data),
    Seq1 = ?u32(Seq+SegSize),
    case ?seq_lte(Seq1, AckNo) of
	true ->
	    if is_reference(Data) ->
		    tcp_report_event(Socket,Data),
		    ack_blocks(Bs,AckNo,AckBytes,Socket,Stream);
	       Data =:= ?FIN ->
		    Stream1 = Stream#stream { closed = true },
		    ack_blocks(Bs,AckNo,AckBytes,Socket,Stream1);
	       true ->
		    ack_blocks(Bs,AckNo,AckBytes+SegSize,Socket,Stream)
	    end;
	false ->
	    Bytes = Stream#stream.bytes - AckBytes,
	    {AckBytes,Stream#stream { seq = AckNo, bytes = Bytes, blocks=Bs0 }}
    end;
ack_blocks([],AckNo,_AckBytes,_Socket,Stream) -> 
    %% all blocks are acked we may disable rt_timer 
    {-1, Stream#stream { seq = AckNo, bytes = 0, blocks=[] }}.

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

enqueue_stream(Stream=#stream{seq=Seq0,closed=Closed,blocks=Bs0},Data) ->
    {Seq,RBs} = case lists:reverse(Bs0) of
		    [] -> {Seq0, []};
		    RBs0=[#block{seq=Seq1}|_] -> {Seq1,RBs0}
		end,
    try enqueue_data_(Data,Seq,Closed,[],RBs) of
	{Closed1,Bs1} ->
	    {ok,Stream#stream {closed=Closed1,blocks=Bs1}}
    catch
	error:_ ->
	    {error,einval}
    end.

%% handle list of data, not segments. The segments are split
%% as late as possible to allow for various options lists.
%% ack may split data list when handling selective acks.

enqueue_data_([Data|Ds],Seq,Closed,Cont,Bs) ->
    enqueue_data_(Data,Seq,Closed,[Ds|Cont],Bs);
enqueue_data_([],Seq,Closed,Cont,Bs) ->
    enqueue_data_cont_(Cont, Seq, Closed, Bs);
enqueue_data_(Data,Seq,Closed,Cont,Bs) when is_binary(Data) ->
    Seq1 = ?u32(Seq + byte_size(Data)),
    B = #block{seq=Seq,status=send,data=Data},
    enqueue_data_cont_(Cont, Seq1, Closed, [B|Bs]);
enqueue_data_(Mark,Seq,Closed,Cont,Bs) when is_reference(Mark) ->
    B = #block{seq=Seq,status=waitack,data=Mark},
    enqueue_data_cont_(Cont, Seq, Closed, [B|Bs]);
enqueue_data_(?FIN,Seq,_Closed,Cont,Bs) ->
    B = #block{seq=Seq,status=send,data=?FIN},
    enqueue_data_cont_(Cont, Seq, pushed, [B|Bs]).

enqueue_data_cont_([],_Seq,Closed,Bs) ->
    {Closed, lists:reverse(Bs)};
enqueue_data_cont_([Data|Cont1],Seq,Closed,Bs) ->
    enqueue_data_(Data,Seq,Closed,Cont1,Bs).

left_sequence_no(#stream { seq=Seq,blocks=[] }) -> Seq;
left_sequence_no(#stream { blocks=[#block{seq=Seq}|_] }) -> Seq.

right_sequence_no(#stream { seq=Seq,blocks=[] }) -> Seq;
right_sequence_no(#stream { blocks=Bs }) ->
    #block{seq=Seq,data=Data} = lists:last(Bs),
    ?u32(Seq+segment_size(Data)).

segment_size(Data) when is_binary(Data) -> byte_size(Data);
segment_size(Data) when is_reference(Data) -> 0;
segment_size(?FIN) -> 1.

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
		    DstMac = route_lookup(DstIP, State),
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
	{true,Sent,Socket1} ->
	    Socket2 =
		if Socket1#tcp_socket.tcp_state =:= ?TCP_CLOSE_WAIT ->
			Socket1#tcp_socket { tcp_state = ?TCP_LAST_ACK };
		   true ->
			Socket1#tcp_socket { tcp_state = ?TCP_FIN_WAIT1 }
		end,
	    start_rt_timer(0,Sent,Socket2);
	{false,Sent,Socket1} ->
	    start_rt_timer(0,Sent,Socket1)
    end.

transmit_data(Socket=#tcp_socket{ostream=Ostream,istream=Istream},State) ->
    #stream { closed=SentFin,bytes=Bytes,window=Window,blocks=Bs } = Ostream,
    Mss = Istream#stream.mss,  %% segment size supported by remote
    Options = if Socket#tcp_socket.tcp_opts band ?TCP_OPT_TIMESTAMP =/= 0 ->
		      {10,[{timestamp,timestamp(),Socket#tcp_socket.tsecr}]};
		 true ->
		      {0,[]}
	      end,
    {SentFin1,Bytes1,Socket1,Bs1} = transmit_stream(Socket,Bs,[],Options,
						    Mss,Bytes,Window,SentFin,
						    State),
    Ostream1 = Ostream#stream { closed=SentFin,bytes=Bytes1,blocks=Bs1 },
    {SentFin1, Bytes1 - Bytes,Socket1#tcp_socket { ostream = Ostream1 }}.

%% send unsent data segments
transmit_stream(Socket,Bs0=[B=#block{seq=Seq,status=Stat,data=Data}|Bs],
		Acc,Opts,Mss,Bytes,Window,SentFin, State) ->
    if is_binary(Data) ->
	    {OptionsSize,TcpOptions} = Opts,
	    SegSize = min(Mss-OptionsSize, byte_size(Data)),
	    Bytes1 = Bytes + SegSize,
	    if Bytes1 =< Window ->  %% ok to send
		    if Stat =:= send ->
			    <<Segment:SegSize/binary, Data1/binary>> = Data,
			    Socket1=transmit_tcp(Socket,Seq,false,true,
						 false,false,TcpOptions,
						 Segment,State),
			    B1 = B#block{status=waitack,data=Segment},
			    Acc1 = [B1|Acc],
			    Bs1 = if Data1 =:= <<>> -> Bs;
				     true ->
					  Seq1=?u32(Seq+SegSize),
					  B0=#block{seq=Seq1,status=send,
						    data=Data1},
					  [B0|Bs]
				  end,
			    transmit_stream(Socket1,Bs1,Acc1,Opts,
					    Mss,Bytes1,Window,
					    SentFin,State);
		       true ->
			    transmit_stream(Socket,Bs,[B|Acc],Opts,
					    Mss,Bytes1,Window,
					    SentFin,State)
		    end;
	       true ->
		    {SentFin,Bytes1,Socket,lists:reverse(Acc)++Bs0}
	    end;
       is_reference(Data) ->
	    transmit_stream(Socket,Bs,[B|Acc],Opts,Mss,Bytes,
			    Window,SentFin,State);
       Data =:= ?FIN ->
	    if Stat =:= send ->
		    Socket1 = transmit_fin(Socket,Seq,State),
		    Acc1 = [B#block{status=waitack}|Acc],
		    %% handle event refs etc, must not send more data
		    transmit_stream(Socket1,Bs,Acc1,Opts,
				    Mss,Bytes,Window,true,
				    State);
	       true ->
		    transmit_stream(Socket,Bs,[B|Acc],Opts,
				    Mss,Bytes,Window,true,
				    State)
	    end
    end;
transmit_stream(Socket,[],Acc,_Opts,_Mss,Bytes1,_Window,SentFin,_State) ->
    {SentFin,Bytes1,Socket,lists:reverse(Acc)}.

transmit_syn(Socket,State) ->
    TcpOptions = tcp_syn_options(Socket),
    transmit_tcp(Socket,true,false,false,false,TcpOptions,<<>>,State).

transmit_syn_ack(Socket,State) ->
    TcpOptions = tcp_syn_options(Socket),
    transmit_tcp(Socket,true,true,false,false,TcpOptions,<<>>,State).

transmit_ack(Socket,State) ->
    transmit_tcp(Socket,false,true,false,false,[],<<>>,State).

transmit_fin(Socket,SeqNo,State) ->
    transmit_tcp(Socket,SeqNo,false,false,true,false,[],<<>>,State).

transmit_tcp(Socket,Syn,Ack,Fin,Rst,TcpOptions,Data,State) ->
    SeqNo = (Socket#tcp_socket.ostream)#stream.seq,
    transmit_tcp(Socket,SeqNo,Syn,Ack,Fin,Rst,TcpOptions,Data,State).

transmit_tcp(Socket=#tcp_socket{istream=Istream,ostream=Ostream},SeqNo,
	     Syn,Ack,Fin,Rst,TcpOptions,Data,State) ->
    Remain = Istream#stream.window - Istream#stream.bytes, %% window remain
    SegWnd = Remain bsr Ostream#stream.wss,
    Tcp = #tcp { src_port = Socket#tcp_socket.src_port,
		 dst_port = Socket#tcp_socket.dst_port,
		 seq_no   = SeqNo,
		 ack_no   = Istream#stream.seq,
		 data_offset=0,
		 reserved=0,
		 urg=false,ack=Ack,psh=(Data =/= <<>>),
		 rst=Rst,syn=Syn,fin=Fin,
		 window=SegWnd,
		 csum=correct,
		 urg_pointer=0,
		 options = TcpOptions,
		 data = Data},
    log_tcp(Socket, Tcp, ">"),
    transmit_ip(Socket, tcp, Tcp, State).

transmit_ip(Socket, Proto, Data, State) ->
    Ip  = #ipv4 { src=Socket#tcp_socket.src,
		  dst=Socket#tcp_socket.dst,
		  proto=Proto, data=Data },
    DstMac = route_lookup(Socket#tcp_socket.dst, State),
    Eth = #eth { src=Socket#tcp_socket.mac, dst=DstMac,type=ipv4,data=Ip },
    transmit_frame(Eth, State),
    Socket.

transmit_frame(Frame, State) ->
    Data=enet_eth:encode(Frame, []),
    eth_devices:send(State#state.eth, Data).

route_lookup(Dst, State) ->
    case cache_lookup(Dst, State) of
	false ->
	    case dict:find(Dst, State#state.ipmac) of
		error -> State#state.gw_mac; %% use the gateway mac
		{ok,Mac} -> Mac
	    end;
	Mac -> Mac
    end.

random_32() ->
    <<X:32>> = crypto:rand_bytes(4),
    X.

default_mss(IP,State) when tuple_size(IP) =:= 4 -> State#state.mssdflt;
default_mss(IP,State) when tuple_size(IP) =:= 8 -> State#state.v6mssdflt.

%% calculte mss given protocol and interface mtu
calc_mss(IP,State) when tuple_size(IP) =:= 4 ->
    if State#state.mtu > ?TCP_IPV4_HEADER_MIN_LEN ->
	    State#state.mtu-?TCP_IPV4_HEADER_MIN_LEN;
       true ->
	    State#state.mssdflt
    end;
calc_mss(IP,State) when tuple_size(IP) =:= 8 ->
    if State#state.mtu > ?TCP_IPV6_HEADER_MIN_LEN ->
	    State#state.mtu-?TCP_IPV6_HEADER_MIN_LEN;
       true ->
	    State#state.v6mssdflt
    end.

%% TCP options sent in SYN/SYN+ACK packet
tcp_syn_options(Socket) ->
    %% push flags in the reversed order, they are build reversed
    tcp_syn_opts_([?TCP_OPT_TIMESTAMP,?TCP_OPT_WSS,
		      ?TCP_OPT_SACK,?TCP_OPT_MSS],
		     Socket#tcp_socket.tcp_opts,
		     Socket, []).

tcp_syn_opts_(_Fs, 16#0000, _Socket, Acc) -> %% no more flags allowed
    Acc;
tcp_syn_opts_([F|Fs], Flags, Socket, Acc) when F band Flags =/= 0 ->
    Flags1 = Flags band (bnot F),
    case F of
	?TCP_OPT_MSS ->
	    tcp_syn_opts_(Fs, Flags1, Socket,
			  [{mss,(Socket#tcp_socket.ostream)#stream.mss}|Acc]);
	?TCP_OPT_WSS ->
	    tcp_syn_opts_(Fs, Flags1, Socket,
			 [{window_size_shift,
			   (Socket#tcp_socket.ostream)#stream.wss}|Acc]);
	?TCP_OPT_TIMESTAMP ->
	    tcp_syn_opts_(Fs, Flags1, Socket,
			  [{timestamp,timestamp(),0}|Acc]);
	?TCP_OPT_SACK ->
	    tcp_syn_opts_(Fs, Flags1, Socket, [sack_ok|Acc]);
	_ -> %% ignore unknown options
	    tcp_syn_opts_(Fs, Flags1, Socket, Acc)
    end;
tcp_syn_opts_([_|Fs], Flags, Socket, Acc) -> %% flag not allowed
    tcp_syn_opts_(Fs, Flags, Socket, Acc);
tcp_syn_opts_([], _Flags, _Socket, Acc) -> Acc.

%% Other side is sending options Flags dictate we.
accept_syn_options(Fs, Socket, State) ->
    accept_syn_opts_(Fs, Socket#tcp_socket.tcp_opts, 0, Socket, State).

accept_syn_opts_([F|Fs], Flags, OFlags, Socket, State) ->
    case F of
	{mss,Mss} ->
	    Flag = ?TCP_OPT_MSS band Flags,
	    #tcp_socket { istream=Istream, ostream=Ostream } = Socket,
	    {IMss,OMss} =
		if Flag =:= 0 ->
			{Istream#stream.mss,Ostream#stream.mss};
		   true ->
			CMss = calc_mss(Socket#tcp_socket.dst,State),
			IMss0 = case Istream#stream.mss of
				    {force,FMss} -> min(CMss,FMss);
				    _Default -> min(CMss,Mss)
				end,
			OMss0 = min(Ostream#stream.mss, CMss),
			{IMss0,OMss0}
		end,
	    Istream1 = Istream#stream { mss = IMss },
	    Ostream1 = Ostream#stream { mss = OMss },
	    Socket1 = Socket#tcp_socket { istream=Istream1, ostream=Ostream1 },
	    io:format("option mss [~w] = ~w\n", [ Flag =/= 0, {IMss,OMss}]),
	    accept_syn_opts_(Fs, Flags, OFlags bor Flag, Socket1, State);

	{window_size_shift, Wss} ->
	    Flag = ?TCP_OPT_WSS band Flags,
	    #tcp_socket { istream=Istream, ostream=Ostream } = Socket,
	    {IWss,OWss} = if Flag =:= 0 -> {0, 0};
			     true ->
				  OWss0 = Ostream#stream.wss,
				  OWss1 = max(State#state.wssdflt,OWss0),
				  {min(14,Wss),min(14,OWss1)}
			  end,
	    Istream1 = Istream#stream { wss = IWss },
	    Ostream1 = Ostream#stream { wss = OWss },
	    Socket1 = Socket#tcp_socket { istream=Istream1, ostream=Ostream1 },
	    io:format("option wss [~w] = ~w\n", [ Flag =/= 0, {IWss,OWss}]),
	    accept_syn_opts_(Fs, Flags, OFlags bor Flag, Socket1, State);

	{timestamp, Ts, _TsReply} ->
	    Flag = ?TCP_OPT_TIMESTAMP band Flags,
	    Ts1 = if Flag =:= 0 -> 0; true -> Ts end,
	    Socket1 = Socket#tcp_socket { tsecr = Ts1 },
	    io:format("option timestamp [~w] = ~w\n", [ Flag =/= 0,
							{Ts,_TsReply}]),
	    accept_syn_opts_(Fs, Flags, OFlags bor Flag, Socket1, State);

	sack_ok ->
	    Flag = ?TCP_OPT_SACK band Flags,
	    io:format("option sack [~w]\n", [ Flag =/= 0 ]),
	    accept_syn_opts_(Fs, Flags, OFlags bor Flag, Socket, State);

	nop ->
	    accept_syn_opts_(Fs, Flags, OFlags, Socket, State);
	_ ->
	    ?debug("accept_syn_opts: ignore unknown option ~p\n", [F]),
	    accept_syn_opts_(Fs, Flags, OFlags, Socket, State)
    end;
accept_syn_opts_([],_Flags,OFlags,Socket,_State) ->
    %% what happens if we get a retransmit on SYN with new options?
    #tcp_socket { istream=Istream } = Socket,
    %% adjust forced values
    Istream1 = case Istream#stream.mss of
		   {force,FMss} -> Istream#stream{mss=FMss};
		   _ -> Istream
	       end,
    Socket#tcp_socket { tcp_opts = OFlags, istream=Istream1 }.

%% handle timestamp on input store last value, update rtt etc
handle_timestamp(Socket, Tcp) ->
    if Socket#tcp_socket.tcp_opts band ?TCP_OPT_TIMESTAMP =:= 0 ->
	    Socket;
       true ->
	    case lists:keyfind(timestamp, 1, Tcp#tcp.options) of
		false -> Socket;
		{_, TsVal, TSecr} ->
		    Socket1 = Socket#tcp_socket { tsecr = TsVal },
		    if Tcp#tcp.ack -> %% TSecr value only when acknowledge
			    Left = left_sequence_no(Socket1#tcp_socket.ostream),
			    %% TSecr used when acking new data
			    case ?seq_lt(Left, Tcp#tcp.ack_no) of
				true ->
				    rto_sample(TSecr, Socket1);
				false ->
				    Socket1
			    end;
		       true ->
			    Socket1
		    end
	    end
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

rto_sample(TSecr, Socket) when is_integer(TSecr), TSecr > 0 ->
    R = ?u32(timestamp() - TSecr) / 1000,  %% convert to seconds
    rto_update(R, Socket).

%% update rto with roundtrip sample R (in seconds)
%% Acording to RFC 2988
rto_update(R,Socket) when is_float(R) ->
    case Socket of
	#tcp_socket { srtt = undefined } ->  %% first measurement
	    SRTT = R,
	    RTTVAR = R / 2,
	    RTO = SRTT + max(?GRANULARITY_RTO, ?K*RTTVAR),
	    io:format("first RTO=~w R=~w\n", [RTO, R]),
	    Socket#tcp_socket { srtt=SRTT, rttvar=RTTVAR, rto=RTO };
	#tcp_socket { srtt = SRTT0, rttvar = RTTVAR0 } ->
	    RTTVAR = (1-?beta)*RTTVAR0 + ?beta*abs(SRTT0 - R),
	    SRTT = (1-?alpha)*SRTT0 + ?alpha*R,
	    RTO = SRTT + max(?GRANULARITY_RTO, ?K*RTTVAR),
	    ?debug("new RTO=~w, R=~w\n", [RTO,R]),
	    Socket#tcp_socket {  srtt=SRTT, rttvar=RTTVAR, rto=RTO }
    end.

%% generate a timestamp for the packet (using ms)
timestamp() ->
    ?u32(erlang:system_time(milli_seconds)).

%% build for
insert_cache(_, {0,0,0,0,0,0}, State) -> State;
insert_cache({0,0,0,0}, _, State) -> State;
insert_cache({0,0,0,0,0,0,0,0}, _, State) -> State;
insert_cache(IP, Mac, State) ->
    IPMac = dict:store(IP, Mac, State#state.cache),
    GwMac = if State#state.gw =:= IP ->
		    ?debug("gateway ~w mac set = ~w\n", [IP,Mac]),
		    Mac;
	       true -> State#state.gw_mac
	    end,
    State#state { cache = IPMac, gw_mac=GwMac }.

cache_lookup(IP, State) ->
    case dict:find(IP, State#state.cache) of
	{ok,Mac} -> Mac;
	error -> false
    end.

send_arp(Op,SenderMac,TargetMac,SenderIP,TargetIP,State) ->
    {PType,PLen} = if tuple_size(SenderIP) =:= 4 -> {ipv4, 4};
		      tuple_size(SenderIP) =:= 8 -> {ipv6, 16}
		   end,
    transmit_arp(?BROADCAST,State#state.mac,
		 #arp { op=Op, htype=ethernet, ptype=PType,
			haddrlen = 6, paddrlen = PLen,
			sender={SenderMac,SenderIP},
			target={TargetMac,TargetIP}}, State).


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

%% fixme options (timestamps) in a nice way
log_tcp(TcpState,Src,SrcPort,Dst,DstPort,Tcp,Dir) ->
    io:format("tcp[~s]: ~s:~w ~s ~s:~w: ~w ~s ack=~w opts=~w: ~s\n",
	      [TcpState,
	       format_ip_addr(Src), SrcPort,
	       Dir,
	       format_ip_addr(Dst), DstPort,
	       Tcp#tcp.seq_no,
	       format_tcp_flags(Tcp),
	       Tcp#tcp.ack_no,
	       Tcp#tcp.options,
	       format_tcp_data(Tcp#tcp.data, 64)]).

dump_sockets(State) ->
    io:format("--- REF TABLE ---\n"),
    dict:fold(
      fun(Ref,Key,_) -> io:format("~w -> ~w\n", [Ref,Key]) end,
      ok, State#state.sockref),
    io:format("--- SOCKET TABLE ---\n"),
    dict:fold(
      fun(_Key,Socket,_) when is_record(Socket,lst_socket) ->
	      io:format("~w: src=~s:~w options=~w\n", 
			[Socket#lst_socket.key,
			 format_ip_addr(Socket#lst_socket.src),
			 Socket#lst_socket.src_port,
			 Socket#lst_socket.options
			]);
	 (_Key,Socket,_) when is_record(Socket,tcp_socket) ->
	      io:format("~w: [~w] src=~s:~w dst=~s:~w rto=~w\n",
			[Socket#tcp_socket.key,
			 Socket#tcp_socket.tcp_state,
			 format_ip_addr(Socket#tcp_socket.src),
			 Socket#tcp_socket.src_port,
			 format_ip_addr(Socket#tcp_socket.dst),
			 Socket#tcp_socket.dst_port,
			 Socket#tcp_socket.rto
			]);
	 (_Key,Socket,_) when is_record(Socket,udp_socket) ->
	      io:format("~w: [udp] src=~s:~w dst=~s:~w\n", 
			[Socket#udp_socket.key,
			 format_ip_addr(Socket#udp_socket.src),
			 Socket#udp_socket.src_port,
			 format_ip_addr(Socket#udp_socket.dst),
			 Socket#udp_socket.dst_port
			])
      end, ok, State#state.sockets),
    io:format("--- END ---\n").



format_ip_addr({A,B,C,D}) ->
    io_lib:format("~w.~w.~w.~w", [A,B,C,D]);
format_ip_addr(undefined) ->
    "".

format_tcp_data(<<>>,_Max) -> "";
format_tcp_data(Binary,Max) when is_binary(Binary) ->
    case list_to_binary(io_lib:format("~w[~s", [byte_size(Binary),Binary])) of
	<<Bin:Max/binary, _/binary>> ->
	    binary_to_list(Bin) ++ "..]";
	Bin ->
	    binary_to_list(Bin) ++ "]"
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
