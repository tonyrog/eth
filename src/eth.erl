%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%
%%% @end
%%% Created : 29 Apr 2013 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(eth).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([bind/2, unbind/1, active/2, setf/2]).
-export([debug/2]).
-export([clear/1, dump/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 
-define(ETH_PORT, eth_port).

-define(CMD_BIND,    1).
-define(CMD_UNBIND,  2).
-define(CMD_ACTIVE,  3).
-define(CMD_SETF,    4).
-define(CMD_DEBUG,   5).

-define(DLOG_DEBUG,     7).
-define(DLOG_INFO,      6).
-define(DLOG_NOTICE,    5).
-define(DLOG_WARNING,   4).
-define(DLOG_ERROR,     3).
-define(DLOG_CRITICAL,  2).
-define(DLOG_ALERT,     1).
-define(DLOG_EMERGENCY, 0).
-define(DLOG_NONE,     -1).

-include_lib("enet/include/enet_types.hrl").

-record(state, 
	{
	  port,
	  packet_counters,
	  data_counters
	}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

bind(Pid, Name) ->
    gen_server:call(Pid, {bind,Name}).

unbind(Pid) ->
    gen_server:call(Pid, unbind).

active(Pid, N) when N >= -1 ->
    gen_server:call(Pid, {active, N}).

setf(Pid, Filter) when is_list(Filter) ->
    BinFilter = eth_bpf:encode(Filter),
    gen_server:call(Pid, {setf, BinFilter}).

debug(Pid, Level) when is_atom(Level) ->
    gen_server:call(Pid, {debug, level(Level)}).

dump(Pid) ->
    {ok,{PacketCounters,DataCounters}} = gen_server:call(Pid, counters),
    dump(PacketCounters, DataCounters).

clear(Pid) ->
    gen_server:call(Pid, clear).

dump(PTab, DTab) ->
    ets:foldl(
      fun({Key,Count}, Acc) ->
	      Data = ets:lookup_element(DTab, Key, 2),
	      io:format("~p : ~p : ~p\n", [Key, Count, Data]),
	      Acc
      end, [], PTab).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    Driver = "eth_drv", 
    ok = erl_ddll:load_driver(code:priv_dir(eth), Driver),
    Port = erlang:open_port({spawn_driver, Driver},[binary]),
    true = erlang:register(?ETH_PORT, Port),
    PacketCounters = ets:new(packet_counters, [ordered_set]),
    DataCounters = ets:new(data_counters, [ordered_set]),
    {ok, #state{ port=Port, 
		 packet_counters = PacketCounters,
		 data_counters = DataCounters }}.


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
handle_call({bind,Name}, _From, State) ->
    Reply = call(State#state.port, ?CMD_BIND, Name),
    {reply, Reply, State};
handle_call(unbind, _From, State) ->
    Reply = call(State#state.port, ?CMD_UNBIND, []),
    {reply, Reply, State};
handle_call({active,N}, _From, State) ->
    Reply = call(State#state.port, ?CMD_ACTIVE, <<N:32/signed-integer>>),
    {reply, Reply, State};
handle_call({setf,BinFilter}, _From, State) ->
    Reply = call(State#state.port, ?CMD_SETF, BinFilter),
    {reply, Reply, State};
handle_call(counters, _From, State) ->
    {reply, {ok, {State#state.packet_counters, State#state.data_counters}}, 
     State};
handle_call(clear, _From, State) ->
    ets:delete_all_objects(State#state.packet_counters),
    ets:delete_all_objects(State#state.data_counters),
    {reply, ok, State};
handle_call({debug,Level}, _From, State) ->
    Reply = call(State#state.port, ?CMD_DEBUG, [Level]),
    {reply, Reply, State};    
handle_call(_Request, _From, State) ->
    Reply = {error,bad_call},
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Frame={eth_frame,Port,_IfIndex,Data}, State) when 
      Port =:= State#state.port ->
    State1 = collect(eth, Data, State, [nolookup]),
    {noreply, State1};
handle_info(_Info, State) ->
    io:format("eth: got ~p\n", [_Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

call(Port, Cmd, Data) ->
    case erlang:port_control(Port, Cmd, Data) of
	<<0>> ->
	    ok;
	<<255,E/binary>> -> 
	    {error, erlang:binary_to_atom(E, latin1)};
	<<1,Y>> -> {ok,Y};
	<<2,Y:16/native-unsigned>> -> {ok, Y};
	<<4,Y:32/native-unsigned>> -> {ok, Y};
	<<3,Return/binary>> -> {ok,Return}
    end.

%%
%% Statistics function:
%%
%% Key1:
%%        {EthSrc,EthDst,>,eth} => counter
%% Key2:
%%        {IPSrc,IPDst,>,ipv4}   => counter
%% Key3:
%%        {IPSrc,IPDst,>,Prot,SrcPort,DstPort} => counter
%%
collect(eth, Data, State, Options) ->
    try enet_eth:decode(Data, Options) of
	{error,_} ->
	    %% fixme count
	    State;
	F ->
	    Key = make_key(F#eth.src,F#eth.dst,eth),
	    State1 = update_counter(Key, Data, State),
	    collect(F#eth.type, F#eth.data, State1, Options)
    catch
	error:_ ->
	    %% fixme count
	    State
    end;
collect(ipv4, Data, State, Options) ->
    try enet_ipv4:decode(Data, Options) of
	{error,_} ->
	    %% fixme count
	    State;
	F ->
	    Key = make_key(F#ipv4.src,F#ipv4.dst,ipv4),
	    State1 = update_counter(Key, Data, State),
	    IPH = #ip_pseudo_hdr{src=F#ipv4.src,
				 dst=F#ipv4.dst,
				 proto=F#ipv4.proto},
	    collect(F#ipv4.proto, F#ipv4.data, State1, [IPH|Options])
    catch
	error:_ ->
	    %% fixme count
	    State
    end;
collect(ipv6, Data, State, Options) ->
    try enet_ipv6:decode(Data, []) of
	{error,_} ->
	    %% fixme count
	    State;
	F ->
	    Key = make_key(F#ipv6.src,F#ipv6.dst,ipv6),
	    State1 = update_counter(Key, Data, State),
	    IPH = #ip_pseudo_hdr{src=F#ipv6.src,dst=F#ipv6.dst,
				 proto=F#ipv6.next_hdr},
	    collect(F#ipv6.next_hdr, F#ipv6.payload, State1, [IPH|Options])
    catch
	error:_ ->
	    %% fixme count
	    State
    end;
collect(udp, Data, State, [IPH|Options]) ->
    IPH1 = encode_pseudo_header(IPH),
    try enet_udp:decode(Data, [IPH1 | Options]) of
	{error,_} ->
	    %% fixme count
	    State;
	P ->
	    Key = make_key(IPH#ip_pseudo_hdr.src,
			   IPH#ip_pseudo_hdr.dst,udp,
			   P#udp.src_port, P#udp.dst_port),
	    State = update_counter(Key, Data, State),
	    %% collect(application_protocol(),...)
	    State
    catch
	error:_ ->
	    %% fixme count
	    State
    end;
collect(tcp, Data, State, [IPH| Options]) ->
    IPH1 = encode_pseudo_header(IPH),
    try enet_tcp:decode(Data, [IPH1 | Options]) of
	{error,_} ->
	    %% fixme count
	    State;
	P ->
	    Key = make_key(IPH#ip_pseudo_hdr.src,
			   IPH#ip_pseudo_hdr.dst,tcp,
			   P#tcp.src_port, P#tcp.dst_port),
	    State = update_counter(Key, Data, State),
	    %% collect(application_protocol(),...)
	    State
    catch
	error:_ ->
	    %% fixme count
	    State
    end;
collect(_Proto, _Data, State, _Options) ->
    %% fixme: log 
    State.
	

make_key(A,B,P) when A < B -> {A,B,P,'>'};
make_key(A,B,P) ->  {B,A,P,'<'}.

make_key(A,B,P,Ap,Bp) when A < B -> {A,B,P,Ap,Bp,'>'};
make_key(A,B,P,Ap,Bp) ->  {B,A,P,Bp,Ap,'<'}.
    

update_counter(Key, Data, State) ->
    Size = data_size(Data),
    State1 = try ets:update_counter(State#state.packet_counters, Key, 1) of
		 _ -> State
	     catch
		 error:_ ->
		     ets:insert(State#state.packet_counters, {Key,1}),
		     State
	     end,
    try ets:update_counter(State1#state.data_counters, Key, Size) of
	_ -> State1
    catch
	error:_ ->
	    ets:insert(State1#state.data_counters, {Key,Size}),
	    State1
    end.

encode_pseudo_header(#ip_pseudo_hdr{src=Src,dst=Dst,proto=Proto}) ->
    #ip_pseudo_hdr { proto = enet_ipv4:encode_protocol(Proto),
		     src   = encode_addr(Src),
		     dst   = encode_addr(Dst) }.

encode_addr({A,B,C,D}) -> 
    <<A,B,C,D>>;
encode_addr({A,B,C,D,E,F,G,H}) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>.
    

data_size(Binary) when is_binary(Binary) ->  byte_size(Binary);
data_size(#eth  { data=Data} ) ->     data_size(Data);
data_size(#ipv4 { data=Data} ) ->     data_size(Data);
data_size(#tcp  { data=Data} ) ->     data_size(Data);
data_size(#udp  { data=Data} ) ->     data_size(Data);
data_size(#ipv6 { payload=Data} ) ->  data_size(Data);
data_size(#icmp { data=Data} ) ->     data_size(Data);
data_size(_) ->  0.

%% convert symbolic to numeric level
level(debug) -> ?DLOG_DEBUG;
level(info)  -> ?DLOG_INFO;
level(notice) -> ?DLOG_NOTICE;
level(warning) -> ?DLOG_WARNING;
level(error) -> ?DLOG_ERROR;
level(critical) -> ?DLOG_CRITICAL;
level(alert) -> ?DLOG_ALERT;
level(emergency) -> ?DLOG_EMERGENCY;
level(none) -> ?DLOG_NONE.
