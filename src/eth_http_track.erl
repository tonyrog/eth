%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     HTTP/TCP connection+cookie tracking
%%% @end
%%% Created :  7 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_http_track).

-behaviour(gen_server).

-include_lib("kernel/include/inet.hrl").

%% API

-export([start_link/1]).
-export([stop/1, dump/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("enet/include/enet_types.hrl").

-record(state, 
	{
	  eth,
	  con,   %% ets table with IPQuad -> latest Headers
	  host   %% ets table with Host -> Cookies
	}).

%%%===================================================================
%%% API
%%%===================================================================

-define(LOG(Fmt, As), io:format((Fmt), (As))).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Pid) ->
    gen_server:call(Pid, stop).

dump(Pid) ->
    {ok,HostTable} = gen_server:call(Pid, get_host_table),
    ets:foldl(fun({Host,Cookies},_) ->
		      dump_host(Host,Cookies)
	      end, ok, HostTable),
    {ok,ConnectionTable} = gen_server:call(Pid, get_connection_table),
    ets:foldl(fun({IPQuad,Hs0,Hs},_) ->
		      dump_connection(IPQuad,Hs0++Hs)
	      end, ok, ConnectionTable).

%% Dump host entry
dump_host(Host, Cookies) ->
    io:format("\nHOST [~s]\n", [Host]),
    lists:foreach(
      fun({Key,Value}) ->
	      io:format("      ~s = ~s\n", [Key,Value])
      end, Cookies).
    

dump_connection(_IPQuad={_Src, Dst, _SrcPort, DstPort}, Hs) ->
    case inet:gethostbyaddr(Dst, 2000) of
	{error, _} ->
	    io:format("\nCONNECTION ~s:~w\n", 
		      [inet_parse:ntoa(Dst), DstPort]);
	{ok,H} ->
	    io:format("\nCONNECTION ~s [~s]:~w\n", 
		      [H#hostent.h_name,inet_parse:ntoa(Dst),
		       DstPort])
    end,
    lists:foreach(
      fun({'Cookie',Cookies}) ->
	      lists:foreach(
		fun({Key,Value}) ->
			io:format("      ~s = ~s\n", [Key,Value])
		end, Cookies);
	 ({'Set-Cookie',Cookies}) ->
	      lists:foreach(
		fun({Key,Value}) ->
			io:format("      ~s = ~s\n", [Key,Value])
		end, Cookies);
	 ({Key,Value}) ->
	      io:format("    ~s: ~p\n", [Key,Value])
      end, Hs).

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
init([Interface]) ->
    case eth_devices:open(Interface) of
	{ok,Port} ->
	    T = ets:new(connection_track, []),
	    H = ets:new(host_track, []),
	    Prog = eth_bpf:build_programx(
		     {'||', 
		      [connect_filter(),
		       disconnect_filter(),
		       reset_filter(),
		       http_request_filter(),
		       http_response_filter()
		      ]}),
	    Filter = bpf:asm(Prog),
	    case eth:set_filter(Port, Filter) of
		ok ->
		    eth:set_active(Port, -1),
		    {ok, #state { eth = Port, con=T, host=H }};
		Error ->
		    {stop, Error}
	    end;
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
handle_call(get_connection_table, _From, State) ->
    {reply, {ok, State#state.con}, State}; 
handle_call(get_host_table, _From, State) ->
    {reply, {ok, State#state.host}, State}; 
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
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
handle_info({eth_frame,_Port,_IfIndex,Data}, State) ->
    try eth_packet:decode(Data, [{decode_types,all},nolookup]) of
	Eth ->
	    IPv4 = Eth#eth.data,
	    Tcp  = IPv4#ipv4.data,
	    if Tcp#tcp.syn, Tcp#tcp.ack ->
		    Key = {IPv4#ipv4.dst, IPv4#ipv4.src,
			   Tcp#tcp.dst_port, Tcp#tcp.src_port},
		    Info=lookup_program_and_pid(IPv4#ipv4.dst,Tcp#tcp.dst_port),
		    TimeStamp = erlang:system_time(micro_seconds),
		    Hs0 = [{'$SYN_TIMESTAMP$', TimeStamp},
			   {'$PROG_INFO', Info}],
		    ?LOG("CONNECT: ~p ~1024p\n", [Key, Hs0]),
		    ets:insert(State#state.con, {Key,Hs0,[]});
	       Tcp#tcp.fin, Tcp#tcp.ack; Tcp#tcp.rst ->
		    IPQuad1 = {IPv4#ipv4.dst, IPv4#ipv4.src,
			       Tcp#tcp.dst_port, Tcp#tcp.src_port},
		    case ets:lookup(State#state.con, IPQuad1) of
			[] ->
			    IPQuad2 = {IPv4#ipv4.dst, IPv4#ipv4.src,
				       Tcp#tcp.dst_port, Tcp#tcp.src_port},
			    case ets:lookup(State#state.con, IPQuad2) of
				[] ->
				    ignore;  %% connection not tracked
				_ ->
				    ?LOG("DISCONNECT: ~p\n", [IPQuad2]),
				    ets:delete(State#state.con, IPQuad2)
			    end;
			_ ->
			    ets:delete(State#state.con, IPQuad1),
			    ?LOG("DISCONNECT: ~p\n", [IPQuad1])
		    end;

	       Tcp#tcp.psh -> %% parse http data and look for cookies
		    %% only tracked nodes?
		    IPQuad1 = {IPv4#ipv4.src, IPv4#ipv4.dst,
			      Tcp#tcp.src_port, Tcp#tcp.dst_port},
		    case ets:lookup(State#state.con, IPQuad1) of
			[] ->
			    IPQuad2 = {IPv4#ipv4.dst, IPv4#ipv4.src,
				       Tcp#tcp.dst_port, Tcp#tcp.src_port},
			    case ets:lookup(State#state.con, IPQuad2) of
				[] ->
				    ignore;  %% connection not tracked
				[{Quad,Hs0,Hs1}] ->
				    parse_http(Quad, Hs0, Hs1,
					       State#state.con, 
					       State#state.host, 
					       Tcp#tcp.data)
			    end;
			[{Quad,Hs0,Hs1}] ->
			    parse_http(Quad, Hs0, Hs1,
				       State#state.con, 
				       State#state.host, 
				       Tcp#tcp.data)
		    end;
	       true ->
		    ignore
	    end,
	    {noreply, State}
    catch
	error:Reason ->
	    io:format("crash: ~p\n  ~p\n",
		      [Reason,erlang:get_stacktrace()]),
	    {noreply, State}
    end;
handle_info(_Info, State) ->
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

lookup_program_and_pid(IP, Port) ->
    Cmd = io_lib:format("lsof -F -n -i TCP@~s:~w", [inet_parse:ntoa(IP), Port]),
    L = os:cmd(Cmd),
    Ps = [{C,Cs} || [C|Cs] <- string:tokens(L, "\n")],
    _Prog = proplists:get_value($c,Ps,""),
    PidString = proplists:get_value($p,Ps,"0"),
    Pid = list_to_integer(PidString),
    Uid = list_to_integer(proplists:get_value($u,Ps,"0")),
    Path = os:cmd("ps -o command= " ++ PidString),
    [{command,Path},{pid,Pid}, {uid,Uid}].
    

parse_http(IPQuad,Hs0,Hs1,ConnectionTable, HostTable, Data) ->
    try erlang:decode_packet(http, Data, []) of
	{ok, {http_request,Method, Url, _Version}, HeaderData} ->
	    Hs = parse_http_headers(HeaderData, []),
	    set_host_cookies(HostTable, 'Cookie', Hs),
	    TimeStamp = erlang:system_time(micro_seconds),
	    Hss = [{'$REQUEST_METHOD$',Method},
		   {'$REQUEST_TIMESTAMP$', TimeStamp},
		   {'$REQUEST_URL$', Url} | Hs],
	    ets:insert(ConnectionTable, {IPQuad,Hs0,Hss});
	{ok, {http_response,_Version,_Status,_Phrase}, HeaderData} ->
	    Hs = parse_http_headers(HeaderData, []),
	    set_host_cookies(HostTable, 'Set-Cookie', Hs),
	    TimeStamp = erlang:system_time(micro_seconds),
	    Hss = [{'$RESPONSE_TIMESTAMP$', TimeStamp} | Hs],
	    Hs2 = Hs1++Hss,
	    ?LOG("HTTP: ~p ~1024p\n", [Hs0, Hs2]),
	    ets:insert(ConnectionTable, {IPQuad,Hs0,Hs2});
	_Error ->
	    ok
    catch
	error:_ -> ok
    end.

parse_http_headers(<<>>, Acc) ->
    lists:reverse(Acc);
parse_http_headers(Data, Acc) ->
    try erlang:decode_packet(httph, Data, []) of
	{ok, {http_header,_Hi,'Cookie',_,Value}, Data1} ->
	    Value1 = process_cookies(Value),
	    parse_http_headers(Data1, [{'Cookie',Value1}|Acc]);
	{ok, {http_header,_Hi,'Set-Cookie',_,Value}, Data1} ->
	    Value1 = process_cookies(Value),
	    parse_http_headers(Data1, [{'Set-Cookie',Value1}|Acc]);
	{ok, {http_header,_Hi,Key,_,Value}, Data1} ->
	    parse_http_headers(Data1, [{Key,Value}|Acc]);
	{ok, http_eoh, _Data} ->
	    lists:reverse(Acc);
	{more, undefined} ->  %% log? warning incomplete 
	    lists:reverse(Acc)
    catch
	error:_ ->
	    lists:reverse(Acc)
    end.

process_cookies(Value) ->
    try string:tokens(Value, "; ") of
	Cookies ->
	    lists:map(
	      fun(Cookie) ->
		      try string:tokens(Cookie, "=") of
			  [Key,Val] -> {Key,Val};
			  _ -> {Cookie, ""}
		      catch
			  error:_ ->
			      {Cookie, ""}
		      end
	      end, Cookies)
    catch
	error:_ ->
	    [{Value,""}]
    end.
    

set_host_cookies(HostTable, Key, Headers) ->
    case proplists:lookup('Host', Headers) of
	none ->
	    none;
	{_,HostName} ->
	    NewCookies = proplists:get_value(Key, Headers, []),
	    case ets:lookup(HostTable, HostName) of
		[] ->
		    ets:insert(HostTable, {HostName,NewCookies});
		[{_,OldCookies}] ->
		    MergedCookies = merge_cookies(NewCookies, HostName, 
						  OldCookies),
		    ets:insert(HostTable, {HostName,MergedCookies})
	    end
    end.

merge_cookies([Prop={K,V}|Ks], HostName, Cookies) ->
    case lists:keytake(K, 1, Cookies) of
	false ->
	    if HostName =:= "www.svtplay.se" ->
		    io:format("New Cookie: ~s = ~s\n", [K,V]);
	       true -> ok
	    end,
	    merge_cookies(Ks, HostName, [Prop|Cookies]);
	{value,{_K,V},_Cookies1} -> %% no value change
	    merge_cookies(Ks, HostName, Cookies);
	{value,_,Cookies1} ->
	    if HostName =:= "www.svtplay.se" ->
		    io:format("New Value: ~s = ~s\n", [K,V]);
	       true -> ok
	    end,
	    merge_cookies(Ks, HostName, [Prop|Cookies1])
    end;
merge_cookies([], _HostName, Cookies) ->
    Cookies.

%% TCP - SYN/ACK => established
connect_filter() ->
    {'&&', ["ether.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.syn", "ip.tcp.flag.ack"
	   ]}.

%% TCP - FIN/ACK => disconnected
disconnect_filter() ->
    {'&&', ["ether.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.fin","ip.tcp.flag.ack"
	   ]}.

reset_filter() ->
    {'&&', ["ether.type.ip", "ip.proto.tcp",
	    {'==',"ip.frag",0},
	    "ip.tcp.flag.rst"
	   ]}.

http_request_filter() ->
    {'&&', ["ether.type.ip", "ip.proto.tcp", {'==',"ip.frag",0},
	    {'||', 
	     {memeq,"ip.tcp.data",<<"GET ">>},
	     {memeq,"ip.tcp.data",<<"POST ">>}}]}.

http_response_filter() ->
    {'&&', ["ether.type.ip", "ip.proto.tcp", {'==',"ip.frag",0},
	    {'||',
	     {memeq,"ip.tcp.data",<<"HTTP/1.0 ">>},
	     {memeq,"ip.tcp.data",<<"HTTP/1.1 ">>}}]}.
