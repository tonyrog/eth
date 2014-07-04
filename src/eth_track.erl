%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     TCP connection tracking
%%% @end
%%% Created :  7 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_track).

-behaviour(gen_server).

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
	  con
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

start_link(Interface) when is_list(Interface) ->
    gen_server:start_link(?MODULE, [Interface], []).

stop(Pid) ->
    gen_server:call(Pid, stop).

dump(Pid) ->
    gen_server:call(Pid, dump).


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
	    T = ets:new(contrack, []),
	    Prog = eth_bpf:build_programx(
		     {'||', 
		      [connect_filter(),
		       disconnect_filter(),
		       reset_filter()
		      ]}),
	    Filter = bpf:asm(Prog),
	    case eth:set_filter(Port, Filter) of
		ok ->
		    eth:set_active(Port, -1),
		    {ok, #state { eth = Port, con=T }};
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
handle_call(dump, _From, State) ->
    ets:foldl(fun(V,_) ->
		      io:format("~w\n", [V])
	      end, ok, State#state.con),
    {reply, ok, State};
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
		    Key = {IPv4#ipv4.src, IPv4#ipv4.dst,
			   Tcp#tcp.src_port, Tcp#tcp.dst_port},
		    ets:insert(State#state.con, {Key,true});
	       Tcp#tcp.fin, Tcp#tcp.ack; Tcp#tcp.rst ->
		    Key = {IPv4#ipv4.src, IPv4#ipv4.dst,
			   Tcp#tcp.src_port, Tcp#tcp.dst_port},
		    ets:delete(State#state.con, Key);
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

