%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     tcpdump rip off
%%% @end
%%% Created :  7 May 2013 by Tony Rogvall <tony@rogvall.se>

-module(eth_dump).

-behaviour(gen_server).

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-export([set_filter/2, set_filterx/2,
	 set_active/2, set_active_time/2, set_style/2, stop/1]).

-export([start/1]).

-include_lib("enet/include/enet_types.hrl").

-record(state, 
	{
	  eth,
	  tref = undefined :: undefined | reference(), %% timer ref
	  style = json :: json|yang|erlang %%  (c...)
	}).

%%%===================================================================
%%% API
%%%===================================================================

%% shell version
start(Interface) ->
    application:ensure_all_started(eth),
    gen_server:start(?MODULE, [Interface], []).

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

%% only do statistic on what matched the filter!
set_filterx(Pid, Expr) when is_pid(Pid) ->
    case eth_bpf:build_programx(Expr) of
	E = {error,_} -> E;
	Prog -> set_filter(Pid, Prog)
    end.

set_filter(Pid, Prog) when is_pid(Pid), is_tuple(Prog) ->
    Filter = bpf:asm(Prog),
    gen_server:call(Pid, {set_filter, Filter}).

%% set output style
set_style(Pid, Style) when is_pid(Pid), is_atom(Style) ->
    gen_server:call(Pid, {set_style, Style}).

%% controls how many packets that should be handled:
%% -1 = unlimited
%%  0 = off
%%  N = count
%%
set_active(Pid, N) when is_integer(N), N >= -1 ->
    gen_server:call(Pid, {set_active, N}).

%%  0  = cancel time logging
%%  T  = log packets for T milliseconds
set_active_time(Pid, T) when is_integer(T), T >= 0 ->
    gen_server:call(Pid, {set_active_time, T}).

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
	    {ok, #state { eth = Port }};
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
handle_call({set_active,N}, _From, State) ->
    if State#state.tref =:= undefined ->
	    Reply = eth:set_active(State#state.eth, N),
	    {reply, Reply, State};
       N =:= 0 -> %% disable log
	    cancel_timer(State#state.tref),
	    eth:set_active(State#state.eth, 0),
	    flush_frames(),
	    {reply, ok, State#state { tref=undefined} };
       true -> %% using time 
	    {reply, {error,einprogress}, State}
    end;
handle_call({set_active_time,T}, _From, State) ->
    TRef = if T =:= 0 ->
		   cancel_timer(State#state.tref),
		   eth:set_active(State#state.eth, 0),
		   flush_frames(),
		   undefined;
	      true ->
		   cancel_timer(State#state.tref),
		   eth:set_active(State#state.eth, -1),
		   erlang:start_timer(T, self(), deactivate)
	   end,
    {reply, ok, State#state { tref = TRef }};
handle_call({set_filter,Filter}, _From, State) ->
    Reply = eth:set_filter(State#state.eth, Filter),
    %% flush frames from old filter. Maybe some to the new as well ..
    flush_frames(),
    {reply, Reply, State};
handle_call({set_style,Style}, _From, State) ->
    if Style =:= json;
       Style =:= yang;
       Style =:= erlang ->
	    {reply, ok, State#state { style=Style}};
       true ->
	    {reply, {error, einval}, State}
    end;
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
	    io:format("~p\n", [Data]),
	    try dump(Eth, State#state.style) of
		ok -> ok
	    catch
		error:Reason ->
		    io:format("crash: ~p\n  ~p\n", 
			      [Reason,erlang:get_stacktrace()])
	    end
    catch
	error:Reason ->
	    io:format("crash: ~p\n  ~p\n",
		      [Reason,erlang:get_stacktrace()])
    end,
    {noreply, State};
handle_info({timeout,TRef, deactivate}, State) when TRef =:= State#state.tref ->
    eth:active(State#state.eth, 0),
    flush_frames(),
    {noreply, State#state { tref = undefined }};
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

flush_frames() ->
    receive
	{eth_frame,_Port,_IfIndex,_Data} ->
	    flush_frames()
    after 0 ->
	    ok
    end.

cancel_timer(undefined) ->
    ok;
cancel_timer(TRef) ->
    erlang:cancel_timer(TRef),
    receive 
	{timeout, TRef, _} ->
	    ok
    after 0 ->
	    ok
    end.


dump(Eth, json) ->
    eth_packet:dump_json(Eth);
dump(Eth, yang) ->
    eth_packet:dump_yang(Eth);
dump(Eth, erlang) -> %% fixme add erlang record variant!
    io:format("~p\n", [Eth]).
