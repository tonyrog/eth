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
-export([start_link/0, stop/1]).
-export([bind/2, unbind/1, active/2, set_filter/2]).
-export([debug/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

%% -define(ETH_PORT, eth_port).

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

-record(subscriber,
	{
	  pid   :: pid(),
	  mon   :: reference(),
	  filter :: binary()
	}).

-record(state, 
	{
	  port :: port(),
	  subs = [] :: [#subscriber{}]
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
    gen_server:start_link(?MODULE, [], []).

bind(Pid, Name) ->
    gen_server:call(Pid, {bind,Name}).

unbind(Pid) ->
    gen_server:call(Pid, unbind).

%%
%% Active or deactive frame reception
%% The caller will be the new message receptor
%%
active(Pid, N) when N >= -1 ->
    gen_server:call(Pid, {active,self(),N}).

set_filter(Pid, Prog) when is_tuple(Prog) ->
    Filter = eth_bpf:encode(Prog),
    gen_server:call(Pid, {set_filter,self(),Filter}).

stop(Pid) ->
    gen_server:call(Pid, stop).

debug(Pid, Level) when is_atom(Level) ->
    gen_server:call(Pid, {debug, level(Level)}).

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
    %% true = erlang:register(?ETH_PORT, Port),
    {ok, #state{ port=Port, 
		 subs=[] }}.

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
handle_call({active,Caller,N}, _From, State) ->
    Reply = call(State#state.port, ?CMD_ACTIVE, <<N:32/signed-integer>>),
    State1 = update_subscription(State, Caller, N =/= 0, <<>>),
    {reply, Reply, State1};
handle_call({set_filter,Caller,BinFilter}, _From, State) ->
    case call(State#state.port, ?CMD_SETF, BinFilter) of
	ok ->
	    State1 = update_subscription(State, Caller, true, BinFilter),
	    {reply, ok, State1};
	Error ->
	    {reply, Error, State}
    end;
handle_call({debug,Level}, _From, State) ->
    Reply = call(State#state.port, ?CMD_DEBUG, [Level]),
    {reply, Reply, State};    
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
handle_info(Frame={eth_frame,Port,_IfIndex,_Data}, State) when 
      Port =:= State#state.port ->
    lists:foreach(
      fun(S) ->
	      %% Fixme: apply subscriber filter (push into driver!!!)
	      S#subscriber.pid ! Frame
      end, State#state.subs),
    {noreply, State};
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
terminate(_Reason, State) ->
    erlang:port_close(State#state.port),
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

update_subscription(State, Pid, true, Filter) ->
    case lists:keytake(Pid, #subscriber.pid, State#state.subs) of
	false ->
	    Mon = erlang:monitor(process, Pid),
	    S = #subscriber { pid = Pid, mon = Mon, filter = Filter },
	    Subs = [S | State#state.subs],
	    State#state { subs = Subs };
	{value,S0,Subs1} ->
	    S = S0#subscriber { filter = Filter },
	    Subs = [S | Subs1],
	    State#state { subs = Subs }
    end;
update_subscription(State, Pid, false, _Filter) ->
    case lists:keytake(Pid, #subscriber.pid, State#state.subs) of
	false ->
	    State;
	{value,S0,Subs1} ->
	    erlang:demonitor(S0#subscriber.mon, [flush]),
	    State#state { subs = Subs1 }
    end.
    

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
