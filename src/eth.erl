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

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 
-define(ETH_PORT, eth_port).

-define(CMD_BIND,    1).
-define(CMD_UNBIND,  2).
-define(CMD_ACTIVE,  3).
-define(CMD_SETF,    4).

-record(state, 
	{
	  port
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
    {ok, #state{ port=Port }}.

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
    Eth = enet_eth:decode(Data, [nolookup]),
    io:format("eth: ~p\n", [Eth]),
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
