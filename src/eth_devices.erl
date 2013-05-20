%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%    Ethernet device server
%%% @end
%%% Created : 18 May 2013 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(eth_devices).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([open/1, close/1, find/1, debug/2]).
-export([set_filter/3]).

%% direct api from eth
-export([set_active/2, set_filter/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("enet/include/enet_types.hrl").

-define(SERVER, ?MODULE).

-record(subscriber,
	{
	  pid   :: pid(),
	  mon   :: reference(),
	  active = false :: boolean(),
	  filter = <<>>  :: binary()
	}).

-record(device,
	{
	  name = "" :: string(),
	  subs = [] :: [#subscriber{}],
	  port :: undefined | port()
	}).

-record(state, 
	{
	  devices = [] :: [#device{}]
	}).

-define(CMD_BIND,    1).
-define(CMD_UNBIND,  2).
-define(CMD_ACTIVE,  3).
-define(CMD_SETF,    4).
-define(CMD_DEBUG,   5).
-define(CMD_SUBF,    6).

-define(DLOG_DEBUG,     7).
-define(DLOG_INFO,      6).
-define(DLOG_NOTICE,    5).
-define(DLOG_WARNING,   4).
-define(DLOG_ERROR,     3).
-define(DLOG_CRITICAL,  2).
-define(DLOG_ALERT,     1).
-define(DLOG_EMERGENCY, 0).
-define(DLOG_NONE,     -1).

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

open(Interface) ->
    gen_server:call(?SERVER, {open, Interface}).

close(Interface) ->
    gen_server:call(?SERVER, {close, Interface}).

find(Interface) ->
    gen_server:call(?SERVER, {find, Interface}).

set_filter(Interface, Pid, Filter) when
      (is_list(Interface) orelse is_port(Interface)),
      is_pid(Pid), is_binary(Filter) ->
    gen_server:call(?SERVER, {set_filter,Interface,Pid,Filter}).

debug(Interface, Level)  when is_atom(Level) ->
    gen_server:call(?SERVER, {set_debug,Interface,level(Level)}).

%% direct port access
set_active(Port, N) when is_port(Port), is_integer(N), N >= -1 ->
    call(Port, ?CMD_ACTIVE, <<N:32/signed-integer>>).

%% direct set filter 
set_filter(Port, Filter) when is_port(Port), is_binary(Filter) ->
    case call(Port, ?CMD_SUBF, Filter) of
	ok ->
	    %% set the global filter (combine all filters)
	    gen_server:call(?SERVER, {set_filter,Port,self(),Filter});
	Error ->
	    Error
    end.

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
    {ok, #state{}}.

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
handle_call({find,Name}, _From, State) ->
    case lists:keyfind(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error, enoent}, State};
	D ->
	    {reply, {ok, D#device.port}, State}
    end;
handle_call({open,Name}, _From, State) ->
    case lists:keyfind(Name, #device.name, State#state.devices) of
	false ->
	    Driver = "eth_drv",
	    Port = erlang:open_port({spawn_driver, Driver},[binary]),
	    case call(Port, ?CMD_BIND, Name) of
		ok ->
		    D = #device { name=Name, port=Port },
		    Ds = [D | State#state.devices],
		    {reply, {ok,Port}, State#state { devices = Ds }};
		Error ->
		    erlang:port_close(Port),
		    {reply, Error, State}
	    end;
	D ->
	    {reply, {ok,D#device.port}, State}
    end;
handle_call({close,Name}, _From, State) ->
    case lists:keytake(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error,enoent}, State};
	{value,D,Ds} ->
	    case call(D#device.port, ?CMD_UNBIND, Name) of
		ok ->
		    erlang:port_close(D#device.port),
		    {reply, ok, State#state { devices = Ds }};
		Error ->
		    erlang:port_close(D#device.port),
		    {reply, Error, State#state { devices = Ds }}
	    end
    end;
handle_call({set_debug,Name,Level}, _From, State) ->
    case lists:keyfind(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error, enoent}, State};
	D ->
	    Reply = call(D#device.port, ?CMD_DEBUG, [Level]),
	    {reply, Reply, State}
    end;
handle_call({set_filter,Port,Pid,Filter}, _From, State) when is_port(Port) ->
    case lists:keytake(Port, #device.port, State#state.devices) of
	false ->
	    {reply, {error, enoent}, State};
	{value,D,Ds} ->
	    D1 = update_subscription(D, Pid, Filter),
	    Result = update_filter(D1),
	    {reply, Result, State#state { devices = [D1|Ds] }}
    end;
handle_call({set_filter,Name,Pid,Filter}, _From, State) when is_list(Name) ->
    case lists:keytake(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error, enoent}, State};
	{value,D,Ds} ->
	    D1 = update_subscription(D, Pid, Filter),
	    Result = update_filter(D1),
	    {reply, Result, State#state { devices = [D1|Ds] }}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, bad_call}, State}.

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
handle_info(_Info={'DOWN',_Ref,process,Pid,_Reason}, State) ->
    io:format("handle_info: ~p\n", [_Info]),
    Ds = [delete_subscription(D,Pid) || D <- State#state.devices],
    {noreply, State#state { devices = Ds }};
handle_info(_Info={eth_active,Port,Pid,Active}, State) ->
    io:format("handle_info: ~p\n", [_Info]),
    %% signal if subscription is active or inactive
    case lists:keytake(Port, #device.port, State#state.devices) of
	false ->
	    {noreply, State};
	{value,Device,Ds} ->
	    case lists:keytake(Pid, #subscriber.pid, Device#device.subs) of
		false ->
		    if Active ->
			    Mon = erlang:monitor(process, Pid),
			    S = #subscriber { pid = Pid, mon = Mon,
					      active = true },
			    Subs = [S | Device#device.subs],
			    Device1 = Device#device { subs = Subs },
			    update_filter(Device1),
			    Ds1 = [Device1 | Ds],
			    {noreply, State#state { devices = Ds1 }};
		       true ->
			    {noreply, State}
		    end;
		{value,S,Subs0} ->
		    S1 = S#subscriber { active = Active },
		    Subs = [S1 | Subs0],
		    Device1 = Device#device { subs = Subs },
		    update_filter(Device1),
		    Ds1 = [Device1 | Ds],
		    {noreply, State#state { devices = Ds1 }}
	    end
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

call(Port, Cmd, Data) ->
    case erlang:port_control(Port, Cmd, Data) of
	<<0>> ->
	    ok;
	<<255,E/binary>> -> 
	    {error, erlang:binary_to_atom(E, latin1)};
	<<254,E/binary>> -> 
	    {error, binary_to_list(E)};
	<<1,Y>> -> {ok,Y};
	<<2,Y:16/native-unsigned>> -> {ok, Y};
	<<4,Y:32/native-unsigned>> -> {ok, Y};
	<<3,Return/binary>> -> {ok,Return}
    end.

delete_subscription(Device, Pid) ->
    case lists:keytake(Pid, #subscriber.pid, Device#device.subs) of
	false ->
	    Device;
	{value,S0,Subs1} ->
	    erlang:demonitor(S0#subscriber.mon, [flush]),
	    Device1 = Device#device { subs = Subs1 },
	    update_filter(Device1),
	    Device1
    end.

update_subscription(Device, Pid, Filter) ->
    case lists:keytake(Pid, #subscriber.pid, Device#device.subs) of
	false ->
	    Mon = erlang:monitor(process, Pid),
	    S = #subscriber { pid = Pid, mon = Mon, active = false,
			      filter = Filter },
	    Subs = [S | Device#device.subs],
	    Device#device { subs = Subs };
	{value,S0,Subs1} ->
	    S = S0#subscriber { filter = Filter },
	    Subs = [S | Subs1],
	    Device#device { subs = Subs }
    end.


update_filter(Device) ->
    Filter = combine_filter(Device#device.subs),
    call(Device#device.port, ?CMD_SETF, Filter).

combine_filter(Subs) ->
    Fs = [S#subscriber.filter || S <- Subs, S#subscriber.active],
    eth_bpf:join(Fs).


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
