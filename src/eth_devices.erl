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
-export([set_filter/3, get_address/1]).
-export([get_list/0, i/0]).

%% direct api from eth
-export([send/2, set_active/2, set_filter/2]).

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
	  name = ""    :: string(),
	  hwaddr = ""  :: ethernet_address(),
	  subs = []    :: [#subscriber{}],
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

%%
%% Try open an interface 
%%
open(Interface) ->
    gen_server:call(?SERVER, {open, Interface}).

%%
%% Close an open interface
%%
close(Interface) ->
    gen_server:call(?SERVER, {close, Interface}).

%%
%% Find port for an interface
%%
find(Interface) ->
    gen_server:call(?SERVER, {find, Interface}).

%%
%% Get the hardware of an interface
%%
get_address(Interface) ->
    gen_server:call(?SERVER, {get_address, Interface}). 

%%
%% Get interface list on form: [{Name,Addr,Port}]
%%
get_list() ->
    gen_server:call(?SERVER, get_list).

%%
%% List ethernet device information
%%
i() ->
    lists:foreach(
      fun({Name,Addr,_Port}) ->
	      io:format("~10s ~s\n", [Name, eth_packet:ethtoa(Addr)])
      end, get_list()).

%%
%% Set filter for process Pid.
%%
set_filter(Interface, Pid, Filter) when
      (is_list(Interface) orelse is_port(Interface)),
      is_pid(Pid), is_binary(Filter) ->
    gen_server:call(?SERVER, {set_filter,Interface,Pid,Filter}).

%% 
%% Set interface port debugging level
%%
debug(Interface, Level)  when is_atom(Level) ->
    gen_server:call(?SERVER, {set_debug,Interface,level(Level)}).

%%
%% Send frame data
%%
send(Port, Data) when is_port(Port), is_binary(Data) ->
    erlang:port_command(Port, Data).

%%
%% Set direct active flag, this is per process (caller in this case)
%% handle by eth_drv.
%%
set_active(Port, N) when is_port(Port), is_integer(N), N >= -1 ->
    call(Port, ?CMD_ACTIVE, <<N:32/signed-integer>>).

%% Set direct filter for this process and initiate setting of
%% the global filter.
%%
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
    {ok,IFs} = inet:getifaddrs(),
    %% fixme: subscriber to netlink events, when interfaces are
    %% added and removed!
    Ds = [#device { name=Name,
		    hwaddr=proplists:get_value(hwaddr,Fs,[])
		  } || {Name,Fs} <- IFs ],
    {ok, #state{ devices = Ds }}.

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
    case lists:keytake(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error,enoent}, State};
	{value,D,Ds} ->
	    if is_port(D#device.port) ->
		    {reply, {ok,D#device.port}, State};
	       true ->
		    Driver = "eth_drv",
		    try erlang:open_port({spawn_driver, Driver},[binary]) of
			Port ->
			    case call(Port, ?CMD_BIND, Name) of
				ok ->
				    D1 = D#device { port=Port },
				    %% inform subscriber that interface is open?
				    %% re-set the filter ...
				    Ds1 = [D1 | Ds],
				    {reply, {ok,Port}, 
				     State#state { devices=Ds1 }};
				Error ->
				    erlang:port_close(Port),
				    {reply, Error, State}
			    end
		    catch
			error:Reason ->
			    {reply, {error,Reason}, State}
		    end
	    end
    end;
handle_call({close,Name}, _From, State) ->
    case lists:keytake(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error,enoent}, State};
	{value,D,Ds} ->
	    case call(D#device.port, ?CMD_UNBIND, Name) of
		ok ->
		    erlang:port_close(D#device.port),
		    D1 = D#device { port=undefined },
		    %% inform subscriber that interface is closed?
		    Ds1 = [D1 | Ds],
		    {reply, ok, State#state { devices = Ds1 }};
		Error ->
		    erlang:port_close(D#device.port),
		    D1 = D#device { port=undefined },
		    %% inform subscriber that interface is closed?
		    Ds1 = [D1 | Ds],
		    {reply, Error, State#state { devices = Ds1 }}
	    end
    end;
handle_call({set_debug,Name,Level}, _From, State) ->
    case lists:keyfind(Name, #device.name, State#state.devices) of
	false ->
	    {reply, {error, enoent}, State};
	D when is_port(D#device.port) ->
	    Reply = call(D#device.port, ?CMD_DEBUG, [Level]),
	    {reply, Reply, State};
	_ ->
	    {reply, {error, ebadfd}, State}
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
handle_call({get_address,Name}, _From, State) ->
    case lists:keyfind(Name, #device.name, State#state.devices) of
	false -> 
	    {reply, {error, enoent}, State};
	D -> 
	    {reply, {ok,D#device.hwaddr}, State}
    end;
handle_call(get_list, _From, State) ->
    {reply, [{Name,Addr,Port} || 
		#device { name=Name, hwaddr=Addr, port=Port} <- 
		    State#state.devices], State};

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


update_filter(D) when is_port(D#device.port) ->
    Filter = combine_filter(D#device.subs),
    call(D#device.port, ?CMD_SETF, Filter);
update_filter(undefined) ->
    {error,ebadfd}.

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
