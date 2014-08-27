%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Test setup eth_net
%%% @end
%%% Created : 25 Aug 2014 by Tony Rogvall <tony@rogvall.se>

-module(eth_net_test).

-export([setup/0]).
-export([init/0]).
-export([udp/1]).
-export([tcp_accept/1]).
-export([tcp_connect/1]).

-include_lib("kernel/include/inet.hrl").

-compile(export_all).

-define(CRNL, "\r\n").

%% linux define TCP_MIN_MSS as 88 (strange why?) a lot of stange ideas
%% and magic on the internet :-)
%% -define(TCP_TINY_MSS, 88). %% MSS used for testing. (10=timestamp,4=data)
%% Mac os x has minmss = 270, mssdflt = 512
%% use sysctl -a | grep mss to find out

-define(TEST_MSS, 64). %% 270 works

%% routing tapx packets with nat etc
%% make sure ip forwarding is enabled:
%%
%%  <ext> = en0 | en1 | eth0 ..
%%  <tap> = tap0 ...
%% macosx:
%%    /usr/sbin/natd -interface <ext>
%%    /sbin/ipfw -f flush
%%    /sbin/ipfw add divert natd all from any to any via <ext>
%%    /sbin/ipfw add pass all from any to any
%%    sudo sysctl -w net.inet.ip.forwarding=1
%%
%% linux:
%%     iptables -A FORWARD -i eth0 -o tap0 -m state --state ESTABLISHED,RELATED -j ACCEPT
%%     iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 192.168.1.1
%%     sudo sysctl -w net.ipv4.ip_forward=1
%%


%% run as root!
test1() ->
    setup(),
    Net = init(),
    tcp_accept(Net).

test2() ->
    setup(),
    Net = init(),
    {ok,L} = gen_tcp:listen(6668, [{ifaddr,{192,168,10,1}},
				   {mode,binary},
				   {reuseaddr,true},{active,true}]),
    spawn(fun() -> test_gen_server(L) end),
    tcp_connect(Net).

test_www(Host,Path) ->
    setup(),
    {ok,#hostent { h_addr_list = [Dst|_] }} = inet:gethostbyname(Host),
    Net = init(),
    http_download(Net,Dst,80,Path).

gen() ->
    {ok,L} = gen_tcp:listen(6668, [{ifaddr,{192,168,10,1}},
				   {mode,binary},
				   {reuseaddr,true},{active,true}]),
    {ok,S} = gen_tcp:accept(L),
    io:format("test_gen_server: got accept\n"),
    gen_tcp:close(L),
    gen_tcp_server(S).

test_gen_server(L) ->
    io:format("test_gen_server: wait for client\n"),
    {ok,S} = gen_tcp:accept(L),
    io:format("test_gen_server: got accept\n"),
    gen_tcp:close(L),
    gen_tcp_client(S).


%% run once to setup tap device
setup() ->
    application:ensure_all_started(eth),
    case eth_devices:find("tap0") of
	{error,enoent} -> %% fixme: eth_device should handle this better?
	    case eth_devices:open("tap") of
		{ok,Port} ->
		    {ok,Tap} = eth_devices:get_name(Port),
		    inet:ifset(Tap, [{addr,{192,168,10,1}}, {flags,[up]}]);
		Error ->
		    Error
	    end;
	{ok,_Port} ->
	    ok
    end.

%% run this to start | when net crashed.
init() ->
    {ok,Net} = eth_net:start("tap0"),
    eth_net:add_ip(Net, {192,168,10,10}, {1,2,3,4,5,6}),
    eth_net:query_mac(Net, {192,168,10,1}), %% force caching
    eth_net:set_gw(Net, {192,168,10,1}),
    io:format("tap0 up and running in 5s\n"),
    timer:sleep(5000),
    Net.

tcp_accept(Net) ->
    {ok,L} = eth_net:tcp_listen(Net, {192,168,10,10}, 6668, 
				[{mss,?TEST_MSS},{send_mss,?TEST_MSS}]),
    {ok,S} = eth_net:tcp_accept(Net, L),
    io:format("enter eth_tcp_server\n"),
    eth_tcp_server(Net, undefined, S).

tcp_connect(Net) ->
    eth_net:query_mac(Net, {192,168,10,1}), %% force caching
    timer:sleep(100),
    random:seed(erlang:now()),
    SrcPort = 57000 + random:uniform(1000),  %% fixme!
    {ok,S} = eth_net:tcp_connect(Net,
				 {192,168,10,10},SrcPort,
				 {192,168,10,1},6668,[{mss,?TEST_MSS},
						      {send_mss,?TEST_MSS}]),
    io:format("enter eth_tcp_server\n"),
    eth_tcp_server(Net, undefined, S).

http_download(Net,Dst,DstPort,Path) ->
    random:seed(erlang:now()),
    SrcPort = 57000 + random:uniform(1000),  %% fixme!
    {ok,S} = eth_net:tcp_connect(Net,{192,168,10,10},SrcPort,
				 Dst,DstPort,[{mss,?TEST_MSS},
					      {send_mss,?TEST_MSS}]),
    HttpRequest=["GET "++Path++" HTTP/1.1",?CRNL,
		 "Connection: close",?CRNL,
		 ?CRNL],
    RequestRef = make_ref(),
    eth_net:tcp_send(Net,S,[list_to_binary(HttpRequest),RequestRef]),
    io:format("send request: ~s\n", [HttpRequest]),
    eth_sink(Net, undefined, S).

eth_sink(Net, Remote, S) ->
    receive
	{tcp_connected,S,IP,Port} ->
	    io:format("connection from ~s:~w\n",
		      [eth_net:format_ip_addr(IP), Port]),
	    ?MODULE:eth_sink(Net, {IP,Port}, S);
	{tcp,S,Message} ->
	    io:format("got tcp message ~p\n",[Message]),
	    ?MODULE:eth_sink(Net, Remote, S);
	{tcp_closed,S} ->
	    io:format("test_tcp_loop: got closed, closing\n", []),
	    eth_net:tcp_close(Net, S),
	    {ok, Net};
	{tcp_event,S,Event} ->
	    io:format("tcp_loop: got event ~w\n", [Event]),
	    ?MODULE:eth_sink(Net, Remote, S);
	Message ->
	    io:format("tcp_loop: got message: ~p\n", [Message]),
	    ?MODULE:eth_sink(Net, Remote, S)
    end.



eth_tcp_server(Net, Remote, S) ->
    receive
	{tcp_connected,S,IP,Port} ->
	    io:format("connection from ~s:~w\n",
		      [eth_net:format_ip_addr(IP), Port]),
	    ?MODULE:eth_tcp_server(Net, {IP,Port}, S);
	{tcp,S,Message} ->
	    io:format("got tcp message ~p\n",[Message]),
	    case binary:split(Message, <<"\r\n">>, [global,trim]) of
		[<<"ping">>] ->
		    eth_net:tcp_send(Net, S, <<"pong\r\n">>),
		    ?MODULE:eth_tcp_server(Net, Remote, S);
		[<<"stop">>] ->
		    eth_net:tcp_send(Net, S, <<"ok\r\n">>),
		    eth_net:tcp_shutdown(Net, S),
		    ?MODULE:eth_tcp_server(Net, Remote, S);
		_ ->
		    eth_net:tcp_send(Net, S, <<"error\r\n">>),
		    ?MODULE:eth_tcp_server(Net, Remote, S)
	    end;
	{tcp_closed,S} ->
	    io:format("test_tcp_loop: got closed, closing\n", []),
	    eth_net:tcp_close(Net, S),
	    {ok, Net};
	{tcp_event,S,Event} ->
	    io:format("tcp_loop: got event ~w\n", [Event]),
	    ?MODULE:eth_tcp_server(Net, Remote, S);
	Message ->
	    io:format("tcp_loop: got message: ~p\n", [Message]),
	    ?MODULE:eth_tcp_server(Net, Remote, S)
    end.

gen_tcp_client(S) ->
    gen_tcp:send(S, <<"ping\r\n">>), %% pong
    receive
	{tcp,S,Data} -> io:format("client got: ~s\n", [Data])
    after 1000 ->
	    io:format("client got nothing\n", [])
    end,
    D500 = <<"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789">>,
    gen_tcp:send(S, <<"echo ", D500/binary, "\r\n">>),  %% error
    receive
	{tcp,S,Data1} -> io:format("client got: ~s\n", [Data1])
    after 1000 ->
	    io:format("client got nothing\n", [])
    end,
    gen_tcp:send(S, <<"stop\r\n">>),
    receive
	{tcp,S,Data2} -> io:format("client got: ~s\n", [Data2]);
	{tcp_closed,S} -> io:format("client got: closed\n", [])
    after 1000 ->
	    io:format("client got nothing\n", [])
    end,
    gen_tcp:close(S).

%% tcp_loop but for gen_tcp.

gen_tcp_server(S) ->
    receive
	{tcp,S,Message} ->
	    io:format("gen_tcp_server: got tcp message ~p\n",[Message]),
	    case binary:split(Message, <<"\r\n">>, [global,trim]) of
		[<<"ping">>] ->
		    gen_tcp:send(S, <<"pong\r\n">>),
		    ?MODULE:gen_tcp_server(S);
		[<<"stop">>] ->
		    gen_tcp:send(S, <<"ok\r\n">>),
		    gen_tcp:shutdown(S, write),
		    ?MODULE:gen_tcp_server(S);
		_ ->
		    gen_tcp:send(S, <<"error\r\n">>),
		    ?MODULE:gen_tcp_server(S)
	    end;
	{tcp_closed,S} ->
	    io:format("gen_tcp_server: got closed, closing\n", []),
	    gen_tcp:close(S),
	    ok;
	Message ->
	    io:format("gen_tcp_server: got message: ~p\n", [Message]),
	    ?MODULE:gen_tcp_server(S)
    end.


udp(Net) ->
    {ok,U} = eth_net:udp_open(Net, {192,168,10,10}, 6666, []),
    udp_loop(Net, U).

udp_loop(Net, U) ->
    receive
	{udp,U,IP,Port,Message} ->
	    case Message of
		<<"ping">> ->
		    eth_net:udp_send(Net, U, IP, Port, <<"pong">>),
		    ?MODULE:udp_loop(Net, U);
		<<"stop">> ->
		    eth_net:udp_send(Net, U, IP, Port, <<"ok">>),
		    eth_net:close(Net, U),
		    {ok,Net};
		_ ->
		    eth_net:udp_send(Net, U, IP, Port, <<"error">>),
		    ?MODULE:udp_loop(Net, U)
	    end;
	Message ->
	    io:format("test_udp_loop: got message: ~p\n", [Message]),
	    ?MODULE:udp_loop(Net, U)
    end.
