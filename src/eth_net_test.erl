%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Test setup eth_net
%%% @end
%%% Created : 25 Aug 2014 by Tony Rogvall <tony@rogvall.se>

-module(eth_net_test).

-export([setup/0,setup/1]).
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

-define(TEST_MSS, 512).

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
%%
%% linux:
%%     iptables -A FORWARD -i eth0 -o tap0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
%%     iptables -A FORWARD -i tap0 -o tap0 -m state --state ESTABLISHED,RELATED -j ACCEPT
%%
%%     iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 192.168.1.1
%%     sudo sysctl -w net.ipv4.ip_forward=1
%%


%% run as root!
test1() ->
    setup(ip),
    Net = init(),
    tcp_accept(Net).

test2() ->
    setup(ip),
    Net = init(),
    {ok,L} = gen_tcp:listen(6668, [{ifaddr,{192,168,10,1}},
				   {mode,binary},
				   {reuseaddr,true},{active,true}]),
    spawn(fun() -> test_gen_server(L) end),
    tcp_connect(Net).

test3() ->
    test_www("www.google.com", "/index.html").

%% www.erlang.org = {192,121,151,107}
test4() ->
    test_www({192,121,151,107}, "/download/otp_src_17.1.readme").

run4(Net) ->
    run_www(Net, {192,121,151,107}, "/download/otp_src_17.1.readme").

test5() ->
    test_www("www.erlang.org", "/download/otp_doc_man_17.1.tar.gz").

run5(Net) ->
    run_www(Net,"www.erlang.org", "/download/otp_doc_man_17.1.tar.gz").


test_www(Host,Path) ->
    test_www(Host,80,Path).

test_www(Host,Port,Path) ->
    setup(gw),
    Net = init(),
    run_www(Net,Host,Port,Path).

run_www(Net,Host,Path) ->
    run_www(Net,Host,80,Path).

run_www(Net,Host,Port,Path) ->
    DstIp = if is_tuple(Host) -> Host;
	       true ->
		    {ok,#hostent { h_addr_list = [Dst|_] }} =
			inet:gethostbyname(Host),
		    Dst
	    end,
    File = filename:basename(Path),
    case file:open(File, [write]) of
	{ok, Fd} ->
	    Res = (catch http_download(Net,DstIp,Port,Path,Fd)),
	    file:close(Fd),
	    Res;
	Error ->
	    Error
    end.

gen() ->
    {ok,L} = gen_tcp:listen(6668, [{ifaddr,{192,168,10,1}},
				   {mode,binary},
				   {reuseaddr,true},{active,true}]),
    {ok,S} = gen_tcp:accept(L),
    io:format("gen: got accept\n"),
    gen_tcp:close(L),
    gen_tcp_server(S).

test_gen_server(L) ->
    io:format("test_gen_server: wait for client\n"),
    {ok,S} = gen_tcp:accept(L),
    io:format("test_gen_server: got accept\n"),
    gen_tcp:close(L),
    gen_tcp_client(S).


%% run once to setup tap device
setup() -> setup(ip).
setup(Type) ->
    application:ensure_all_started(eth),
    case eth_devices:find("tap0") of
	{error,enoent} -> %% fixme: eth_device should handle this better?
	    case eth_devices:open("tap") of
		{ok,Port} ->
		    {ok,Tap} = eth_devices:get_name(Port),
		    setup(os:type(),Tap,Type);
		Error ->
		    Error
	    end;
	{ok,_Port} ->
	    ok
    end.

setup(_, Tap, ip) ->
    inet:ifset(Tap, [{addr,{192,168,10,1}}, {flags,[up]}]);
setup({_,darwin}, Tap, gw) ->
    Bridge = "bridge0",
    command(["ifconfig", Bridge, "addm",Tap]).

command(Args) ->
    Command = string:join(Args, " "),
    io:format("execute: ~s\n", [Command]),
    R = os:cmd(Command),
    io:format("result: ~s\n", [R]).

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
    eth_net:dump(Net),
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

http_download(Net,Dst,DstPort,Path,Fd) ->
    random:seed(erlang:now()),
    SrcPort = 57000 + random:uniform(1000),  %% fixme!
    {ok,S} = eth_net:tcp_connect(Net,{192,168,10,10},SrcPort,
				 Dst,DstPort,[{mss,?TEST_MSS},
					      {send_mss,?TEST_MSS}]),
    receive
	{tcp_connected,S,IP,Port} ->
	    io:format("connected to ~s:~w\n",
		      [eth_net:format_ip_addr(IP), Port]),
	    HttpRequest=["GET "++Path++" HTTP/1.0",?CRNL,
			 %% "Connection: close",?CRNL,
			 ?CRNL],
	    RequestRef = make_ref(),
	    eth_net:tcp_send(Net,S,[list_to_binary(HttpRequest),RequestRef]),
	    io:format("send request: ~s\n", [HttpRequest]),
	    eth_sink(Net, {IP,Port}, Path, S, Fd);
	{tcp_closed,S} ->
	    io:format("connection failed: closed\n", []),
	    eth_net:tcp_close(Net,S)
    after 10000 ->
	    io:format("connection failed: timeout\n", []),
	    eth_net:tcp_close(Net,S)
    end.


eth_sink(Net, Remote, Path, S, Fd) ->
    receive
	{tcp,S,Message} ->
	    io:format("got tcp message ~p\n",[Message]),
	    file:write(Fd, Message),
	    ?MODULE:eth_sink(Net, Remote, Path, S, Fd);
	{tcp_closed,S} ->
	    io:format("test_tcp_loop: got closed, closing\n", []),
	    eth_net:tcp_close(Net, S),
	    {ok, Net};
	{tcp_event,S,Event} ->
	    io:format("tcp_loop: GOT EVENT ~w\n", [Event]),
	    ?MODULE:eth_sink(Net, Remote, Path, S, Fd);
	Message ->
	    io:format("tcp_loop: got message: ~p\n", [Message]),
	    ?MODULE:eth_sink(Net, Remote, Path, S, Fd)
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
		[<<"close">>] ->
		    eth_net:tcp_send(Net, S, <<"ok\r\n">>),
		    eth_net:tcp_shutdown(Net, S),
		    ?MODULE:eth_tcp_server(Net, Remote, S);
		[<<"get ",File/binary>>] ->
		    case file:read_file(File) of
			{ok,Bin} ->
			    eth_net:tcp_send(Net,S,tohex32(byte_size(Bin))),
			    eth_net:tcp_send(Net,S,Bin),
			    ?MODULE:eth_tcp_server(Net,Remote,S);
			{error,Error} ->
			    Atm=atom_to_binary(Error,latin1),
			    eth_net:tcp_send(Net,S,
					     <<"error ",Atm/binary,"\r\n">>),
			    ?MODULE:eth_tcp_server(Net,Remote,S)
		    end;
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
    gen_tcp:send(S, <<"close\r\n">>), %% application level close
    gen_close_loop(S).

%% tcp_loop but for gen_tcp.

gen_tcp_server(S) ->
    receive
	{tcp,S,Message} ->
	    io:format("gen_tcp_server: got tcp message ~p\n",[Message]),
	    case binary:split(Message, <<"\r\n">>, [global,trim]) of
		[<<"ping">>] ->
		    gen_tcp:send(S, <<"pong\r\n">>),
		    ?MODULE:gen_tcp_server(S);
		[<<"close">>] ->
		    gen_tcp:send(S, <<"ok\r\n">>),
		    gen_tcp:shutdown(S, write),
		    ?MODULE:gen_tcp_server(S);
		[<<"get ",File/binary>>] ->
		    case file:read_file(File) of
			{ok,Bin} ->
			    gen_tcp:send(S,tohex32(byte_size(Bin))),
			    gen_tcp:send(S,Bin),
			    ?MODULE:gen_tcp_server(S);
			{error,Error} ->
			    Atm=atom_to_binary(Error,latin1),
			    gen_tcp:send(S, <<"error",Atm/binary,"\r\n">>),
			    ?MODULE:gen_tcp_server(S)
		    end;
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

%% return integer as 8 digit binary hex.
tohex32(Size) when is_integer(Size), Size >= 0 ->
    Size32 = Size band 16#ffffffff,
    list_to_binary(tl(integer_to_list(16#100000000+Size32,16))).


gen_close_loop(S) ->
    receive
	{tcp_closed,S} ->
	    io:format("gen_tcp_server: got closed, closing\n", []),
	    gen_tcp:close(S),
	    ok;
	{tcp,S,Data} ->
	    io:format("gen_close_lopo: data=~w\n", [Data]),
	    ?MODULE:gen_close_loop(S);
	Message ->
	    io:format("gen_close_loop: got message: ~p\n", [Message]),
	    ?MODULE:gen_close_loop(S)
    after 5000 ->
	    io:format("gen_close_loop: timeout\n", []),
	    gen_tcp:close(S),
	    ok
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
		<<"close">> ->
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
