%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%     Test of various filters
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(eth_bpf_test).

-compile(export_all).

test1() ->
    eth_bpf:build_programx({'&&', ["ether.type.ip", "ip.proto.tcp",
			   {'==',"ip.frag",0},
			   "ip.tcp.flag.syn",
			   "ip.tcp.flag.ack"]}).

test2() ->
    eth_bpf:build_programx({'||', 
			    {'&&', ["ether.type.ip", "ip.proto.tcp",
				    {'==',"ip.frag",0},
				    "ip.tcp.flag.syn",
				    "ip.tcp.flag.ack"]},
			    {'&&', ["ether.type.ip", "ip.proto.tcp",
				    {'==',"ip.frag",0},
				    "ip.tcp.flag.fin",
				    "ip.tcp.flag.ack"]}}).

test3() ->
    eth_bpf:build_program_list(
      [{'&&', ["ether.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 14}
	      ]},
       
       {'&&', ["ether.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 15}
	      ]},

       {'&&', ["ether.type.ip",
	       {'==', "ip.src[0]", 192},
	       {'==', "ip.src[1]", 16}
	      ]},

       {'&&', ["ether.type.ip",
	       {'==', "ip.src[0]", 239},
	       {'==', "ip.src[1]", 17}
	      ]},

       {'&&', ["ether.type.ip",
	       {'==', "ip.src[0]", 235}
	      ]},

       {'&&', ["ether.type.ip", "ip.src.10.13.75.100"]},
       {'&&', ["ether.type.ip", "ip.src.10.13.75.101"]},
       {'&&', ["ether.type.ip", "ip.src.10.13.75.102"]},
       {'&&', ["ether.type.ip6",
	       "ip6.src.fd6b:9860:79f5:ae8c:600b:8ea1:fbf9:807"]},
       {'&&', ["ether.type.ip6",
	       "ip6.src.fd6b:9860:79f5:ae8c:600b:8ea1:fbf9:808"]}
      ]).


test4() ->
    eth_bpf:build_programx(
      {'&&',["ether.type.ip",
	     "ip.proto.udp",
	     {'||',
	      ["ip.src.1.2.3.4",
	       "ip.src.1.2.3.12",
	       "ip.src.1.2.3.14",
	       "ip.src.1.2.3.23",
	       "ip.src.1.2.3.100",
	       "ip.src.1.2.3.103",
	       "ip.src.1.2.3.111",
	       "ip.src.1.2.3.115",
	       "ip.src.1.2.3.117",
	       "ip.src.1.2.3.119"
	      ]}]}).

test41() ->
    eth_bpf:build_programx(
      {'||',
       [{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.4"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.12"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.14"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.23"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.100"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.103"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.111"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.115"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.117"]},
	{'&&',["ether.type.ip","ip.proto.udp",   "ip.src.1.2.3.119"]}
       ]}).

test51() ->
    eth_bpf:build_programx(
      {'&&',
       ["ether.type.ip",
	"ip.src.192.168.1.16..192.168.1.32"
	%% "ip.src.192.168.2.0/24"
       ]}).

test52() ->
    eth_bpf:build_programx(	 
      {'&&', 
       ["ether.type.ip6",
	"ip6.src.0:1:0:2:0:3:192.168.1.16..0:1:0:2:0:3:192.168.1.32"
	%% "ip6.src.1::5:6:192.168.2.0/120"
       ]}).

%% should be same as port.53!
test53() ->
    eth_bpf:build_programx(
      {'||',
       [{'&&',["ether.type.ip",
	       "ip.proto.tcp",
	       "ip.tcp.src_port.53",
	       "ip.tcp.dst_port.53"]},
	{'&&',["ether.type.ip",
	       "ip.proto.udp",
	       "ip.udp.src_port.53",
	       "ip.udp.dst_port.53"]},
	{'&&',["ether.type.ip6",
	       "ip6.proto.tcp",
	       "ip6.tcp.src_port.53",
	     "ip6.tcp.dst_port.53"]},
	{'&&',["ether.type.ip6",
	       "ip6.proto.udp",
	       "ip6.udp.src_port.53",
	       "ip6.udp.dst_port.53"]}]}).

test6() ->
    eth_bpf:build_programx(
      {'&&', ["ether.type.ip",
	      "ip.host.192.168.1.103"]}).

test_http_get() ->
    eth_bpf:build_programx(
      {'&&',
       ["ether.type.ip","ip.proto.tcp", {'==',"ip.frag",0},
	"ip.tcp.flag.psh",
	{memeq, "ip.tcp.data", <<"GET ">>}
       ]}).

test_teclo_profile() ->
    eth_bpf:build_program_list(
      [  {'&&', ["vlan", "ether.type.ip", "ip.src.41.0.0.228" ]},
	 {'&&', ["vlan",
		 "ether.type.ip",
		 {'||', ["ip.src.41.185.26.72",
			 "ip.src.117.121.243.78",
			 "ip.src.159.253.209.38",
			 "ip.src.188.40.129.212",

			 "ip.dst.41.185.26.72",
			 "ip.dst.117.121.243.78",
			 "ip.dst.159.253.209.38",
			 "ip.dst.188.40.129.212"

			]}]},
	 {'&&', ["vlan",
		 "ether.type.ip",
		 {'||', ["ip.src.10.188.0.0/18",
			 "ip.src.10.194.0.0/18",

			 "ip.dst.10.188.0.0/18",
			 "ip.dst.10.194.0.0/18"

			]}]},
	 {'||', [ {'&&', ["ether.type.ip", "ip.proto.tcp"]},
		  {'&&', ["vlan",
			  "ether.type.ip", "ip.proto.tcp"]}
		]}
      ]).

test_teclo_optimise() ->
    eth_bpf:build_program_list(
      [ 
	%% "vlan and host "41.0.0.228"
	{'&&', ["vlan",
		"ether.type.ip",
		"ip.host.41.0.0.228"]},

	%% "vlan (?tcp) and ((dst port 45373) or (src portrange 50000-59999))",
	{'&&', ["vlan",
		"ether.type.ip",
		"ip.proto.tcp",
		{'||',
		 "ip.tcp.dst_port.45373",
		 "ip.tcp.src_port.50000..59999"}
	       ]},
	%%  (ip[12]+ip[13]+ip[14]+ip[15]) & 1 == ((src rem 255) & 1) ???
	%% "(vlan and ((ip[12]+ip[13]+ip[14]+ip[15]) & 1) == 1) ",
	{'&&', ["vlan",
		"ether.type.ip",
		{'==', 
		 {'&', 
		  {'+', [ "ip[12]", "ip[13]", "ip[14]", "ip[15]" ] }, 1}, 1}
	       ]},
	%% "tcp"
	{'&&', ["ether.type.ip", "ip.proto.tcp"]}
      ]).


test_contrack() ->
    eth_bpf:build_programx(
      {'||', 
       [connect_filter(),
	disconnect_filter(),
	reset_filter()
       ]}).

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


