%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%    Random defined used in various layers of bpf
%%% @end
%%% Created :  2 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-ifndef(__ETH_DEF_HRL__).
-define(__ETH_DEF_HRL__, true).

-define(MAX_OPTIMISE, 100).

-define(U8,  1).
-define(U16, 2).
-define(U32, 4).
%%
%% Examples (remove soon)
%%
-define(ETHERTYPE_PUP,    16#0200).
-define(ETHERTYPE_IP,     16#0800).
-define(ETHERTYPE_ARP,    16#0806).
-define(ETHERTYPE_REVARP, 16#8035).
-define(ETHERTYPE_VLAN,   16#8100).
-define(ETHERTYPE_IPV6,   16#86dd).
-define(ETHERTYPE_BRIDGE, 16#88A8).
-define(ETHERTYPE_QINQ,   16#9100).


-define(ARPOP_REQUEST,  1).	%% ARP request.
-define(ARPOP_REPLY,    2).	%% ARP reply.
-define(ARPOP_RREQUEST, 3).	%% RARP request.
-define(ARPOP_RREPLY,   4).     %% RARP reply.

-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP,  6).
-define(IPPROTO_UDP,  17).
-define(IPPROTO_SCTP, 132).

-define(OFFS_ETH,        (0)).
-define(OFFS_ETH_DST,    (0)).
-define(OFFS_ETH_SRC,    (6)).
-define(OFFS_ETH_TYPE,   (6+6)).
-define(OFFS_ETH_DATA,   (6+6+2)).

-define(VLAN, 4).

-define(OFFS_VLAN_TPID,  (?OFFS_ETH_TYPE)).
-define(OFFS_VLAN_TCI,   (?OFFS_ETH_TYPE+2)).

-define(OFFS_ARP_HTYPE,  (?OFFS_ETH_DATA)).
-define(OFFS_ARP_PTYPE,  (?OFFS_ETH_DATA+2)).
-define(OFFS_ARP_HALEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_ARP_PALEN,  (?OFFS_ETH_DATA+5)).
-define(OFFS_ARP_OP,     (?OFFS_ETH_DATA+6)).

-define(OFFS_IPV4,       (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV4_HLEN,  (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV4_DSRV,  (?OFFS_ETH_DATA+1)).
-define(OFFS_IPV4_LEN,   (?OFFS_ETH_DATA+2)).
-define(OFFS_IPV4_ID,    (?OFFS_ETH_DATA+4)).
-define(OFFS_IPV4_FRAG,  (?OFFS_ETH_DATA+6)).
-define(OFFS_IPV4_TTL,   (?OFFS_ETH_DATA+8)).
-define(OFFS_IPV4_PROTO, (?OFFS_ETH_DATA+9)).
-define(OFFS_IPV4_CSUM,  (?OFFS_ETH_DATA+10)).
-define(OFFS_IPV4_SRC,   (?OFFS_ETH_DATA+12)).
-define(OFFS_IPV4_DST,   (?OFFS_ETH_DATA+16)).
-define(OFFS_IPV4_DATA,  (?OFFS_ETH_DATA+20)).

-define(OFFS_IPV6,      (?OFFS_ETH_DATA+0)).
-define(OFFS_IPV6_LEN,  (?OFFS_ETH_DATA+4)).
-define(OFFS_IPV6_NEXT, (?OFFS_ETH_DATA+6)).
-define(OFFS_IPV6_HOPC, (?OFFS_ETH_DATA+7)).
-define(OFFS_IPV6_SRC,  (?OFFS_ETH_DATA+8)).
-define(OFFS_IPV6_DST,  (?OFFS_ETH_DATA+24)).
-define(OFFS_IPV6_PAYLOAD, (?OFFS_ETH_DATA+40)).

%% Given that X contains the IP headers length
-define(OFFS_TCP_SRC_PORT, 0).  %% uint16
-define(OFFS_TCP_DST_PORT, 2).  %% uint16
-define(OFFS_TCP_SEQ,      4).  %% uint32
-define(OFFS_TCP_ACK,      8).  %% uint32
-define(OFFS_TCP_FLAGS,    12). %% Offs:4,_:6,UAPRSF:6
-define(OFFS_TCP_WINDOW,   14). %% uint16
-define(OFFS_TCP_CSUM,     16). %% uint16
-define(OFFS_TCP_UPTR,     18). %% uint16

-define(OFFS_UDP_SRC_PORT,  0).  %% uint16
-define(OFFS_UDP_DST_PORT,  2).  %% uint16
-define(OFFS_UDP_LENGTH,    4).  %% uint16
-define(OFFS_UDP_CSUM,      6).  %% uint16
-define(OFFS_UDP_DATA,      8).  

-endif.
