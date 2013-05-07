%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2013, Tony Rogvall
%%% @doc
%%%     BPF instruction codes
%%% @end
%%% Created :  2 May 2013 by Tony Rogvall <tony@rogvall.se>

-ifndef(__BPF_HRL__).
-define(__BPF_HRL__, true).
%%
%% The instruction encodings.
%% <<_:5,Class:3>>
%%
%% instruction classes 
-define(BPF_CLASS(Code), ((Code) band 16#07)).
-define(BPF_LD,		16#00).
-define(BPF_LDX,	16#01).
-define(BPF_ST,		16#02).
-define(BPF_STX,	16#03).
-define(BPF_ALU,	16#04).
-define(BPF_JMP,	16#05).
-define(BPF_RET,	16#06).
-define(BPF_MISC,	16#07).

%% ld/ldx fields
%%  <<_:3,Size:2,Class:3>>
-define(BPF_SIZE(Code),	((Code) band 16#18)).
-define(BPF_W, 16#00).
-define(BPF_H, 16#08).
-define(BPF_B, 16#10).

%% <<Mode:3,Size:2,Class:3>>
-define(BPF_MODE(Code), ((Code) band 16#e0)).
-define(BPF_IMM, 16#00).
-define(BPF_ABS, 16#20).
-define(BPF_IND, 16#40).
-define(BPF_MEM, 16#60).
-define(BPF_LEN, 16#80).
-define(BPF_MSH, 16#a0).

%% alu/jmp fields
%% <<Mode:4,Src:1,Class:3>>
-define(BPF_OP(Code), ((Code) band 16#f0)).
-define(BPF_ADD, 16#00).
-define(BPF_SUB, 16#10).
-define(BPF_MUL, 16#20).
-define(BPF_DIV, 16#30).
-define(BPF_OR,  16#40).
-define(BPF_AND, 16#50).
-define(BPF_LSH, 16#60).
-define(BPF_RSH, 16#70).
-define(BPF_NEG, 16#80).
-define(BPF_JA,  16#00).
-define(BPF_JEQ, 16#10).
-define(BPF_JGT, 16#20).
-define(BPF_JGE, 16#30).
-define(BPF_JSET, 16#40).

-define(BPF_SRC(Code), ((Code) band 16#08)).
-define(BPF_K, 16#00).
-define(BPF_X, 16#08).

%% ret - BPF_K and BPF_X also apply
%% <<_:3,RVal:2,Class:3>>
-define(BPF_RVAL(Code), ((Code) band 16#18)).
-define(BPF_A, 16#10).

%% misc
%% <<Op:1, _:4, Class:3>>
-define(BPF_MISCOP(Code), ((Code) band 16#f8)).
-define(BPF_TAX, 16#00).
-define(BPF_TXA, 16#80).

-type uint8_t() :: 16#00..16#ff.
-type uint16_t() :: 16#0000..16#ffff.
-type uint32_t() :: 16#00000000..16#ffffffff.

%%
%% The instruction data structure.
%%
-record(bpf_insn,
	{
	  code = 0 :: uint16_t(),
	  jt   = 0 :: uint8_t(),
	  jf   = 0 :: uint8_t(),
	  k    = 0 :: uint32_t()
	}).

-record(bpf_block,
	{
	  label = 0  :: uint32_t(),    %% could be anything
	  insns = [] :: [#bpf_insn{}], %% non jump code
	  next       :: #bpf_insn{}    %% jmp/ret instruction 
	}).

%% 
%% Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
%%
-define(BPF_MEMWORDS, 16).

-endif.
