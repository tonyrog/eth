#@BEGIN-C_SRC-DEFAULT-RULES@
ERL=$(shell readlink -f `which erl`)
ERL_TOP=$(ERL:%/bin/erl=%)
OS=$(shell uname -s)
CFLAGS=-MMD -MP -MF .$<.d -I$(ERL_TOP)/usr/include
#@END-C_SRC-DEFAULT-RULES@

APP=eth
CFLAGS+=-std=c99 -Wall -O3 -DDEBUG_MEM -DDLOG_DEFAULT=DLOG_NONE
LDFLAGS+=-shared

OBJS = eth_bpf.o eth_drv.o
LIBS = 

all: ../priv/$(APP)_drv.so

../priv/$(APP)_drv.so: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o ../priv/$(APP)_nif.so

%.o:	%.c
	$(CC) $(CFLAGS) -c -fPIC $<

.%.d:	;

-include .*.d
