//
// eth_drv.c
//
// usage: sed 's/eth/foo/g' template_drv.c > foo_drv.c
//

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#endif

#include "erl_driver.h"
// #include "dthread.h"

#define ATOM(NAME) am_ ## NAME
#define INIT_ATOM(NAME) am_ ## NAME = driver_mk_atom(#NAME)

// Hack to handle R15 driver used with pre R15 driver
#if ERL_DRV_EXTENDED_MAJOR_VERSION == 1
typedef int  ErlDrvSizeT;
typedef int  ErlDrvSSizeT;
#endif

#define PORT_CONTROL_BINARY

#define INT_EVENT(e) ((int)((long)(e)))

typedef struct _eth_ctx_t
{
    ErlDrvPort  port;
    ErlDrvEvent fd;
    char*       if_name;       // interface name
    int         if_index;      // interface index
    int         is_selecting;  // driver select in use
    int         active;        // number of packets remain to process
    ErlDrvTermData dport;
    ErlDrvTermData target;
} eth_ctx_t;

#define CMD_BIND   1
#define CMD_UNBIND 2
#define CMD_ACTIVE 3

static inline uint32_t get_uint32(uint8_t* ptr)
{
    uint32_t value = (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | (ptr[3]<<0);
    return value;
}

static inline int32_t get_int32(uint8_t* ptr)
{
    uint32_t value = (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | (ptr[3]<<0);
    return (int32_t) value;
}

static inline uint16_t get_uint16(uint8_t* ptr)
{
    uint16_t value = (ptr[0]<<8) | (ptr[1]<<0);
    return value;
}

static inline uint8_t get_uint8(uint8_t* ptr)
{
    uint8_t value = (ptr[0]<<0);
    return value;
}

static inline void put_uint16(uint8_t* ptr, uint16_t v)
{
    ptr[0] = v>>8;
    ptr[1] = v;
}

static inline void put_uint32(uint8_t* ptr, uint32_t v)
{
    ptr[0] = v>>24;
    ptr[1] = v>>16;
    ptr[2] = v>>8;
    ptr[3] = v;
}


static int  eth_drv_init(void);
static void eth_drv_finish(void);
static void eth_drv_stop(ErlDrvData);
static void eth_drv_output(ErlDrvData, char*, ErlDrvSizeT);
static void eth_drv_ready_input(ErlDrvData, ErlDrvEvent);
static void eth_drv_ready_output(ErlDrvData data, ErlDrvEvent event);
static ErlDrvData eth_drv_start(ErlDrvPort, char* command);
static ErlDrvSSizeT eth_drv_ctl(ErlDrvData,unsigned int,char*,ErlDrvSizeT,char**, ErlDrvSizeT);
static void eth_drv_timeout(ErlDrvData);
static void eth_drv_stop_select(ErlDrvEvent, void*);

ErlDrvTermData am_ok;
ErlDrvTermData am_error;
ErlDrvTermData am_undefined;
ErlDrvTermData am_eth_frame;

#define push_atom(atm) do {			\
	message[i++] = ERL_DRV_ATOM;		\
	message[i++] = (atm);			\
    } while(0)

#define push_port(prt) do {			\
	message[i++] = ERL_DRV_PORT;		\
	message[i++] = (prt);			\
    } while(0)

#define push_bin(buf,len) do {			\
	message[i++] = ERL_DRV_BUF2BINARY;	\
	message[i++] = (ErlDrvTermData)(buf);	\
	message[i++] = (ErlDrvTermData)(len);	\
    } while(0)

#define push_nil() do {			\
	message[i++] = ERL_DRV_NIL;	\
    } while(0)

#define push_string(str) do {			\
	message[i++] = ERL_DRV_STRING;		\
	message[i++] = (ErlDrvTermData) (str);	\
	message[i++] = strlen(str);		\
    } while(0)

#define push_int(val) do {			\
	message[i++] = ERL_DRV_INT;		\
	message[i++] = (val);			\
    } while(0)

#define push_tuple(n) do {			\
	message[i++] = ERL_DRV_TUPLE;		\
	message[i++] = (n);			\
    } while(0)

#define push_list(n) do {			\
	message[i++] = ERL_DRV_LIST;		\
	message[i++] = (n);			\
    } while(0)


static ErlDrvEntry eth_drv_entry;

#define DLOG_DEBUG     7
#define DLOG_INFO      6
#define DLOG_NOTICE    5
#define DLOG_WARNING   4
#define DLOG_ERROR     3
#define DLOG_CRITICAL  2
#define DLOG_ALERT     1
#define DLOG_EMERGENCY 0
#define DLOG_NONE     -1

#ifndef DLOG_DEFAULT
#define DLOG_DEFAULT DLOG_NONE
#endif

#define DLOG(level,file,line,args...) do {				\
	if (((level) == DLOG_EMERGENCY) ||				\
	    ((debug_level >= 0) && ((level) <= debug_level))) {		\
	    int save_errno = errno;					\
	    emit_log((level),(file),(line),args);			\
	    errno = save_errno;						\
	}								\
    } while(0)

#define DEBUGF(args...) DLOG(DLOG_DEBUG,__FILE__,__LINE__,args)
#define INFOF(args...)  DLOG(DLOG_INFO,__FILE__,__LINE__,args)
#define NOTICEF(args...)  DLOG(DLOG_NOTICE,__FILE__,__LINE__,args)
#define WARNINGF(args...)  DLOG(DLOG_WARNING,__FILE__,__LINE__,args)
#define ERRORF(args...)  DLOG(DLOG_ERROR,__FILE__,__LINE__,args)
#define CRITICALF(args...)  DLOG(DLOG_CRITICAL,__FILE__,__LINE__,args)
#define ALERTF(args...)  DLOG(DLOG_ALERT,__FILE__,__LINE__,args)
#define EMERGENCYF(args...)  DLOG(DLOG_EMERGENCY,__FILE__,__LINE__,args)

static int debug_level = DLOG_DEFAULT;

static void emit_log(int level, char* file, int line, ...)
{
    va_list ap;
    char* fmt;

    if ((level == DLOG_EMERGENCY) ||
	((debug_level >= 0) && (level <= debug_level))) {
	va_start(ap, line);
	fmt = va_arg(ap, char*);
	fprintf(stderr, "%s:%d: ", file, line); 
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\r\n");
	va_end(ap);
    }
}

/* general control reply function */
static ErlDrvSSizeT ctl_reply(int rep, char* buf, ErlDrvSizeT len,
			      char** rbuf, ErlDrvSizeT rsize)
{
    char* ptr;

    if ((len+1) > rsize) {
#ifdef PORT_CONTROL_BINARY
	ErlDrvBinary* bin = driver_alloc_binary(len+1);
	if (bin == NULL) 
	    return -1;
	ptr = bin->orig_bytes;	
	*rbuf = (char*) bin;
#else
	if ((ptr = driver_alloc(len+1)) == NULL)
	    return -1;
	*rbuf = ptr;
#endif
    }
    else
	ptr = *rbuf;
    *ptr++ = rep;
    memcpy(ptr, buf, len);
    return len+1;
}

//
// attach socket to interface
//
static int get_ifindex(int fd, const uint8_t* ifname, size_t len)
{
    struct ifreq ifr;
    int    index;

    memset(&ifr, 0, sizeof(ifr));
    if (len >= sizeof(ifr.ifr_name))
	len = sizeof(ifr.ifr_name)-1;
    memcpy(ifr.ifr_name, ifname, len);
    
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	ERRORF("iocrl error=%s", strerror(errno));
	return -1;
    }
    index = ifr.ifr_ifindex;
    DEBUGF("device %s has index %d", ifr.ifr_name, index);
    return index;
}

static int add_membership(eth_ctx_t* ctx)
{
    struct packet_mreq mr;
    socklen_t mrlen = sizeof(mr);
    mr.mr_ifindex = ctx->if_index;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(INT_EVENT(ctx->fd), SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
		   &mr, mrlen) < 0) {
	ERRORF("ioctl error=%s", strerror(errno));
	return -1;
    }
    return 0;
}

static int drop_membership(eth_ctx_t* ctx)
{
    struct packet_mreq mr;
    socklen_t mrlen = sizeof(mr);
    mr.mr_ifindex = ctx->if_index;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(INT_EVENT(ctx->fd), SOL_PACKET, PACKET_DROP_MEMBERSHIP, 
		   &mr, mrlen) < 0) {
	ERRORF("ioctl error=%s", strerror(errno));
	return -1;
    }
    return 0;
}

//
// Send an ARP_PACKET
//
#if 0 
static void make_arp_packet(eth_ctx_t* ctx)
{
    const uint8_t ether_broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    struct sockaddr_ll addr = {0};

    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex  = ctx->if_index;
    addr.sll_halen    = ETHER_ADDR_LEN;

    memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);
}
#endif

static int input_frame(eth_ctx_t* ctx)
{
    char buffer[2048];
    int n;
    if ((n = recvfrom(INT_EVENT(ctx->fd), buffer, 2048, 0, NULL, NULL)) > 0) {
	ErlDrvTermData message[16];
	int i = 0;
	DEBUGF("input_frame %d bytes", n);
	// {eth_frame, <port>, <index>, <data>}
	push_atom(ATOM(eth_frame));
	push_port(ctx->dport);
	push_int(ctx->if_index);
	push_bin(buffer, n);
	push_tuple(4);
	driver_send_term(ctx->port, ctx->target, message, i);
    }
    else if (n < 0) {
	DEBUGF("input_frame failed %s", strerror(errno));
    }
    return n;
}

// setup global object area
// load atoms etc.

static int eth_drv_init(void)
{
    debug_level = DLOG_DEFAULT;
    DEBUGF("eth_driver_init");
    INIT_ATOM(ok);
    INIT_ATOM(error);
    INIT_ATOM(undefined);
    INIT_ATOM(eth_frame);
    return 0;
}

// clean up global stuff
static void eth_drv_finish(void)
{
}

static ErlDrvData eth_drv_start(ErlDrvPort port, char* command)
{
    (void) command;
    eth_ctx_t* ctx;
    int fd;

    // could select ETH_P_ARP/ETH_P_8021Q ...
    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	return ERL_DRV_ERROR_ERRNO;

    if ((ctx = (eth_ctx_t*) 
	 driver_alloc(sizeof(eth_ctx_t))) == NULL) {
	errno = ENOMEM;
	return ERL_DRV_ERROR_ERRNO;
    }
    DEBUGF("eth_drv: start (%s) fd=%d", command, fd);

    ctx->port         = port;
    ctx->dport        = driver_mk_port(port);
    ctx->target       = driver_caller(port);
    ctx->fd           = (ErlDrvEvent)fd;
    ctx->if_index     = -1;
    ctx->if_name      = NULL;
    ctx->is_selecting = 0;
    ctx->active       = 0;
    
#ifdef PORT_CONTROL_BINARY
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
#endif
    return (ErlDrvData) ctx;
}

static void eth_drv_stop(ErlDrvData d)
{
    eth_ctx_t* ctx = (eth_ctx_t*) d;

    DEBUGF("eth_drv: stop");

    if (ctx->is_selecting)
	driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
    if (ctx->if_name != NULL)
	driver_free(ctx->if_name);
    driver_select(ctx->port, ctx->fd, ERL_DRV_USE, 0);
    driver_free(ctx);
}

static ErlDrvSSizeT eth_drv_ctl(ErlDrvData d, 
				unsigned int cmd, char* buf0, ErlDrvSizeT len,
				char** rbuf, ErlDrvSizeT rsize)
{
    uint8_t* buf = (uint8_t*) buf0;
    eth_ctx_t* ctx = (eth_ctx_t*) d;

    DEBUGF("eth_drv: ctl: cmd=%u, len=%d", cmd, len);

    switch(cmd) {
    case CMD_BIND:
	if (len == 0) goto badarg;
	if ((ctx->if_index = get_ifindex(INT_EVENT(ctx->fd), buf, len)) < 0)
	    goto error;
	ctx->if_name = driver_alloc(len+1);
	memcpy(ctx->if_name, buf, len);
	ctx->if_name[len] = '\0';
	// FIXME: add_membership or bind (support old linux?)
	if (add_membership(ctx) < 0)
	    goto error;
	goto ok;

    case CMD_UNBIND:
	if (len != 0) goto badarg;
	if (ctx->if_index >= 0) {
	    if (drop_membership(ctx) < 0)
		goto error;
	    ctx->if_index = -1;
	    if (ctx->is_selecting) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		ctx->is_selecting = 0;
	    }
	}
	goto ok;
	    
    case CMD_ACTIVE:  // <<n:32/signed>>
	if (len != 4) goto badarg;
	if (ctx->if_index < 0) goto badarg;
	ctx->active = get_int32(buf);
	if (ctx->active == 0) { // disable
	    if (ctx->is_selecting) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		ctx->is_selecting = 0;
	    }
	}
	else { // enable
	    if (!ctx->is_selecting) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 1);
		ctx->is_selecting = 1;
	    }
	}
	goto ok;
    default:
	goto badarg;
    }
	
ok:
    return ctl_reply(0, NULL, 0, rbuf, rsize);
badarg:
    errno = EINVAL;
error:
    {
        char* err_str = erl_errno_id(errno);
	return ctl_reply(255, err_str, strlen(err_str), rbuf, rsize);
    }
}


static void eth_drv_output(ErlDrvData d, char* buf, ErlDrvSizeT len)
{
    (void) d;
    (void) buf;
    (void) len;
    // eth_ctx_t*   ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: output");
}

static void eth_drv_outputv(ErlDrvData d, ErlIOVec *ev)
{
    (void) d;
    (void) ev;
//  eth_ctx_t*   ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: outputv");
}

static void eth_drv_event(ErlDrvData d, ErlDrvEvent e,
				  ErlDrvEventData ed)
{
    (void) d;
    (void) e;
    (void) ed;
//  eth_ctx_t* ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: event called");
}

static void eth_drv_ready_input(ErlDrvData d, ErlDrvEvent e)
{
    eth_ctx_t* ctx = (eth_ctx_t*) d;

    DEBUGF("eth_drv: ready_input called active = %d", ctx->active);

    if (ctx->fd == e) {
	if (input_frame(ctx) < 0)
	    return;
	if (ctx->active > 0) {
	    ctx->active--;
	    if (ctx->active == 0) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		ctx->is_selecting = 0;
	    }
	}
    }
}

static void eth_drv_ready_output(ErlDrvData d, ErlDrvEvent e)
{
    (void) d;
    (void) e;
//  eth_ctx_t* ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: ready_output called");
}

// operation timed out
static void eth_drv_timeout(ErlDrvData d)
{
    (void) d;
    DEBUGF("eth_drv: timeout");
}

static void eth_drv_stop_select(ErlDrvEvent event, void* arg)
{    
    (void) arg;
    DEBUGF("eth_drv: stop_select event=%d", INT_EVENT(event));
    close(INT_EVENT(event));
}

DRIVER_INIT(eth_drv)
{
    ErlDrvEntry* ptr = &eth_drv_entry;

    DEBUGF("eth driver_init");

    ptr->driver_name = "eth_drv";
    ptr->init  = eth_drv_init;
    ptr->start = eth_drv_start;
    ptr->stop  = eth_drv_stop;
    ptr->output = eth_drv_output;
    ptr->ready_input  = eth_drv_ready_input;
    ptr->ready_output = eth_drv_ready_output;
    ptr->finish = eth_drv_finish;
    ptr->control = eth_drv_ctl;
    ptr->timeout = eth_drv_timeout;
    ptr->outputv = eth_drv_outputv;
    ptr->ready_async = 0;
    ptr->flush = 0;
    ptr->call = 0;
    ptr->event = eth_drv_event;
    ptr->extended_marker = ERL_DRV_EXTENDED_MARKER;
    ptr->major_version = ERL_DRV_EXTENDED_MAJOR_VERSION;
    ptr->minor_version = ERL_DRV_EXTENDED_MINOR_VERSION;
    ptr->driver_flags = ERL_DRV_FLAG_USE_PORT_LOCKING;
    ptr->process_exit = 0;
    ptr->stop_select = eth_drv_stop_select;
    return ptr;
}
