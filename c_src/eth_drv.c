//
// eth_drv.c
//
//

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/filter.h>
#elif defined(__APPLE__)
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#endif

#include "erl_driver.h"

#include "eth_bpf.h"

#define ATOM(NAME) am_ ## NAME
#define INIT_ATOM(NAME) am_ ## NAME = driver_mk_atom(#NAME)

// Hack to handle R15 driver used with pre R15 driver
#if ERL_DRV_EXTENDED_MAJOR_VERSION == 1
typedef int  ErlDrvSizeT;
typedef int  ErlDrvSSizeT;
#endif

#define PORT_CONTROL_BINARY

#define INT_EVENT(e) ((int)((long)(e)))

typedef struct _eth_sub_t
{
    ErlDrvTermData  pid;    // the process 
    ErlDrvMonitor   mon;    // the monitor
    int32_t         active; // packet active mode/count
    uint32_t        plen;   // program len
    uint8_t*        prog;   // BPF program (driver_alloc)
    struct _eth_sub_t* next;
} eth_sub_t;

typedef struct _eth_ctx_t
{
    ErlDrvPort  port;
    ErlDrvEvent fd;
    ErlDrvTermData owner;         // port owner
    char*       if_name;       // interface name
    int         if_index;      // interface index
    int         is_selecting;  // driver select in use
    int         nactive;       // number of active subs
    ErlDrvTermData dport;
    eth_sub_t*     first;
    void*          ibuf;
    size_t         ibuflen;
} eth_ctx_t;

#define CMD_BIND   1
#define CMD_UNBIND 2
#define CMD_ACTIVE 3
#define CMD_SETF   4
#define CMD_DEBUG  5
#define CMD_SUBF   6

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
    return ptr[0];
}

static inline int8_t get_int8(uint8_t* ptr)
{
    return (int8_t) ptr[0];
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
static void eth_drv_process_exit(ErlDrvData,ErlDrvMonitor *);
static void eth_drv_stop_select(ErlDrvEvent, void*);


ErlDrvTermData am_ok;
ErlDrvTermData am_error;
ErlDrvTermData am_undefined;
ErlDrvTermData am_true;
ErlDrvTermData am_false;
ErlDrvTermData am_eth_frame;
ErlDrvTermData am_eth_active;

#define push_atom(atm) do {			\
	message[i++] = ERL_DRV_ATOM;		\
	message[i++] = (atm);			\
    } while(0)

#define push_port(prt) do {			\
	message[i++] = ERL_DRV_PORT;		\
	message[i++] = (prt);			\
    } while(0)

#define push_pid(pid) do {			\
	message[i++] = ERL_DRV_PID;		\
	message[i++] = (pid);			\
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


static eth_sub_t** find_sub(eth_ctx_t* ctx, ErlDrvTermData pid)
{
    eth_sub_t** pptr = &ctx->first;

    while(*pptr) {
	if ((*pptr)->pid == pid)
	    return pptr;
	pptr = &(*pptr)->next;
    }
    return NULL;
}


//
// find or create a subscription record 
// setup a monitor if needed 
//
static eth_sub_t** find_or_create_sub(eth_ctx_t* ctx, ErlDrvTermData pid)
{
    eth_sub_t*  ptr;
    eth_sub_t** pptr;
    ErlDrvMonitor mon;

    if ((pptr = find_sub(ctx, pid)) != NULL)
	return pptr;
    if (driver_monitor_process(ctx->port, pid, &mon) < 0)
	return NULL;
    if ((ptr = driver_alloc(sizeof(eth_sub_t))) == NULL) {
	driver_demonitor_process(ctx->port, &mon);
	return NULL;
    }
    memset(ptr, 0, sizeof(eth_sub_t));
    ptr->pid = pid;
    ptr->mon = mon;
    ptr->next = ctx->first;
    ctx->first = ptr;
    return &ctx->first;
}


static int open_device()
{
#if defined(__linux__)
    // could select ETH_P_ARP/ETH_P_8021Q ...
    return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif defined(__APPLE__)
    int i;
    for (i = 0; i < 255; i++) {
	int fd;
	char bpfname[32];
	sprintf(bpfname, "/dev/bpf%d", i);
	if ((fd = open(bpfname, O_RDWR)) >= 0) {
	    DEBUGF("/dev/bpf%d is opened for read and write", i);
	    return fd;
	}
	else if (errno != EBUSY)
	    return -1;
    }
    errno = ENOENT;
    return -1;
#else
    errno = ENOENT;
    return -1;
#endif
}
//
// attach socket to interface
//
static int get_ifindex(int fd, const uint8_t* ifname, size_t len)
{
#if defined(__linux__)
    struct ifreq ifr;
    int    index;

    if (len >= sizeof(ifr.ifr_name)) {
	errno = EINVAL;
	return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, len);
    
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	ERRORF("iocrl error=%s", strerror(errno));
	return -1;
    }
    index = ifr.ifr_ifindex;
    DEBUGF("device %s has index %d", ifr.ifr_name, index);
    return index;
#elif defined(__APPLE__)
    // not used with bpf
    return 0;
#else
    return -1;
#endif
}

static int setup_input_buffer(eth_ctx_t* ctx)
{
#if defined(__linux__)
    ctx->ibuf    = NULL;
    ctx->ibuflen = 64*1024;
    return 0;
#elif defined(__APPLE__)
    u_int immediate = 1;
    u_int buflen = 32*1024;

    while(buflen > 0) {
	if (ioctl(INT_EVENT(ctx->fd), BIOCSBLEN, &buflen) >= 0)
	    break;
	if (errno != ENOBUFS) {
	    ERRORF("ioctl BIOCSBLEN %s", strerror(errno));
	    return -1;
	}
	buflen >>= 1;
    }
    DEBUGF("buflen used = %d", buflen);
    if (ioctl(INT_EVENT(ctx->fd), BIOCIMMEDIATE, &immediate) < 0) {
	ERRORF("ioctl BIOCIMMEDIATE %s", strerror(errno));
	return -1;
    }
    ctx->ibuf    = NULL;
    ctx->ibuflen = buflen;
    return 0;
#else
    return -1;
#endif
}

static int alloc_input_buffer(eth_ctx_t* ctx)
{
    uint buflen;
#if defined(__APPLE__)
    if (ioctl(INT_EVENT(ctx->fd), BIOCGBLEN, &buflen) < 0) {
	ERRORF("ioctl BIOCGBLEN %s", strerror(errno));
	return -1;
    }
#else
    buflen = ctx->ibuflen;
#endif
    DEBUGF("alloc_input_buffer: size=%d", buflen);
    ctx->ibuf = driver_alloc(buflen);
    ctx->ibuflen = buflen;
    return 0;
}


static int set_bpf(eth_ctx_t* ctx, uint8_t* buf, int len)
{
#if defined(__linux__)
    struct sock_fprog fcode;
    struct sock_filter* insns = (struct sock_filter*) buf;
    uint8_t* ptr = buf;
    int n = len >> 3;
    int i;
    for (i = 0; i < n; i++) {
        // inline convert to host endian
	insns[i].code = get_uint16(ptr);
	insns[i].k    = get_uint32(ptr+4);
	DEBUGF("instruction: %d  code=%04x,jt=%d,jf=%d,k=%d",
	       i, insns[i].code, insns[i].jt, insns[i].jf,
	       insns[i].k);
	ptr += 8;
    }
    fcode.len = n;
    fcode.filter = insns;
    if (setsockopt(INT_EVENT(ctx->fd), SOL_SOCKET, SO_ATTACH_FILTER,
		   &fcode, sizeof(fcode)) == -1) {
        DEBUGF("setsockopt error=%s", strerror(errno));
        return -1;
    }
    return 0;
#elif defined(__APPLE__)
    struct bpf_program prog;
    struct bpf_insn*   insns = (struct bpf_insn*) buf;
    uint8_t* ptr = buf;
    int n = len >> 3;
    int i;
    for (i = 0; i < n; i++) {
        // inline convert to host endian
	insns[i].code = get_uint16(ptr);
	insns[i].k    = get_uint32(ptr+4);
	DEBUGF("instruction: %d  code=%04x,jt=%d,jf=%d,k=%d",
	       i, insns[i].code, insns[i].jt, insns[i].jf,
	       insns[i].k);
	ptr += 8;
    }
    prog.bf_len = n;
    prog.bf_insns = insns;
    if (ioctl(INT_EVENT(ctx->fd), BIOCSETF, &prog) < 0) {
	ERRORF("ioctl BIOCSETF %s", strerror(errno));
	return -1;
    }
    return 0;
#else
    errno = EINVAL;
    retur -1;
#endif
}

static int bind_interface(eth_ctx_t* ctx)
{
#if defined(__linux__)
    struct packet_mreq mr;
    socklen_t mrlen = sizeof(mr);
    mr.mr_ifindex = ctx->if_index;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(INT_EVENT(ctx->fd), SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
		   &mr, mrlen) < 0) {
	ERRORF("setsockopt PACKET_ADD_MEMBERSHIP error=%s", strerror(errno));
	return -1;
    }
    return 0;
#elif defined(__APPLE__)
    struct ifreq ifr;
    int    len = strlen(ctx->if_name);
    u_int promisc = 1;
    u_int flush = 1;

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ctx->if_name, len);
    if (ioctl(INT_EVENT(ctx->fd), BIOCSETIF, &ifr) < 0) {
	ERRORF("ioctl BIOCSETIF error=%s", strerror(errno));
	return -1;
    }
    if (ioctl(INT_EVENT(ctx->fd), BIOCPROMISC, &promisc) < 0) {
	ERRORF("ioctl BIOCPROMISC error=%s", strerror(errno));
	return -1;
    }
    if (ioctl(INT_EVENT(ctx->fd), BIOCFLUSH, &flush) < 0) {
	ERRORF("ioctl BIOCFLUSH error=%s", strerror(errno));
	return -1;
    }
    return 0;
#else
    return -1;
#endif
}

static int unbind_interface(eth_ctx_t* ctx)
{
#if defined(__linux__)
    struct packet_mreq mr;
    socklen_t mrlen = sizeof(mr);
    mr.mr_ifindex = ctx->if_index;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(INT_EVENT(ctx->fd), SOL_PACKET, PACKET_DROP_MEMBERSHIP, 
		   &mr, mrlen) < 0) {
	ERRORF("setsockopt PACKET_DROP_MEMBERSHIP error=%s", strerror(errno));
	return -1;
    }
    return 0;
#elif defined(__APPLE__)
    // not possible with bpf ? (nor needed?)
    return 0;
#else
    return -1;
#endif
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

static int deliver_active(eth_ctx_t* ctx, ErlDrvTermData pid, int is_active)
{
    ErlDrvTermData message[16];
    int i = 0;
    // {eth_active, <port>, <pid>, <bool>}
    push_atom(ATOM(eth_active));
    push_port(ctx->dport);
    push_pid(pid);
    push_atom(is_active ? ATOM(true) : ATOM(false));
    push_tuple(4);
    return driver_send_term(ctx->port, ctx->owner, message, i);
}


static int deliver_frame(eth_ctx_t* ctx, uint8_t* p, uint32_t len)
{
    eth_sub_t* ptr;
    ErlDrvTermData message[16];
    int i = 0;
    int bpf_err;
    uint32_t bpf_err_loc;

    // {eth_frame, <port>, <index>, <data>}
    push_atom(ATOM(eth_frame));
    push_port(ctx->dport);
    push_int(ctx->if_index);
    push_bin((char*)p, len);
    push_tuple(4);

    ptr = ctx->first;
    while(ptr != NULL) {
	if (ptr->active != 0) {
	    if (eth_bpf_exec(ptr->prog, ptr->plen, p, len, 
			     &bpf_err, &bpf_err_loc)) {
		driver_send_term(ctx->port, ptr->pid, message, i);
		if (ptr->active > 0)
		    ptr->active--;
		if (ptr->active == 0) {
		    deliver_active(ctx, ptr->pid, 0);
		    ctx->nactive--;
		    if (ctx->nactive == 0) {
			if (ctx->is_selecting) {
			    driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
			    ctx->is_selecting = 0;
			}
		    }
		}
	    }
	    else if (bpf_err != ETH_BPF_OK) {
		DEBUGF("bpf_exec failed %s @%d", 
		       eth_bpf_strerr(bpf_err), bpf_err_loc);
	    }
	}
	ptr = ptr->next;
    }
    return 0;
}

static int input_frame(eth_ctx_t* ctx)
{
#if defined(__linux__)
    int n;
    if ((n = read(INT_EVENT(ctx->fd), ctx->ibuf, ctx->ibuflen)) > 0) {

	send_frame(ctx, ctx->ibuf, n);
    }
    else if (n < 0) {
	DEBUGF("input_frame recvfrom failed %s", strerror(errno));
    }
    return n;
#elif defined(__APPLE__)
    int n;
    if ((n = read(INT_EVENT(ctx->fd), ctx->ibuf, ctx->ibuflen)) > 0) {
	char* ptr = (char*) ctx->ibuf;
	char* ptr_end = ptr + n;
	while (ptr < ptr_end) {
	    struct bpf_hdr* p = (struct bpf_hdr*)  ptr;
	    char* data = ptr + p->bh_hdrlen;

	    DEBUGF("input_frame %d bytes of %d remain=%d n=%d",
		   p->bh_caplen, p->bh_datalen,
		   ptr_end - data, n);
	    
	    if ((p->bh_caplen == p->bh_datalen) &&
		(data+p->bh_caplen <= ptr_end)) {
		deliver_frame(ctx, (uint8_t*)data, p->bh_caplen);
	    }
	    ptr += BPF_WORDALIGN(p->bh_hdrlen + p->bh_caplen);
	}
    }
    else if (n < 0) {
	DEBUGF("input_frame read failed %s", strerror(errno));
    }
    return n;
#else
    return -1;
#endif
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
    INIT_ATOM(true);
    INIT_ATOM(false);
    INIT_ATOM(eth_frame);
    INIT_ATOM(eth_active);
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

    if ((fd = open_device()) < 0)
	return ERL_DRV_ERROR_ERRNO;

    if ((ctx = (eth_ctx_t*) 
	 driver_alloc(sizeof(eth_ctx_t))) == NULL) {
	close(fd);
	errno = ENOMEM;
	return ERL_DRV_ERROR_ERRNO;
    }
    memset(ctx, 0, sizeof(eth_ctx_t));
    DEBUGF("eth_drv: start (%s) fd=%d", command, fd);

    ctx->port         = port;
    ctx->dport        = driver_mk_port(port);
    ctx->owner        = driver_connected(port);
    ctx->fd           = (ErlDrvEvent)fd;
    ctx->if_index     = -1;

    if (setup_input_buffer(ctx) < 0) {
	close(fd);
	driver_free(ctx);
	return ERL_DRV_ERROR_ERRNO;
    }
    
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
    int bpf_err;
    uint32_t bpf_err_loc;

    DEBUGF("eth_drv: ctl: cmd=%u, len=%d", cmd, len);

    switch(cmd) {
    case CMD_BIND:
	if (len == 0) goto badarg;
	if ((ctx->if_index = get_ifindex(INT_EVENT(ctx->fd), buf, len)) < 0)
	    goto error;
	ctx->if_name = driver_alloc(len+1);
	memcpy(ctx->if_name, buf, len);
	ctx->if_name[len] = '\0';
	if (bind_interface(ctx) < 0)
	    goto error;
	if (alloc_input_buffer(ctx) < 0)
	    goto error;
	goto ok;

    case CMD_UNBIND:
	if (len != 0) goto badarg;
	if (ctx->if_index >= 0) {
	    if (unbind_interface(ctx) < 0)
		goto error;
	    ctx->if_index = -1;
	    if (ctx->is_selecting) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		ctx->is_selecting = 0;
	    }
	}
	goto ok;
	    
	// Global filter
    case CMD_SETF: {  // N*<<code:16,jt:8,jl:8,k:32>>
	if ((len & 7) != 0) goto badarg;  // must be multiple of 8
	if (set_bpf(ctx, buf, len) < 0)
	    goto error;
	goto ok;
    }

	// Set local active
    case CMD_ACTIVE: { // <<n:32/signed>>
	eth_sub_t** pptr;
	eth_sub_t* ptr;
	int32_t active;
	if (len != 4) 
	    goto badarg;
	if (ctx->if_index < 0) 
	    goto badarg;
	if ((pptr = find_or_create_sub(ctx, driver_caller(ctx->port)))==NULL) {
	    errno = ENOMEM;
	    goto error;
	}
	ptr = *pptr;
	active = ptr->active;
	ptr->active = get_int32(buf);

	if ((active == 0) && (ptr->active != 0)) {
	    deliver_active(ctx, ptr->pid, 1);
	    ctx->nactive++;
	    if (!ctx->is_selecting) {
		driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 1);
		ctx->is_selecting = 1;
	    }
	}
	else if ((active != 0) && (ptr->active == 0)) {
	    deliver_active(ctx, ptr->pid, 0);
	    ctx->nactive--;
	    if (ctx->nactive == 0) { // disable
		if (ctx->is_selecting) {
		    driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		    ctx->is_selecting = 0;
		}
	    }
	}
	goto ok;
    }

	// Create or update subscription
    case CMD_SUBF: {
	eth_sub_t** pptr;
	eth_sub_t* ptr;
	uint8_t* prog;
	uint32_t plen;
	if ((len & 7) != 0) // must be multiple of 8
	    goto badarg;
	if (len == 0)
	    prog = NULL;
	else if ((prog = driver_alloc(len)) == NULL)
	    goto error;
	plen = len >> 3;
	if (!eth_bpf_validate(buf, prog, plen, &bpf_err, &bpf_err_loc)) {
	    driver_free(prog);
	    goto bpf_error;
	}
	if ((pptr=find_or_create_sub(ctx, driver_caller(ctx->port)))==NULL) {
	    if (prog)
		driver_free(prog);
	    errno = ENOMEM;
	    goto error;
	}
	ptr = *pptr;
	if (ptr->prog != NULL)
	    driver_free(ptr->prog);
	ptr->prog = prog;
	ptr->plen = plen;
	goto ok;
    }

    case CMD_DEBUG: {
	if (len != 1) goto badarg;
	debug_level = get_int8(buf);
	goto ok;
    }
    default:
	goto badarg;
    }
	
ok:
    return ctl_reply(0, NULL, 0, rbuf, rsize);
badarg:
    errno = EINVAL;
error: {
    char* err_str = erl_errno_id(errno);
    return ctl_reply(255, err_str, strlen(err_str), rbuf, rsize);
}
bpf_error: {
    char* err_str = eth_bpf_strerr(bpf_err);
    return ctl_reply(254, err_str, strlen(err_str), rbuf, rsize);
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

    DEBUGF("eth_drv: ready_input called nactive = %d", ctx->nactive);

    if (ctx->fd == e)
	input_frame(ctx);
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

static void eth_drv_process_exit(ErlDrvData d, ErlDrvMonitor *mon)
{
    eth_ctx_t* ctx = (eth_ctx_t*) d;
    ErlDrvTermData pid;
    pid = driver_get_monitored_process(ctx->port, mon);
    if (pid != driver_term_nil) {
	eth_sub_t** pptr = find_sub(ctx, pid);
	if (pptr != NULL) {
	    eth_sub_t* ptr = *pptr;
	    *pptr = ptr->next;
	    if (ptr->active != 0) {
		deliver_active(ctx, ptr->pid, 0);
		ctx->nactive--;
		if (ctx->nactive == 0) {
		    driver_select(ctx->port, ctx->fd, ERL_DRV_READ, 0);
		    ctx->is_selecting = 0;
		}
	    }
	    if (ptr->prog)
		driver_free(ptr->prog);
	    driver_free(ptr);
	}
    }
}

DRIVER_INIT(eth_drv)
{
    ErlDrvEntry* ptr = &eth_drv_entry;

    DEBUGF("eth DRIVER_INIT");

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
    ptr->process_exit = eth_drv_process_exit;
    ptr->stop_select = eth_drv_stop_select;
    return ptr;
}
