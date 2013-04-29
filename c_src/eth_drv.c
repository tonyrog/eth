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
    ErlDrvPort port;
} eth_ctx_t;

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

#define DLOG(level,file,line,args...) do { \
	if (((level) == DLOG_EMERGENCY) ||				\
	    ((debug_level >= 0) && ((level) <= debug_level))) { \
	    emit_log((level),(file),(line),args);		\
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


// setup global object area
// load atoms etc.

static int eth_drv_init(void)
{
    debug_level = DLOG_DEFAULT;
    DEBUGF("eth_driver_init");
    INIT_ATOM(ok);
    INIT_ATOM(error);
    INIT_ATOM(undefined);
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

    if ((ctx = (eth_ctx_t*) 
	 driver_alloc(sizeof(eth_ctx_t))) == NULL) {
	errno = ENOMEM;
	return ERL_DRV_ERROR_ERRNO;
    }
    DEBUGF("eth_drv: start (%s)", command);
#ifdef PORT_CONTROL_BINARY
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
#endif
    return (ErlDrvData) ctx;
}

static void eth_drv_stop(ErlDrvData d)
{
    eth_ctx_t* ctx = (eth_ctx_t*) d;
    // add structure cleanup here
    driver_free(ctx);
}

static ErlDrvSSizeT eth_drv_ctl(ErlDrvData d, 
				   unsigned int cmd, char* buf, ErlDrvSizeT len,
				   char** rbuf, ErlDrvSizeT rsize)
{
//    eth_ctx_t* ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: ctl: cmd=%u, len=%d", 
	   cmd, len);
    return ctl_reply(1, "hello", 5, rbuf, rsize);
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
    (void) d;
    (void) e;
//  eth_ctx_t* ctx = (eth_ctx_t*) d;
    DEBUGF("eth_drv: ready_input called");
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
