#pragma once

#include <ev/conf.h>
#include <ev.h>

#include <linux/stat.h>
#include <liburing.h>
#include <sys/socket.h>

typedef enum {
	EVI_URING_NONE,
	EVI_URING_OPEN,
	EVI_URING_STAT,
	EVI_URING_RW,
	EVI_URING_ACCEPT,
	EVI_URING_CONNECT,
	EVI_URING_WAIT,

	// Special, used for eventfd signals
	EVI_URING_USR,
	EVI_URING_TIMEOUT,
} ev_async_type_t;

typedef struct {
	void *ticket;
	ev_async_type_t type;
	union {
		ev_handle_t *phnd;
		size_t *pn;
		struct {
			ev_stat_t *pres;
			struct statx buff;
		} stat;
		struct {
			ev_handle_t *pres;
			ev_server_t *pserv_res;
			ev_addr_t *paddr;
			uint16_t *pport;

			struct sockaddr_storage addr;
			socklen_t len;
		} accept;
		struct {
			int sock;
			ev_handle_t *pres;
		} connect;
		struct {
			int *pcode;
			int *psig;
			siginfo_t buff;
		} wait;
		char usr[8];
	};
} *ev_async_udata_t, ev_async_udata_s;

typedef struct ev_async {
	struct io_uring ctx;
	int usermsg_fd;
	ev_async_udata_s usermsg_read_udata[1];
} *ev_async_t, ev_async_s;
