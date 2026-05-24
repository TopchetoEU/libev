#pragma once

// Utility for poll-like (poll-ish) interfaces. The gist is that with this interface (unlike uring),
// you will be notified that you can perform a certain IO operation without being blocked.

// You must implement all _impl stuff. Define EVI_POLL_ACCEPT if a socket becomes readable when it can accept()

#include <ev/conf.h>
#include <ev/errno.h>
#include <ev.h>

#include <stdint.h>

typedef enum {
	EVI_POLL_READ = 0x01,
	EVI_POLL_PREAD = 0x02,
	EVI_POLL_ACCEPT = 0x03,
	EVI_POLL_WRITE = 0x11,
	EVI_POLL_PWRITE = 0x12,
} ev_pl_type_t;

typedef struct {
	ev_pl_type_t type;
	void *ticket;
	int fd;
	union {
		struct { char *data; size_t *pn; size_t offset; } rw;
		struct { ev_handle_t *pres; ev_addr_t *paddr; uint16_t *pport; } accept;
	};
} ev_pl_event_t;

typedef struct {
	void *ticket;
	ev_code_t err;
} ev_pl_msg_t;

typedef enum {
	EV_POLL_TIMEOUT = -1,
	EV_POLL_EMPTY,
	EV_POLL_OK,
} ev_pl_res_t;

typedef struct {
	int usermsg_read, usermsg_write;
} *ev_pl_t, ev_pl_s;

static bool evi_pl_cb(ev_t ev, const ev_pl_event_t *evn, void **pticket, ev_code_t *perr);

ev_code_t ev_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n);
ev_code_t ev_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n);
ev_code_t ev_file_read(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset);
ev_code_t ev_file_write(ev_t ev, void *ticket, ev_handle_t fd, char *buff, size_t *n, size_t offset);
ev_code_t ev_server_accept(ev_t ev, void *udata, ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server);

static ev_code_t evi_pl_impl_init(ev_t ev);
static ev_code_t evi_pl_impl_free(ev_t ev);
static ev_code_t evi_pl_impl_add(ev_t ev, ev_pl_event_t evn);
static ev_pl_res_t evi_pl_impl_poll(ev_t ev, const ev_time_t *timeout, void **pticket, ev_code_t *perr);

// typedef struct ev_poll_req {
// 	struct ev_poll_req **slot;
// 	struct ev_poll_req *next;
// 	size_t pollfd_i;
// 	void *ticket;
// 	ev_async_type_t type;
// 	int fd;
// 	union {
// 		struct { char *data; size_t *pn; size_t offset; } rw;
// 	};
// } *ev_poll_req_t;
