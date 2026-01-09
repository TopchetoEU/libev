#pragma once

#include "ev/conf.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct ev *ev_t;

// An integer, identifying a logical task.
// ev_poll will return this + an error code, and a callee
// will use the ticket to identify what request it is associated to
// A value of 0 is considered invalid
typedef size_t ev_ticket_t;

// Used to deploy a sync workload in an ev-managed thread
typedef int (*ev_worker_t)(void *pargs);

typedef struct ev_fd *ev_fd_t;
typedef struct ev_dir *ev_dir_t;

typedef enum {
	// The file will be usable only for statting (by default allowed)
	EV_OPEN_STAT = 0,
	// Opens the file in read mode
	EV_OPEN_READ = 1,
	// Opens the file in write mode
	EV_OPEN_WRITE = 2,
	// Opens the file in append mode (implies WRITE)
	EV_OPEN_APPEND = 4,

	// Creates the file if it doesn't exist
	EV_OPEN_CREATE = 8,
	// Empties the contents of the file if it exists
	EV_OPEN_TRUNC = 16,
	// Opens the file in direct mode
	EV_OPEN_DIRECT = 32,
} ev_open_flags_t;

typedef enum {
	EV_ADDR_IPV4,
	EV_ADDR_IPV6,
	// TODO: bluetooth maybe?
} ev_addr_type_t;
typedef struct {
	ev_addr_type_t type;
	union {
		uint8_t v4[4];
		uint16_t v6[8];
	};
} ev_addr_t;

typedef struct {
	size_t n;
	ev_addr_t addr[];
} *ev_addrinfo_t;
typedef enum {
	// Resolves only ipv4 (if neither this nor EV_AI_IPV6 are specified, resolves both)
	EV_AI_IPV4 = 1,
	// Resolves only ipv6 (this is mutually-exclusive with IPV4, and this will override IPV4)
	EV_AI_IPV6 = 2,
	// If no IPV6 address was found, but an IPV4 address was, resolves as an ipv6 mapping of the ipv4 address
	EV_AI_IPV4_MAPPED = 4,
	// Resolves to a bindable address - mostly applicable when name is NULL (equivalent to AI_PASSIVE)
	EV_AI_BIND = 8,
	// Resolves only IP addresses - does not make DNS requests (equivalent to AI_NUMERICHOST)
	EV_AI_NODNS = 16,
} ev_addrinfo_flags_t;

typedef enum {
	EV_PROTO_TCP,
	EV_PROTO_UDP,
} ev_proto_t;

typedef enum {
	EV_STAT_REG,
	EV_STAT_DIR,
	EV_STAT_LINK,
	EV_STAT_SOCK,
	EV_STAT_FIFO,
	EV_STAT_CHAR,
	EV_STAT_BLK,
} ev_stat_type_t;

typedef struct {
	ev_stat_type_t type;
	uint32_t mode;
	uint32_t gid;
	uint32_t uid;

	struct timespec atime, mtime, ctime;

	uint64_t size;
	uint32_t blksize;

	uint64_t inode;
	uint32_t links;
} ev_stat_t;

// Creates an ev instance. Combines a queue and a thread pool
ev_t ev_init();
// Puts the loop in a special "closed" state. This means that all new (well-behaving)
// tasks will immediately pushes the ticket with an error code.
// In this mode, when all the remaining tickets get polled, all resources, associated with this loop will be released.
// NOTE: this behavior means that at least one ev_poll call is required to actually free the loop after ev_free was called
// After that, using this event loop is UB.
// Calling this function multiple times is safe
void ev_free(ev_t ev);

// Checks if ev still has pending tickets
bool ev_busy(ev_t ev);
// Returns true if the loop is closed
// Well-behaving tasks will check this first, and will ev_push an error code, if this returns true
bool ev_closed(ev_t ev);

// Gets the next unique ticket
ev_ticket_t ev_next(ev_t ev);
// Pushes the given ticket to the message queue
// NOTE: using the same ticket twice is UB
void ev_push(ev_t ev, ev_ticket_t ticket, int err);
// Calls worker with pargs in a ev-managed thread and returns a new ticket to it
// Internally, this is used as a fallback for ops, not supported by AIO
// sync - if true, will side-step the thread pool and will instead call the worker immediately
ev_ticket_t ev_exec(ev_t ev, ev_worker_t worker, void *pargs, bool sync);

// Gets the next ticket in the message queue
// If the queue is empty:
//     If the loop is closed, returns false and frees the loop
//     If block is false, returns false
//     If block is true, blocks until a message is available and returns it
bool ev_poll(ev_t ev, bool block, ev_ticket_t *pticket, int *perr);

// Returns a reference to the stdin FD
ev_fd_t ev_stdin(ev_t ev);
// Returns a reference to the stdout FD
ev_fd_t ev_stdout(ev_t ev);
// Returns a reference to the stderr FD
ev_fd_t ev_stderr(ev_t ev);

// Equivalent to posix's open
ev_ticket_t ev_open(ev_t ev, ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode);
// Equivalent to posix's pread
ev_ticket_t ev_read(ev_t ev, ev_fd_t fd, char *buff, size_t *n, size_t offset);
// Equivalent to posix's pwrite
ev_ticket_t ev_write(ev_t ev, ev_fd_t fd, char *buff, size_t *n, size_t offset);
// Equivalent to posix's fstat
ev_ticket_t ev_stat(ev_t ev, ev_fd_t fd, ev_stat_t *buff);
// Unlike all other functions, close will complete synchronously, and will never error out
// Equivalent to posix's close
void ev_close(ev_t ev, ev_fd_t fd);

// Equivalent to posix's mkdir
ev_ticket_t ev_mkdir(ev_t ev, const char *path, int mode);
// Equivalent to posix's opendir
ev_ticket_t ev_opendir(ev_t ev, ev_dir_t *pres, const char *path);
// Equivalent to posix's readdir
ev_ticket_t ev_readdir(ev_t ev, ev_dir_t fd, char **pname);
// Equivalent to posix's closedir
void ev_closedir(ev_t ev, ev_dir_t fd);

// Parses the string to an IP address (ipv4/6 auto-detected)
bool ev_parse_ip(const char *str, ev_addr_t *pres);

// Equivalent to socket() + bind()
ev_ticket_t ev_bind(ev_t ev, ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);
// Equivalent to socket() + connect()
ev_ticket_t ev_connect(ev_t ev, ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);
// Equivalent to posix's accept
ev_ticket_t ev_accept(ev_t ev, ev_fd_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_fd_t server);
// Equivalent to posix's getaddrinfo (with a few simplifications)
ev_ticket_t ev_getaddrinfo(ev_t ev, ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags);
