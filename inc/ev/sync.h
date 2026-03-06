#include "ev.h"
#include "ev/errno.h"

// These functions give you more or less direct access to the underlying OS I/O functions
// Most of these have async versions, except for environment, path, time and close functions, which aren't meant to be async

ev_code_t evs_read(ev_handle_t fd, char *buff, size_t *pn);
ev_code_t evs_write(ev_handle_t fd, char *buff, size_t *pn);
void evs_close(ev_handle_t fd);

ev_code_t evs_file_open(ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode);
ev_code_t evs_file_read(ev_handle_t fd, char *buff, size_t *n, size_t offset);
ev_code_t evs_file_write(ev_handle_t fd, char *buff, size_t *n, size_t offset);
ev_code_t evs_sync(ev_handle_t fd);
ev_code_t evs_stat(ev_handle_t fd, ev_stat_t *buff);

ev_code_t evs_dir_new(const char *path, int mode);
ev_code_t evs_dir_open(ev_dir_t *pres, const char *path);
ev_code_t evs_dir_next(ev_dir_t dir, char **pname);
void evs_dir_close(ev_dir_t dir);

ev_code_t evs_server_bind(ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n);
ev_code_t evs_server_accept(ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server);
void evs_server_close(ev_server_t server);

ev_code_t evs_socket_connect(ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port);

ev_code_t evs_proc_spawn(
	ev_proc_t *pres,
	const char **argv, const char **envp,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_handle_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_handle_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_handle_t *perr
);
ev_code_t evs_proc_wait(ev_proc_t proc, int *psig, int *pcode);

ev_code_t evs_getaddrinfo(ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags);
// Gets a malloc'd string, representing the requested path
ev_code_t evs_getpath(char **pres, ev_path_type_t type);

// Gets an env variable from the current process
ev_code_t evs_getenv(const char *name, char **pres);
// Sets an env variable in the current process (if val is NULL, unsets it)
ev_code_t evs_setenv(const char *name, const char *val);
// Iterates all key-value env pairs and sets them to pit, as "KEY=VAL\0"
// pit contains impl-specific iteration data. Passing the pointer, stored after an iteration more than once is UB
// ppair is used to save the current pair, or NULL if the end of the list is reached
// Modifying of the environment in between iterations leads to UB, and generally is a very, very bad idea
ev_code_t evs_nextenv(void **pit, const char **ppair);

// Gets the time, elapsed since the unix epoch (CLOCK_REALTIME)
ev_code_t evs_realtime(ev_time_t *pres);
// Gets a reliably and monotonically ticking time, unaffected by the system time (CLOCK_MONOTONIC)
// You should use this instead of `ev_realtime` when dealing with ev_poll's timeouts, and in general,
// when you care about time offsets more than the actual current time, which is almost always the case
ev_code_t evs_monotime(ev_time_t *pres);

// Sleeps until the monotone timestamp provided occurs
void evs_sleep(ev_time_t time);
