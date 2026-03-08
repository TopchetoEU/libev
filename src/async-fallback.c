#pragma once

/*
One of the more complicated files, so i think an explanation is in order:

Since not all operations are implemented or implementable using the async mechanism of choice,
Some operations must go thru the thread pool. In order to not repeat a lot of code, this macro spaghetti is used
In short, it generates a structure to pack the arguments of each IO op, a worker function for the thread pool and
an implementation of the ev.h interface function.
*/

#include <ev/conf.h>
#include <ev/sync.h>
#include <ev.h>

#include <stddef.h>
#include <stdlib.h>

#include "./impl/async.c"

#define EVI_COMMA ,
#define EVI_SEMICOLON ;

#define EVI_FALLBACK_STRUCT_ARG_X(type, name) type name
#define EVI_FALLBACK_PARAM_ARG_X(type, name) type name
#define EVI_FALLBACK_CONSTRUCT_ARG_X(type, name) pargs->name = name
#define EVI_FALLBACK_DECONSTRUCT_ARG_X(type, name) args.name

#define EVI_MKFALLBACK(name, func, args_x) \
	typedef struct { \
		args_x(EVI_FALLBACK_STRUCT_ARG_X, EVI_SEMICOLON); \
	} evi_##name##_args_t; \
\
	static int evi_##name##_worker(void *pargs) { \
		evi_##name##_args_t args = *(evi_##name##_args_t*)pargs; \
		free(pargs); \
		return func(args_x(EVI_FALLBACK_DECONSTRUCT_ARG_X, EVI_COMMA)); \
	} \
	ev_code_t ev_##name(ev_t ev, void *udata, args_x(EVI_FALLBACK_PARAM_ARG_X, EVI_COMMA)) {\
		evi_##name##_args_t *pargs = malloc(sizeof *pargs);\
		if (!pargs) return EV_ENOMEM; \
\
		args_x(EVI_FALLBACK_CONSTRUCT_ARG_X, EVI_SEMICOLON); \
		return ev_exec(ev, udata, evi_##name##_worker, pargs, false); \
	}

#define EVI_READ_PARAMS(ARG, SEP) ARG(ev_handle_t, handle) SEP ARG(char*, buff) SEP ARG(size_t*, pn)
#define EVI_WRITE_PARAMS(ARG, SEP) ARG(ev_handle_t, handle) SEP ARG(char*, buff) SEP ARG(size_t*, pn)
#define EVI_SYNC_PARAMS(ARG, SEP) ARG(ev_handle_t, fd)
#define EVI_STAT_PARAMS(ARG, SEP) ARG(ev_handle_t, fd) SEP ARG(ev_stat_t*, buff)

#define EVI_FILE_OPEN_PARAMS(ARG, SEP) ARG(ev_handle_t*, pres) SEP ARG(const char*, path) SEP ARG(ev_open_flags_t, flags) SEP ARG(int, mode)
#define EVI_FILE_READ_PARAMS(ARG, SEP) ARG(ev_handle_t, handle) SEP ARG(char*, buff) SEP ARG(size_t*, pn) SEP ARG(size_t, offset)
#define EVI_FILE_WRITE_PARAMS(ARG, SEP) ARG(ev_handle_t, handle) SEP ARG(char*, buff) SEP ARG(size_t*, pn) SEP ARG(size_t, offset)

#define EVI_DIR_NEW_PARAMS(ARG, SEP) ARG(const char*, path) SEP ARG(int, mode)
#define EVI_DIR_OPEN_PARAMS(ARG, SEP) ARG(ev_dir_t*, pres) SEP ARG(const char*, path)
#define EVI_DIR_NEXT_PARAMS(ARG, SEP) ARG(ev_dir_t, dir) SEP ARG(char**, pname)

#define EVI_SERVER_BIND_PARAMS(ARG, SEP) ARG(ev_server_t*, pres) SEP ARG(ev_proto_t, proto) SEP ARG(ev_addr_t, addr) SEP ARG(uint16_t, port) SEP ARG(size_t, max_n)
#define EVI_SERVER_ACCEPT_PARAMS(ARG, SEP) ARG(ev_handle_t*, pres) SEP ARG(ev_addr_t*, paddr) SEP ARG(uint16_t*, pport) SEP ARG(ev_server_t, server)

#define EVI_SOCKET_CONNECT_PARAMS(ARG, SEP) ARG(ev_handle_t*, pres) SEP ARG(ev_proto_t, proto) SEP ARG(ev_addr_t, addr) SEP ARG(uint16_t, port)

#define EVI_PROC_SPAWN_PARAMS(ARG, SEP) \
	ARG(ev_proc_t*, pres) SEP \
	ARG(const char**, argv) SEP \
	ARG(const char**, env) SEP \
	ARG(const char*, cwd) SEP \
	ARG(ev_spawn_stdio_flags_t, in_flags) SEP ARG(ev_handle_t*, pin) SEP \
	ARG(ev_spawn_stdio_flags_t, out_flags) SEP ARG(ev_handle_t*, pout) SEP \
	ARG(ev_spawn_stdio_flags_t, err_flags) SEP ARG(ev_handle_t*, perr)
#define EVI_PROC_WAIT_PARAMS(ARG, SEP) \
	ARG(ev_proc_t, proc) SEP \
	ARG(int*, psig) SEP \
	ARG(int*, pcode)

#define EVI_GETADDRINFO_PARAMS(ARG, SEP) ARG(ev_addrinfo_t*, pres) SEP ARG(const char*, name) SEP ARG(ev_addrinfo_flags_t, flags)

#ifndef EVI_ASYNC_READ
	EVI_MKFALLBACK(read, evs_read, EVI_READ_PARAMS)
#endif
#ifndef EVI_ASYNC_WRITE
	EVI_MKFALLBACK(write, evs_write, EVI_WRITE_PARAMS)
#endif

#ifndef EVI_ASYNC_SYNC
	EVI_MKFALLBACK(sync, evs_sync, EVI_SYNC_PARAMS)
#endif
#ifndef EVI_ASYNC_STAT
	EVI_MKFALLBACK(stat, evs_stat, EVI_STAT_PARAMS)
#endif
#ifndef EVI_ASYNC_FILE_OPEN
	EVI_MKFALLBACK(file_open, evs_file_open, EVI_FILE_OPEN_PARAMS)
#endif
#ifndef EVI_ASYNC_FILE_READ
	EVI_MKFALLBACK(file_read, evs_file_read, EVI_FILE_READ_PARAMS)
#endif
#ifndef EVI_ASYNC_FILE_WRITE
	EVI_MKFALLBACK(file_write, evs_file_write, EVI_FILE_WRITE_PARAMS)
#endif
#ifndef EVI_ASYNC_DIR_NEW
	EVI_MKFALLBACK(dir_new, evs_dir_new, EVI_DIR_NEW_PARAMS)
#endif
#ifndef EVI_ASYNC_DIR_OPEN
	EVI_MKFALLBACK(dir_open, evs_dir_open, EVI_DIR_OPEN_PARAMS)
#endif
#ifndef EVI_ASYNC_DIR_NEXT
	EVI_MKFALLBACK(dir_next, evs_dir_next, EVI_DIR_NEXT_PARAMS)
#endif
#ifndef EVI_ASYNC_SOCKET_CONNECT
	EVI_MKFALLBACK(socket_connect, evs_socket_connect, EVI_SOCKET_CONNECT_PARAMS)
#endif
#ifndef EVI_ASYNC_SERVER_BIND
	EVI_MKFALLBACK(server_bind, evs_server_bind, EVI_SERVER_BIND_PARAMS)
#endif
#ifndef EVI_ASYNC_SERVER_ACCEPT
	EVI_MKFALLBACK(server_accept, evs_server_accept, EVI_SERVER_ACCEPT_PARAMS)
#endif
#ifndef EVI_ASYNC_PROC_SPAWN
	EVI_MKFALLBACK(proc_spawn, evs_proc_spawn, EVI_PROC_SPAWN_PARAMS)
#endif
#ifndef EVI_ASYNC_PROC_WAIT
	EVI_MKFALLBACK(proc_wait, evs_proc_wait, EVI_PROC_WAIT_PARAMS)
#endif
#ifndef EVI_ASYNC_GETADDRINFO
	EVI_MKFALLBACK(getaddrinfo, evs_getaddrinfo, EVI_GETADDRINFO_PARAMS)
#endif
