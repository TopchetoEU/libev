#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once

#include "ev.h"
#include "./common.h"
#include <asm-generic/errno-base.h>
#include <bits/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

struct ev_dir {};

static int evi_unix_mksock(ev_proto_t proto, ev_addr_type_t type) {
	return socket(
		type == EV_ADDR_IPV4 ? AF_INET : AF_INET6,
		proto == EV_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
		proto == EV_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP
	);
}

static ev_code_t evi_sync_open(ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	int fd = open(path, evi_unix_conv_open_flags(flags), mode);
	if (fd < 0) return evi_unix_conv_errno(errno);
	*pres = (void*)(size_t)fd;
	return EV_OK;
}
static ev_code_t evi_sync_stat(ev_fd_t fd, ev_stat_t *buff) {
	struct stat stat;
	if (fstat((int)(size_t)fd, &stat) < 0) return evi_unix_conv_errno(errno);
	evi_unix_conv_stat(buff, &stat);
	return EV_OK;
}
static ev_code_t evi_sync_read(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	ssize_t res = pread((int)(size_t)fd, buff, *n, offset);
	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}
static ev_code_t evi_sync_write(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	ssize_t res = pwrite((int)(size_t)fd, buff, *n, offset);
	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}
void ev_close(ev_t loop, ev_fd_t fd) {
	(void)loop;

	while (close((int)(size_t)fd) < 0) {
		if (errno != EINTR) return;
	}
}

static ev_code_t evi_sync_mkdir(const char *path, int mode) {
	if (mkdir(path, mode) < 0) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
static ev_code_t evi_sync_opendir(ev_dir_t *pres, const char *path) {
	*pres = (ev_dir_t)opendir(path);
	if (!*pres) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
static ev_code_t evi_sync_readdir(ev_dir_t dir, char **pname) {
	struct dirent *ent;

	while (true) {
		errno = 0;
		ent = readdir((DIR*)dir);
		if (errno) return evi_unix_conv_errno(errno);

		if (!ent) {
			*pname = NULL;
			return EV_OK;
		}

		if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) break;
	}

	*pname = malloc(strlen(ent->d_name) + 1);
	if (!*pname) return EV_ENOMEM;

	strcpy(*pname, ent->d_name);
	return EV_OK;
}
void ev_closedir(ev_t loop, ev_dir_t dir) {
	(void)loop;

	while (closedir((DIR*)dir) < 0) {
		if (errno != EINTR) return;
	}
}

static ev_code_t evi_sync_connect(ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_mksock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = (void*)(size_t)sock;
	return EV_OK;
}
static ev_code_t evi_sync_bind(ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_mksock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (bind(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = (void*)(size_t)sock;
	return EV_OK;
}
static ev_code_t evi_sync_accept(ev_fd_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_fd_t server) {
	struct sockaddr_storage addr;
	socklen_t addr_len;

	int client = accept((int)(size_t)server, (void*)&addr, &addr_len);
	if (!client) return evi_unix_conv_errno(errno);

	evi_unix_conv_sockaddr(&addr, paddr, pport);
	*pres = (void*)(size_t)client;
	return EV_OK;
}
static ev_code_t evi_sync_getaddrinfo(ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
	struct addrinfo hints = { 0 };

	if (flags & EV_AI_IPV4_MAPPED) hints.ai_flags |= EV_AI_IPV4_MAPPED;

	if (flags & EV_AI_IPV6) hints.ai_family = AF_INET6;
	else if (flags & EV_AI_IPV4) hints.ai_family = AF_INET;
	else hints.ai_family = AF_UNSPEC;

	if (flags & EV_AI_BIND) hints.ai_flags |= AI_PASSIVE;
	if (flags & EV_AI_NODNS) hints.ai_flags |= AI_NUMERICHOST;

	struct addrinfo *list = NULL;

	int code;

	// We still want to resolve a valid loopback IP, even if getaddrinfo
	if (name == NULL) code = getaddrinfo(name, "80", &hints, &list);
	else code = getaddrinfo(name, "", &hints, &list);

	switch (code) {
		case 0: break;
		case EAI_NODATA: break;
		case EAI_NONAME: break;
		default: return evi_unix_conv_aierr(code);
	}

	size_t n = 0;
	for (struct addrinfo *it = list; it; it = it->ai_next) n++;

	ev_addrinfo_t res = malloc(sizeof *res + sizeof *res->addr * n);
	if (!res) return ENOMEM;

	size_t i = 0;
	for (struct addrinfo *it = list; it; it = it->ai_next) {
		uint16_t port;
		ev_addr_t addr;
		evi_unix_conv_sockaddr((void*)it->ai_addr, &addr, &port);

		bool found = false;

		for (size_t j = 0; j < i; j++) {
			if (ev_cmpaddr(addr, res->addr[j])) {
				found = true;
				break;
			}
		}

		if (!found) {
			res->addr[i] = addr;
			i++;
		}
	}

	res->n = i;

	if (list) freeaddrinfo(list);

	*pres = res;
	return EV_OK;
}

int ev_realtime(ev_time_t *pres) {
	struct timespec res;
	if (clock_gettime(CLOCK_REALTIME, &res) < 0) return -1;
	*pres = (ev_time_t) { .sec = res.tv_sec, .nsec = res.tv_nsec };
	return EV_OK;
}
int ev_monotime(ev_time_t *pres) {
	struct timespec res;
	if (clock_gettime(CLOCK_MONOTONIC, &res) < 0) return -1;
	*pres = (ev_time_t) { .sec = res.tv_sec, .nsec = res.tv_nsec };
	return EV_OK;
}

static ev_code_t evi_stdio_init(ev_fd_t *in, ev_fd_t *out, ev_fd_t *err) {
	*in = (void*)(size_t)STDIN_FILENO;
	*out = (void*)(size_t)STDOUT_FILENO;
	*err = (void*)(size_t)STDERR_FILENO;

	return EV_OK;
}
static ev_code_t evi_stdio_free(ev_fd_t in, ev_fd_t out, ev_fd_t err) {
	(void)in;
	(void)out;
	(void)err;
	return EV_OK;
}
