#include <sys/types.h>
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once

#include "ev/conf.h"
#include "ev.h"
#include "ev/errno.h"
#include "./common.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>

struct ev_dir {};

static int evi_unix_new_sock(ev_proto_t proto, ev_addr_type_t type) {
	return socket(
		type == EV_ADDR_IPV4 ? AF_INET : AF_INET6,
		proto == EV_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
		proto == EV_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP
	);
}

static ev_code_t evi_sync_open(ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	int fd = -1;

	#ifdef EV_USE_LINUX
		fd = open(path, evi_unix_conv_open_flags(flags), mode);
		if (fd < 0) return evi_unix_conv_errno(errno);
	#else
		if (flags != EV_OPEN_STAT) {
			int unix_flags = evi_unix_conv_open_flags(flags);
			fd = open(path, unix_flags, mode);
			if (fd < 0) return evi_unix_conv_errno(errno);
		}

		if (fd < 0) {
			*pres = evi_unix_mkat(path);
		}
		else
	#endif
	{
		*pres = evi_unix_mkfd(fd);
	}

	if (!*pres) return EV_ENOMEM;
	return EV_OK;
}
static ev_code_t evi_sync_stat(ev_fd_t fd, ev_stat_t *buff) {
	struct stat res;

	if (evi_unix_isfd(fd)) {
		if (fstat(evi_unix_fd(fd), &res) < 0) return evi_unix_conv_errno(errno);
	}
	else {
		if (stat(evi_unix_at(fd), &res) < 0) return evi_unix_conv_errno(errno);
	}

	evi_unix_conv_stat(buff, &res);
	return EV_OK;
}
static ev_code_t evi_sync_read(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	// Since our API doesn't work with seek pointers (as uring warrants that),
	// but pread/pwrite always seek, we need to have a special case for TTYs and pipes
	ssize_t res;
	if (offset == 0 && lseek(evi_unix_fd(fd), 0, SEEK_CUR) < 0) {
		res = read(evi_unix_fd(fd), buff, *n);
	}
	else {
		res = pread(evi_unix_fd(fd), buff, *n, offset);
	}

	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}
static ev_code_t evi_sync_write(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t res;
	if (offset == 0 && lseek(evi_unix_fd(fd), 0, SEEK_CUR) < 0) {
		res = write(evi_unix_fd(fd), buff, *n);
	}
	else {
		res = pwrite(evi_unix_fd(fd), buff, *n, offset);
	}

	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}
void ev_close(ev_t loop, ev_fd_t fd) {
	(void)loop;

	if (evi_unix_isfd(fd)) {
		while (close((int)(size_t)fd) < 0) {
			if (errno != EINTR) return;
		}
	}

	evi_unix_freefd(fd);
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

static ev_code_t evi_sync_connect(ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = evi_unix_mksock(sock);
	return EV_OK;
}
static ev_code_t evi_sync_bind(ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (bind(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = evi_unix_mksock(sock);
	return EV_OK;
}
static ev_code_t evi_sync_accept(ev_socket_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_socket_t server) {
	struct sockaddr_storage addr;
	socklen_t addr_len;

	int client = accept((int)(size_t)server, (void*)&addr, &addr_len);
	if (!client) return evi_unix_conv_errno(errno);

	evi_unix_conv_sockaddr(&addr, paddr, pport);
	*pres = evi_unix_mksock(client);
	return EV_OK;
}
static ev_code_t evi_sync_recv(ev_socket_t sock, char *buff, size_t *pn) {
	ssize_t n = recv(evi_unix_sock(sock), buff, *pn, 0);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
	return EV_OK;
}
static ev_code_t evi_sync_send(ev_socket_t sock, char *buff, size_t *pn) {
	ssize_t n = send(evi_unix_sock(sock), buff, *pn, 0);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
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
		#ifdef EV_USE_LINUX
			case EAI_NODATA: break;
		#endif
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
void ev_closesock(ev_t ev, ev_socket_t sock) {
	ev_close(ev, evi_unix_mkfd(evi_unix_sock(sock)));
}

// static const char =

static char *evi_unix_gethome(const char *suffix) {
	struct passwd resbuf[1];
	struct passwd *ppwd;
	char *buff = malloc(1024);
	if (!buff) return NULL;

	size_t buffn = 1024;

	while (true) {
		getpwuid_r(getuid(), resbuf, buff, buffn, &ppwd);
		if (ppwd) break;
		if (errno == ERANGE) {
			buffn *= 2;
			free(buff);
			buff = malloc(buffn);
			if (!buff) return NULL;
		}
		else {
			free(buff);
			return NULL;
		}
	}

	if (suffix) {
		char *res = malloc(strlen(ppwd->pw_dir) + strlen(suffix) + 1);
		if (!res) return NULL;

		strcpy(res, ppwd->pw_dir);
		strcat(res, suffix);
		free(buff);
		return res;
	}
	else {
		char *res = malloc(strlen(ppwd->pw_dir) + 1);
		strcpy(res, ppwd->pw_dir);
		free(buff);
		return res;
	}
}
static char *evi_unix_getpath(const char *envname, const char *suffix) {
	const char *env = getenv(envname);
	if (env && *env) {
		char *res = malloc(strlen(env) + 1);
		if (!res) return NULL;

		strcpy(res, env);
		return res;
	}

	return evi_unix_gethome(suffix);
}

static ev_code_t evi_sync_getpath(char **pres, ev_path_type_t type) {
	switch (type) {
		case EV_PATH_HOME: {
			char *res = evi_unix_gethome(NULL);
			if (!res) return evi_unix_conv_errno(errno);

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_CACHE: {
			char *res = evi_unix_getpath("XDG_CACHE_HOME", "/.cache");
			if (!res) return evi_unix_conv_errno(errno);

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_CONFIG: {
			char *res = evi_unix_getpath("XDG_CONFIG_HOME", "/.config");
			if (!res) return evi_unix_conv_errno(errno);

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_DATA: {
			char *res = evi_unix_getpath("XDG_DATA_HOME", "/.local/share");
			if (!res) return evi_unix_conv_errno(errno);

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_RUNTIME: {
			const char *res;

			const char *env = getenv("XDG_RUNTIME_DIR");
			if (env && *env) res = env;
			else res = "/tmp";

			*pres = malloc(strlen(res) + 1);
			if (!*pres) return evi_unix_conv_errno(errno);

			strcpy(*pres, res);
			return EV_OK;
		}
		case EV_PATH_CWD: {
			char *buff = malloc(1024);
			size_t buffn = 1024;
			if (!buff) return EV_ENOMEM;

			while (true) {
				if (!getcwd(buff, buffn) == 0) break;
				if (errno != ERANGE) {
					free(buff);
					return evi_unix_conv_errno(errno);
				}

				buffn *= 2;
				free(buff);
				buff = malloc(buffn);
				if (!buff) return EV_ENOMEM;
			}

			*pres = realloc(buff, strlen(buff) + 1);
			return EV_OK;
		}
	}

	return EV_EINVAL;
}

static void evi_sleep(ev_time_t time) {
	struct timespec req = { .tv_sec = time.sec, .tv_nsec = time.nsec };
	while (true) {
		if (nanosleep(&req, NULL) == 0) break;
		if (errno == EINTR) continue;
	}
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
