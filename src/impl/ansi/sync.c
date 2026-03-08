#pragma once

#include <ev/conf.h>
#include <ev/errno.h>
#include <ev/sync.h>
#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../ev.h"
#include "./utils.c"

#ifndef __USE_GNU
	extern char **environ;
#endif

static char *evi_generic_getenvpath(const char *envname, const char *fallback, const char *suffix) {
	const char *home = getenv(envname);
	if (!home) home = fallback;

	if (suffix) {
		char *res = malloc(strlen(home) + strlen(suffix) + 1);
		if (!res) return NULL;

		strcpy(res, home);
		strcat(res, suffix);
		return res;
	}
	else {
		char *res = malloc(strlen(home) + 1);
		strcpy(res, home);
		return res;
	}
}

ev_code_t evs_read(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_generic_isfd(fd)) return EV_EBADF;

	clearerr(evi_generic_fd(fd));
	size_t n = fread(buff, *pn, 1, evi_generic_fd(fd));
	if (ferror(evi_generic_fd(fd))) return EV_EIO;

	*pn = n;
	return EV_OK;
}
ev_code_t evs_write(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_generic_isfd(fd)) return EV_EBADF;

	clearerr((FILE*)fd);
	size_t n = fwrite(buff, *pn, 1, (FILE*)fd);
	if (ferror(evi_generic_fd(fd))) return EV_EIO;

	*pn = n;
	return EV_OK;
}
ev_code_t evs_sync(ev_handle_t fd) {
	if (!evi_generic_isfd(fd)) return EV_EBADF;
	if (fflush(evi_generic_fd(fd)) < 0) return EV_EIO;
	return EV_OK;
}
ev_code_t evs_stat(ev_handle_t fd, ev_stat_t *buff) {
	FILE *f;
	bool owned = false;

	if (evi_generic_isfd(fd)) f = evi_generic_fd(fd);
	else {
		f = fopen(evi_generic_at(fd), "r");
		owned = true;
		if (!f) return EV_ENOENT;
	}

	size_t at = ftell(f);
	size_t size = fseek(f, 0, SEEK_END);
	fseek(f, at, SEEK_SET);

	buff->type = EV_STAT_REG;
	buff->mode = 0777;
	buff->gid = 1000;
	buff->uid = 1000;

	buff->atime = (ev_time_t) { 0, 0 };
	buff->ctime = (ev_time_t) { 0, 0 };
	buff->mtime = (ev_time_t) { 0, 0 };

	buff->blksize = 512;
	buff->size = size;

	buff->inode = -1;
	buff->links = 1;

	if (owned) fclose(f);
	return EV_OK;
}
void evs_close(ev_handle_t fd) {
	if (evi_generic_isfd(fd)) fclose(evi_generic_fd(fd));
	free(fd);
}

ev_code_t evs_file_open(ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	(void)mode;

	flags &= ~(EV_OPEN_SHARED | EV_OPEN_DIRECT);

	const char *open_mode;

	switch ((int)flags) {
		case EV_OPEN_STAT: {
			*pres = evi_generic_mkat(path);
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_OPEN_READ: {
			open_mode = "rb";
			break;
		}
		case EV_OPEN_READ | EV_OPEN_WRITE: {
			open_mode = "rb+";
			break;
		}
		case EV_OPEN_WRITE | EV_OPEN_APPEND | EV_OPEN_CREATE:
		case EV_OPEN_APPEND | EV_OPEN_CREATE: {
			open_mode = "ab";
			break;
		}
		case EV_OPEN_WRITE | EV_OPEN_TRUNC: {
			open_mode = "wb";
			break;
		}
		case EV_OPEN_READ | EV_OPEN_WRITE | EV_OPEN_TRUNC: {
			open_mode = "wb+";
			break;
		}
		default:
			return EV_ENOTSUP;
	}

	FILE *f = fopen(path, open_mode);
	if (!f) return EV_ENOENT;

	*pres = evi_generic_mkfd(f);
	if (!*pres) return EV_ENOMEM;
	return EV_OK;
}
ev_code_t evs_file_read(ev_handle_t fd, char *buff, size_t *pn, size_t offset) {
	if (!evi_generic_isfd(fd)) return EV_EBADF;

	size_t curr = ftell(evi_generic_fd(fd));
	if (fseek(evi_generic_fd(fd), offset, SEEK_SET) < 0) return EV_ESPIPE;

	size_t n = fread(buff, 1, *pn, evi_generic_fd(fd));
	if (ferror(evi_generic_fd(fd))) return EV_EIO;

	if (fseek(evi_generic_fd(fd), curr, SEEK_SET) < 0) return EV_ESPIPE;

	*pn = n;
	return EV_OK;
}
ev_code_t evs_file_write(ev_handle_t fd, char *buff, size_t *pn, size_t offset) {
	if (!evi_generic_isfd(fd)) return EV_EBADF;

	size_t curr = ftell(evi_generic_fd(fd));
	if (fseek(evi_generic_fd(fd), offset, SEEK_SET) < 0) return EV_ESPIPE;

	size_t n = fwrite(buff, 1, *pn, evi_generic_fd(fd));
	if (ferror(evi_generic_fd(fd))) return EV_EIO;

	if (fseek(evi_generic_fd(fd), curr, SEEK_SET) < 0) return EV_ESPIPE;

	*pn = n;
	return EV_OK;
}

ev_code_t evs_dir_new(const char *path, int mode) {
	(void)path;
	(void)mode;
	return EV_ENOTSUP;
}
ev_code_t evs_dir_open(ev_dir_t *pres, const char *path) {
	(void)pres;
	(void)path;
	return EV_ENOTSUP;
}
ev_code_t evs_dir_next(ev_dir_t dir, char **pname) {
	(void)dir;
	(void)pname;
	return EV_ENOTSUP;
}
void evs_dir_close(ev_dir_t dir) {
	(void)dir;
}

ev_code_t evs_socket_connect(ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	(void)pres;
	(void)proto;
	(void)addr;
	(void)port;
	return EV_ENOTSUP;
}
ev_code_t evs_server_bind(ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
	(void)max_n;
	(void)pres;
	(void)proto;
	(void)addr;
	(void)port;
	return EV_ENOTSUP;
}
ev_code_t evs_server_accept(ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	(void)server;
	(void)pres;
	(void)paddr;
	(void)pport;
	return EV_ENOTSUP;
}
void evs_server_close(ev_server_t server) {
	(void)server;
}

// Equivalent to posix's fork then exec
ev_code_t evs_proc_spawn(
	ev_proc_t *pres,
	const char **argv, const char **env,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_handle_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_handle_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_handle_t *perr
) {
	(void)perr;
	(void)pres;
	(void)argv;
	(void)env;
	(void)cwd;
	(void)in_flags;
	(void)pin;
	(void)out_flags;
	(void)pout;
	(void)err_flags;
	return EV_ENOTSUP;
}
ev_code_t evs_proc_wait(ev_proc_t proc, int *psig, int *pcode) {
	(void)pcode;
	(void)proc;
	(void)psig;
	return EV_ENOTSUP;
}

ev_code_t evs_getaddrinfo(ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
	(void)pres;
	(void)name;
	(void)flags;
	return EV_ENOTSUP;
}
ev_code_t evs_getpath(char **pres, ev_path_type_t type) {
	switch (type) {
		case EV_PATH_HOME: {
			*pres = evi_generic_getenvpath("HOME", ".", NULL);
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_PATH_CACHE: {
			*pres = evi_generic_getenvpath("XDG_CACHE_HOME", ".", "/.cache");
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_PATH_CONFIG: {
			*pres = evi_generic_getenvpath("XDG_CONFIG_HOME", ".", "/.config");
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_PATH_DATA: {
			*pres = evi_generic_getenvpath("XDG_DATA_HOME", ".", "/.local/share");
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_PATH_RUNTIME: {
			*pres = evi_generic_getenvpath("XDG_DATA_HOME", "/tmp", NULL);
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
		case EV_PATH_CWD: {
			*pres = evi_generic_getenvpath("PWD", ".", NULL);
			if (!*pres) return EV_ENOMEM;
			return EV_OK;
		}
	}

	return EV_EINVAL;
}

ev_code_t evs_getenv(const char *name, char **pres) {
	const char *val = getenv(name);
	if (!val) {
		*pres = NULL;
		return EV_OK;
	}

	char *res = malloc(strlen(val) + 1);
	if (!res) return EV_ENOMEM;

	strcpy(res, val);
	*pres = res;
	return EV_OK;
}
ev_code_t evs_setenv(const char *name, const char *val) {
	if (!val) {
		if (unsetenv(name) < 0) return EV_ENOMEM;
	}
	else {
		if (setenv(name, val, true) < 0) return EV_ENOMEM;
	}

	return EV_OK;
}
ev_code_t evs_nextenv(void **pit, const char **ppair) {
	(void)pit;
	*ppair = NULL;
	return EV_OK;
}

ev_code_t evs_realtime(ev_time_t *pres) {
	time_t now = time(NULL);
	if (now == -1) return EV_EIO;

	*pres = (ev_time_t) { .sec = now, .nsec = 0 };
	return EV_OK;
}
ev_code_t evs_monotime(ev_time_t *pres) {
	clock_t now = clock();
	if (now == -1) return EV_EIO;

	*pres = (ev_time_t) { .sec = now / CLOCKS_PER_SEC, .nsec = now % CLOCKS_PER_SEC * 1000 };
	return EV_OK;
}

void evs_sleep(ev_time_t time) {
	// As we have no better option, we will do a spinwait
	clock_t end = time.sec * CLOCKS_PER_SEC + time.nsec / 1000;
	while (clock() < end);
}

static ev_code_t evi_sync_init(ev_t ev) {
	ev->in = evi_generic_mkfd(stdin);
	ev->out = evi_generic_mkfd(stdout);
	ev->err = evi_generic_mkfd(stderr);

	return EV_OK;
}
static ev_code_t evi_sync_free(ev_t ev) {
	free(ev->in);
	free(ev->out);
	free(ev->err);
	return EV_OK;
}
