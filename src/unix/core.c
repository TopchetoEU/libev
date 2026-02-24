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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <dirent.h>

struct ev_dir {};

static char *evi_unix_gethome(const char *suffix) {
	struct passwd resbuf[1];
	struct passwd *ppwd;
	char *buff = malloc(PATH_MAX);
	if (!buff) return NULL;

	size_t buffn = PATH_MAX;

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

static int evi_unix_mkstd(int std_fd, int *pparent, int *pchild, ev_spawn_stdio_flags_t flags, ev_handle_t *pfd) {
	switch (flags) {
		case EV_SPAWN_STD_INHERIT:
			*pparent = *pchild = std_fd;
			break;
		case EV_SPAWN_STD_DUP:
			*pparent = *pchild = evi_unix_fd(*pfd);
			break;
		case EV_SPAWN_STD_PIPE: {
			int pipe_fd[2];
			if (pipe(pipe_fd) < 0) return -1;

			if (std_fd == STDIN_FILENO) {
				*pparent = pipe_fd[1];
				*pchild = pipe_fd[0];
			}
			else {
				*pparent = pipe_fd[0];
				*pchild = pipe_fd[1];
			}

			break;
		}
	}

	return 0;
}

static ev_code_t evi_sync_read(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t n = read(evi_unix_fd(fd), buff, *pn);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
	return EV_OK;
}
static ev_code_t evi_sync_write(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t n = write(evi_unix_fd(fd), buff, *pn);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
	return EV_OK;
}
void ev_close(ev_t loop, ev_handle_t fd) {
	(void)loop;

	if (evi_unix_isfd(fd)) {
		while (close((int)(size_t)fd) < 0) {
			if (errno != EINTR) return;
		}
	}

	evi_unix_freefd(fd);
}

static ev_code_t evi_sync_file_open(ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
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
static ev_code_t evi_sync_file_stat(ev_handle_t fd, ev_stat_t *buff) {
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
static ev_code_t evi_sync_file_read(ev_handle_t fd, char *buff, size_t *n, size_t offset) {
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
static ev_code_t evi_sync_file_write(ev_handle_t fd, char *buff, size_t *n, size_t offset) {
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
static ev_code_t evi_sync_file_sync(ev_handle_t fd) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	return evi_unix_conv_errno(fsync(evi_unix_fd(fd)));
}

static ev_code_t evi_sync_dir_new(const char *path, int mode) {
	if (mkdir(path, mode) < 0) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
static ev_code_t evi_sync_dir_open(ev_dir_t *pres, const char *path) {
	*pres = (ev_dir_t)opendir(path);
	if (!*pres) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
static ev_code_t evi_sync_dir_next(ev_dir_t dir, char **pname) {
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
void ev_dir_close(ev_t loop, ev_dir_t dir) {
	(void)loop;

	while (closedir((DIR*)dir) < 0) {
		if (errno != EINTR) return;
	}
}

static ev_code_t evi_sync_socket_connect(ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = evi_unix_mkfd(sock);
	return EV_OK;
}
static ev_code_t evi_sync_server_bind(ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int)) < 0) {
		close(sock);
		return evi_unix_conv_errno(errno);
	}

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (bind(sock, (void*)&arg_addr, len) < 0) {
		close(sock);
		return evi_unix_conv_errno(errno);
	}
	if (listen(sock, max_n) < 0) {
		close(sock);
		return evi_unix_conv_errno(errno);
	}

	*pres = (void*)(size_t)sock;
	return EV_OK;
}
static ev_code_t evi_sync_server_accept(ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	struct sockaddr_storage addr = {};
	socklen_t addr_len = sizeof addr;

	int client = accept((int)(size_t)server, (void*)&addr, &addr_len);
	if (client < 0) return evi_unix_conv_errno(errno);

	evi_unix_conv_sockaddr(&addr, paddr, pport);
	*pres = evi_unix_mkfd(client);
	return EV_OK;
}
void ev_server_close(ev_t ev, ev_server_t server) {
	(void)ev;
	close((int)(size_t)server);
}

// Equivalent to posix's fork then exec
static ev_code_t evi_sync_spawn(
	ev_proc_t *pres,
	const char **argv, const char **env,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_handle_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_handle_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_handle_t *perr
) {
	int in_parent, in_child;
	int out_parent, out_child;
	int err_parent, err_child;

	int status_pipe[2];

	if (pipe(status_pipe) < 0) goto err;
	if (fcntl(status_pipe[0], F_SETFD, FD_CLOEXEC) < 0) goto err_status_pipe;
	if (fcntl(status_pipe[1], F_SETFD, FD_CLOEXEC) < 0) goto err_status_pipe;

	if (evi_unix_mkstd(STDIN_FILENO, &in_parent, &in_child, in_flags, pin) < 0) goto err_status_pipe;
	if (evi_unix_mkstd(STDOUT_FILENO, &out_parent, &out_child, out_flags, pout)) goto err_in_pipe;
	if (evi_unix_mkstd(STDERR_FILENO, &err_parent, &err_child, err_flags, perr)) goto err_out_pipe;

	pid_t pid = fork();
	if (pid < 0) goto err_err_pipe;
	if (!pid) { // child
		close(status_pipe[0]);

		if (in_child != STDIN_FILENO) {
			if (dup2(in_child, STDIN_FILENO) < 0) goto err_child;
			close(in_child);
			if (in_child != in_parent) close(in_parent);
		}
		if (out_child != STDOUT_FILENO) {
			if (dup2(out_child, STDOUT_FILENO) < 0) goto err_child;
			close(out_child);
			if (out_child != out_parent) close(out_parent);
		}
		if (err_child != STDERR_FILENO) {
			if (dup2(err_child, STDERR_FILENO) < 0) goto err_child;
			close(err_child);
			if (err_child != err_parent) close(err_parent);
		}

		if (cwd) chdir(cwd);

		execve(argv[0], (void*)argv, (void*)env);
	err_child:
		write(status_pipe[1], &errno, sizeof errno);
		_exit(127);
	}

	close(status_pipe[1]);
	if (in_flags == EV_SPAWN_STD_PIPE) close(in_child);
	if (out_flags == EV_SPAWN_STD_PIPE) close(out_child);
	if (err_flags == EV_SPAWN_STD_PIPE) close(err_child);

	int child_code;
	int code = read(status_pipe[0], &child_code, sizeof child_code);
	close(status_pipe[0]);

	if (code < 0) goto err_exec;
	if (code > 0) {
		errno = child_code;
		goto err_exec;
	}

	if (in_flags == EV_SPAWN_STD_PIPE) *pin = evi_unix_mkfd(in_parent);
	if (out_flags == EV_SPAWN_STD_PIPE) *pout = evi_unix_mkfd(out_parent);
	if (err_flags == EV_SPAWN_STD_PIPE) *perr = evi_unix_mkfd(err_parent);

	*pres = (ev_proc_t)(size_t)pid;
	return 0;

err_exec:
	if (pid) {
		waitpid(pid, NULL, 0);
	}
err_err_pipe:
	if (err_flags == EV_SPAWN_STD_PIPE) {
		close(err_parent);
		close(err_child);
	}
err_out_pipe:
	if (out_flags == EV_SPAWN_STD_PIPE) {
		close(out_parent);
		close(out_child);
	}
err_in_pipe:
	if (in_flags == EV_SPAWN_STD_PIPE) {
		close(in_parent);
		close(in_child);
	}
err_status_pipe:
	close(status_pipe[0]);
	close(status_pipe[1]);
err:
	return evi_unix_conv_errno(errno);
}
ev_code_t evi_sync_wait(ev_proc_t proc, int *psig, int *pcode) {
	int status;
	if (waitpid((pid_t)(size_t)proc, &status, 0) < 0)  return evi_unix_conv_errno(errno);

	*pcode = -1;
	*psig = -1;

	if (WIFEXITED(status)) {
		*pcode = WEXITSTATUS(status);
	}
	if (WIFSIGNALED(status)) {
		*pcode = WTERMSIG(status);
	}

	return 0;
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
			char *buff = malloc(PATH_MAX);
			size_t buffn = PATH_MAX;
			if (!buff) return EV_ENOMEM;

			while (true) {
				if (!getcwd(buff, buffn)) break;
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

static ev_code_t evi_stdio_init(ev_handle_t *in, ev_handle_t *out, ev_handle_t *err) {
	*in = (void*)(size_t)STDIN_FILENO;
	*out = (void*)(size_t)STDOUT_FILENO;
	*err = (void*)(size_t)STDERR_FILENO;

	return EV_OK;
}
static ev_code_t evi_stdio_free(ev_handle_t in, ev_handle_t out, ev_handle_t err) {
	(void)in;
	(void)out;
	(void)err;
	return EV_OK;
}
