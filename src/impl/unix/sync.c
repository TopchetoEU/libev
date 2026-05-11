#pragma once

#include <ev/conf.h>
#include <ev/errno.h>
#include <ev/signo.h>
#include <ev/sync.h>
#include <ev.h>

#include <signal.h>
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
#include <limits.h>

#include "../../ev.h"
#include "../../utils/atomic.h"
#include "./utils.c"

#ifdef EV_USE_URING
	#include <sys/signalfd.h>
#endif

#ifndef __USE_GNU
	extern char **environ;
#endif


static bool _sig_init = false;
static ev_mutex_t _sig_mut;
static size_t _sig_counts[EV_SIGUSR2 + 1];
static sigset_t _sig_set;

static char *evi_generic_getenvpath(const char *suffix) {
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

	return evi_generic_getenvpath(suffix);
}

static int evi_unix_mkstd(bool in, int *pparent, int *pchild) {
	int pipe_fd[2];
	if (pipe(pipe_fd) < 0) return -1;

	if (in) {
		*pparent = pipe_fd[1];
		*pchild = pipe_fd[0];
	}
	else {
		*pparent = pipe_fd[0];
		*pchild = pipe_fd[1];
	}

	return 0;
}

ev_code_t evs_read(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t n = read(evi_unix_fd(fd), buff, *pn);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
	return EV_OK;
}
ev_code_t evs_write(ev_handle_t fd, char *buff, size_t *pn) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t n = write(evi_unix_fd(fd), buff, *pn);
	if (n < 0) return evi_unix_conv_errno(errno);

	*pn = n;
	return EV_OK;
}
ev_code_t evs_sync(ev_handle_t fd) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	return evi_unix_conv_errno(fsync(evi_unix_fd(fd)));
}
ev_code_t evs_stat(ev_handle_t fd, ev_stat_t *buff) {
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
void evs_close(ev_handle_t fd) {
	if (evi_unix_isfd(fd)) {
		while (close(evi_unix_fd(fd)) < 0) {
			if (errno != EINTR) return;
		}
	}

	evi_unix_freefd(fd);
}

ev_code_t evs_file_open(ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
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
ev_code_t evs_file_read(ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t res = pread(evi_unix_fd(fd), buff, *n, offset);
	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}
ev_code_t evs_file_write(ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	if (!evi_unix_isfd(fd)) return EV_EBADF;

	ssize_t res = pwrite(evi_unix_fd(fd), buff, *n, offset);
	if (res < 0) return evi_unix_conv_errno(errno);
	*n = res;
	return EV_OK;
}

ev_code_t evs_file_symlink(const char *path, const char *target) {
	if (symlink(path, target) < 0) return evi_unix_conv_errno(errno);
	return EV_OK;
}
ev_code_t evs_file_hardlink(ev_handle_t hnd, const char *target) {
	#ifdef EV_USE_LINUX
		if (linkat(evi_unix_fd(hnd), "", AT_FDCWD, target, AT_EMPTY_PATH) < 0) return evi_unix_conv_errno(errno);
	#else
		if (evi_unix_isfd(hnd)) return EV_ENOTSUP;
		if (link(evi_unix_at(hnd), target) < 0) return evi_unix_conv_errno(errno);
	#endif

	return EV_OK;
}
ev_code_t evs_file_readlink(ev_handle_t hnd, char **pres) {
	struct stat stat;
	if (evi_unix_isfd(hnd)) {
		if (fstat(evi_unix_fd(hnd), &stat) < 0) return evi_unix_conv_errno(errno);
	}
	else {
		if (lstat(evi_unix_at(hnd), &stat) < 0) return evi_unix_conv_errno(errno);
	}

	char *res = malloc(stat.st_size + 1);
	if (!res) return EV_ENOMEM;

	#ifdef EV_USE_LINUX
		int n = readlinkat(evi_unix_fd(hnd), "", res, stat.st_size + 1);
	#else
		if (evi_unix_isfd(hnd)) {
			free(res);
			return EV_ENOTSUP;
		}
		int n = readlink(evi_unix_at(hnd), res, stat.st_size + 1);
	#endif

	if (n < 0) {
		free(res);
		return evi_unix_conv_errno(errno);
	}

	res[n] = 0;

	*pres = res;
	return EV_OK;
}
ev_code_t evs_file_chmod(ev_handle_t hnd, int mode) {
	if (evi_unix_isfd(hnd)) {
		if (fchmod(evi_unix_fd(hnd), mode) < 0) return evi_unix_conv_errno(errno);
	}
	else {
		if (chmod(evi_unix_at(hnd), mode) < 0) return evi_unix_conv_errno(errno);
	}

	return EV_OK;
}
ev_code_t evs_file_chown(ev_handle_t hnd, int uid, int gid) {
	if (evi_unix_isfd(hnd)) {
		if (fchown(evi_unix_fd(hnd), uid, gid) < 0) return evi_unix_conv_errno(errno);
	}
	else {
		if (chown(evi_unix_at(hnd), uid, gid) < 0) return evi_unix_conv_errno(errno);
	}

	return EV_OK;
}
ev_code_t evs_file_delete(ev_handle_t hnd) {
	#ifdef EV_USE_LINUX
		if (unlinkat(evi_unix_fd(hnd), "", AT_EMPTY_PATH) < 0) return evi_unix_conv_errno(errno);
	#else
		if (evi_unix_isfd(hnd)) return EV_ENOTSUP;
		if (unlink(evi_unix_at(hnd)) < 0) return evi_unix_conv_errno(errno);
	#endif

	return EV_OK;
}

ev_code_t evs_dir_new(const char *path, int mode) {
	if (mkdir(path, mode) < 0) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
ev_code_t evs_dir_open(ev_dir_t *pres, const char *path) {
	*pres = (ev_dir_t)opendir(path);
	if (!*pres) return evi_unix_conv_errno(errno);
	else return EV_OK;
}
ev_code_t evs_dir_next(ev_dir_t dir, char **pname) {
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
void evs_dir_close(ev_dir_t dir) {
	while (closedir((DIR*)dir) < 0) {
		if (errno != EINTR) return;
	}
}

ev_code_t evs_socket_connect(ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	int sock = evi_unix_new_sock(proto, addr.type);
	if (sock < 0) return evi_unix_conv_errno(errno);

	struct sockaddr_storage arg_addr;
	int len = evi_unix_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_unix_conv_errno(errno);

	*pres = evi_unix_mkfd(sock);
	return EV_OK;
}
ev_code_t evs_server_bind(ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
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
ev_code_t evs_server_accept(ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	struct sockaddr_storage addr = {};
	socklen_t addr_len = sizeof addr;

	int client = accept((int)(size_t)server, (void*)&addr, &addr_len);
	if (client < 0) return evi_unix_conv_errno(errno);

	evi_unix_conv_sockaddr(&addr, paddr, pport);
	*pres = evi_unix_mkfd(client);
	return EV_OK;
}
void evs_server_close(ev_server_t server) {
	close((int)(size_t)server);
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
	int in_parent = -1, in_child = -1;
	int out_parent = -1, out_child = -1;
	int err_parent = -1, err_child = -1;

	int status_pipe[2];

	if (pipe(status_pipe) < 0) goto err;
	if (fcntl(status_pipe[0], F_SETFD, FD_CLOEXEC) < 0) goto err_status_pipe;
	if (fcntl(status_pipe[1], F_SETFD, FD_CLOEXEC) < 0) goto err_status_pipe;

	if (in_flags == EV_SPAWN_STD_PIPE) {
		if (evi_unix_mkstd(true, &in_parent, &in_child) < 0) goto err_status_pipe;
		if (fcntl(in_parent, F_SETFD, FD_CLOEXEC) < 0) goto err_in_pipe;
	}
	if (out_flags == EV_SPAWN_STD_PIPE) {
		if (evi_unix_mkstd(false, &out_parent, &out_child) < 0) goto err_in_pipe;
		if (fcntl(out_parent, F_SETFD, FD_CLOEXEC) < 0) goto err_out_pipe;
	}
	if (err_flags == EV_SPAWN_STD_PIPE) {
		if (evi_unix_mkstd(false, &err_parent, &err_child) < 0) goto err_out_pipe;
		if (fcntl(err_parent, F_SETFD, FD_CLOEXEC) < 0) goto err_err_pipe;
	}

	pid_t pid = fork();
	if (pid < 0) goto err_err_pipe;
	if (!pid) { // child
		close(status_pipe[0]);

		if (in_child != -1) {
			if (dup2(in_child, STDIN_FILENO) < 0) goto err_child;
		}
		if (out_child != -1) {
			if (dup2(out_child, STDOUT_FILENO) < 0) goto err_child;
		}
		if (err_child != -1) {
			if (dup2(err_child, STDERR_FILENO) < 0) goto err_child;
		}

		if (in_parent != -1) close(in_parent);
		if (out_parent != -1) close(out_parent);
		if (err_parent != -1) close(err_parent);
		in_parent = out_parent = err_parent = -1;

		if (in_child != -1) close(in_child);
		if (out_child != -1) close(out_child);
		if (err_child != -1) close(err_child);
		in_child = out_child = err_child = -1;

		if (cwd) {
			if (chdir(cwd) < 0) goto err_child;
		}

		sigset_t set;
		sigemptyset(&set);
		if (ev_setmask(SIG_SETMASK, &set, NULL) < 0) goto err_child;

		errno = 0;
		execve(argv[0], (void*)argv, (void*)env);

	err_child: ;
		int err = errno;
		write(status_pipe[1], &err, sizeof err);

		if (in_child != -1) close(in_child);
		if (out_child != -1) close(out_child);
		if (err_child != -1) close(err_child);
		close(status_pipe[0]);

		_exit(127);
	}

	if (in_child != -1) close(in_child);
	if (out_child != -1) close(out_child);
	if (err_child != -1) close(err_child);
	in_child = out_child = err_child = -1;

	close(status_pipe[1]);
	status_pipe[1] = -1;

	int child_code;
	int read_n = read(status_pipe[0], &child_code, sizeof child_code);
	close(status_pipe[0]);
	status_pipe[0] = -1;

	if (read_n < 0) goto err_exec;
	if (read_n > 0) {
		assert(read_n == 4);
		errno = child_code;
		goto err_exec;
	}

	if (in_parent != -1) *pin = evi_unix_mkfd(in_parent);
	if (out_parent != -1) *pout = evi_unix_mkfd(out_parent);
	if (err_parent != -1) *perr = evi_unix_mkfd(err_parent);

	*pres = (ev_proc_t)(size_t)pid;
	return 0;

err_exec:
	if (pid) {
		// Mostly unnecessary, as child will exit anyways. Still, good to have...
		waitpid(pid, NULL, 0);
	}
err_err_pipe:
	if (err_parent != -1) close(err_parent);
	if (err_child != -1) close(err_child);
err_out_pipe:
	if (out_parent != -1) close(out_parent);
	if (out_child != -1) close(out_child);
err_in_pipe:
	if (in_parent != -1) close(in_parent);
	if (in_child != -1) close(in_child);
err_status_pipe:
	if (status_pipe[0] != -1) close(status_pipe[0]);
	if (status_pipe[1] != -1) close(status_pipe[1]);
err:
	return evi_unix_conv_errno(errno);
}
ev_code_t evs_proc_wait(ev_proc_t proc, int *psig, int *pcode) {
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

ev_code_t evs_getaddrinfo(ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
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
	code = getaddrinfo(name, "0", &hints, &list);

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

ev_code_t ev_sig_on(ev_t ev, ev_signo_t sig) {
	(void)ev;

	ev_mutex_lock(_sig_mut);

	if (!_sig_counts[sig]) {
		sigset_t old_set = _sig_set;

		switch (sig) {
			case EV_SIGINT: sigaddset(&_sig_set, SIGINT); break;
			case EV_SIGQUIT: sigaddset(&_sig_set, SIGQUIT); break;
			case EV_SIGABRT: sigaddset(&_sig_set, SIGABRT); break;
			case EV_SIGTERM: sigaddset(&_sig_set, SIGTERM); break;

			case EV_SIGBADMEM:
				sigaddset(&_sig_set, SIGSEGV);
				sigaddset(&_sig_set, SIGBUS);
				sigaddset(&_sig_set, SIGSTKFLT);
				break;
			case EV_SIGBADOP:
				sigaddset(&_sig_set, SIGILL);
				sigaddset(&_sig_set, SIGFPE);
				sigaddset(&_sig_set, SIGSYS);
				break;
			case EV_SIGBADPIPE: sigaddset(&_sig_set, SIGPIPE); break;

			case EV_SIGTSIZE: sigaddset(&_sig_set, SIGWINCH); break;
			case EV_SIGTLOST: sigaddset(&_sig_set, SIGHUP); break;

			case EV_SIGUSR1: sigaddset(&_sig_set, SIGUSR1); break;
			case EV_SIGUSR2: sigaddset(&_sig_set, SIGUSR2); break;
		}

		if (ev_setmask(SIG_SETMASK, &_sig_set, NULL) < 0) {
			_sig_set = old_set;
			ev_mutex_unlock(_sig_mut);
			return evi_unix_conv_errno(errno);
		}

		// Very bad solution, come up with a better one if u can
		#ifdef EV_USE_URING
			if (signalfd(ev->async->signal_fd, &_sig_set, 0) < 0) {
				ev_setmask(SIG_SETMASK, &old_set, NULL);

				_sig_set = old_set;
				ev_mutex_unlock(_sig_mut);
				return evi_unix_conv_errno(errno);
			}
		#endif
	}

	_sig_counts[sig]++;

	ev_mutex_unlock(_sig_mut);
	return EV_OK;
}
ev_code_t ev_sig_off(ev_t ev, ev_signo_t sig) {
	(void)ev;

	ev_mutex_lock(_sig_mut);

	if (_sig_counts[sig] == 1) {
		sigset_t old_set = _sig_set;

		switch (sig) {
			case EV_SIGINT: sigdelset(&_sig_set, SIGINT); break;
			case EV_SIGQUIT: sigdelset(&_sig_set, SIGQUIT); break;
			case EV_SIGABRT: sigdelset(&_sig_set, SIGABRT); break;
			case EV_SIGTERM: sigdelset(&_sig_set, SIGTERM); break;

			case EV_SIGBADMEM:
				sigdelset(&_sig_set, SIGSEGV);
				sigdelset(&_sig_set, SIGBUS);
				sigdelset(&_sig_set, SIGSTKFLT);
				break;
			case EV_SIGBADOP:
				sigdelset(&_sig_set, SIGILL);
				sigdelset(&_sig_set, SIGFPE);
				sigdelset(&_sig_set, SIGSYS);
				break;
			case EV_SIGBADPIPE: sigdelset(&_sig_set, SIGPIPE); break;

			case EV_SIGTSIZE: sigdelset(&_sig_set, SIGWINCH); break;
			case EV_SIGTLOST: sigdelset(&_sig_set, SIGHUP); break;

			case EV_SIGUSR1: sigdelset(&_sig_set, SIGUSR1); break;
			case EV_SIGUSR2: sigdelset(&_sig_set, SIGUSR2); break;
		}

		if (ev_setmask(SIG_SETMASK, &_sig_set, NULL) < 0) {
			_sig_set = old_set;
			ev_mutex_unlock(_sig_mut);
			return evi_unix_conv_errno(errno);
		}

		// Very bad solution, come up with a better one if u can
		#ifdef EV_USE_URING
			if (signalfd(ev->async->signal_fd, &_sig_set, 0) < 0) {
				ev_setmask(SIG_SETMASK, &old_set, NULL);

				_sig_set = old_set;
				ev_mutex_unlock(_sig_mut);
				return evi_unix_conv_errno(errno);
			}
		#endif
	}

	if (_sig_counts[sig]) {
		_sig_counts[sig]--;
	}

	ev_mutex_unlock(_sig_mut);
	return EV_OK;
}

ev_code_t evs_sig_wait(ev_signo_t *pres) {
	sigset_t old, add_pwr, full;
	sigfillset(&full);
	sigemptyset(&add_pwr);
	sigaddset(&add_pwr, SIGPWR);
	if (ev_setmask(SIG_BLOCK, &add_pwr, &old) < 0) return evi_unix_conv_errno(errno);

	int res;
	while (true) {
		if (sigwait(&full, &res) < 0) return evi_unix_conv_errno(errno);

		if (res == SIGPWR) {
			ev_setmask(SIG_SETMASK, &old, NULL);
			return EV_EINTR;
		}

		int sig = evi_unix_conv_signal(res);
		if (sig < 0) continue;

		*pres = sig;
		ev_setmask(SIG_SETMASK, &old, NULL);
		return EV_OK;
	}
}

ev_code_t evs_getpath(char **pres, ev_path_type_t type) {
	switch (type) {
		case EV_PATH_HOME: {
			char *res = evi_generic_getenvpath(NULL);
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
				errno = 0;
				if (getcwd(buff, buffn)) break;
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
		if (unsetenv(name) < 0) return evi_unix_conv_errno(errno);
	}
	else {
		if (setenv(name, val, true) < 0) return evi_unix_conv_errno(errno);
	}

	return EV_OK;
}
ev_code_t evs_nextenv(void **pit, const char **ppair) {
	char **it = *pit;
	if (!it) it = environ;

	char *pair = *it;
	if (pair) it++;

	*pit = it;
	*ppair = pair;
	return EV_OK;
}

ev_code_t evs_realtime(ev_time_t *pres) {
	struct timespec res;
	if (clock_gettime(CLOCK_REALTIME, &res) < 0) return -1;
	*pres = (ev_time_t) { .sec = res.tv_sec, .nsec = res.tv_nsec };
	return EV_OK;
}
ev_code_t evs_monotime(ev_time_t *pres) {
	struct timespec res;
	if (clock_gettime(CLOCK_MONOTONIC, &res) < 0) return -1;
	*pres = (ev_time_t) { .sec = res.tv_sec, .nsec = res.tv_nsec };
	return EV_OK;
}

void evs_sleep(ev_time_t time) {
	struct timespec req = { .tv_sec = time.sec, .tv_nsec = time.nsec };
	while (true) {
		if (nanosleep(&req, NULL) == 0) break;
		if (errno == EINTR) continue;
	}
}

static ev_code_t evi_sync_init(ev_t ev) {
	if (!_sig_init) {
		_sig_init = true;

		ev_mutex_new(_sig_mut);
		memset(_sig_counts, 0, sizeof _sig_counts);
		sigemptyset(&_sig_set);
	}

	ev->in = evi_unix_mkfd(STDIN_FILENO);
	ev->out = evi_unix_mkfd(STDOUT_FILENO);
	ev->err = evi_unix_mkfd(STDERR_FILENO);

	return EV_OK;
}
static ev_code_t evi_sync_free(ev_t ev) {
	evi_unix_freefd(ev->in);
	evi_unix_freefd(ev->out);
	evi_unix_freefd(ev->err);
	return EV_OK;
}
