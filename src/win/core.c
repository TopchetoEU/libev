#pragma once
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ev/conf.h"
#include "ev/errno.h"
#include "ev.h"
#include "common.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <handleapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <shlobj.h>
#include <processenv.h>
#include <processthreadsapi.h>
#include <synchapi.h>

// FIXME: never before run code, shat it out in an evening.
// Consider windows as unsupported, until I can be bothered to cross-compile luajit

#define COMBINE64(a, b) (((uint64_t)(b) << 32) | (a))

static SOCKET evi_win_sock_new(ev_proto_t proto, ev_addr_type_t type) {
	return socket(
		type == EV_ADDR_IPV4 ? AF_INET : AF_INET6,
		proto == EV_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
		proto == EV_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP
	);
}

static char *evi_win_getpath(int id, const char *suffix) {
	char *res = suffix ? malloc(MAX_PATH + strlen(suffix) + 1) : malloc(MAX_PATH);
	if (!res) return NULL;
	if (SHGetFolderPath(NULL, id, NULL, 0, res) != S_OK) return NULL;

	if (suffix) strcpy(res, suffix);
	res = realloc(res, strlen(res) + 1);
	return res;
}

static int evi_win_child_std_new(
	DWORD std,
	HANDLE *pparent,
	HANDLE *pchild,
	ev_spawn_stdio_flags_t flags,
	ev_handle_t *pfd
) {
	switch (flags) {
		case EV_SPAWN_STD_INHERIT: {
			*pparent = *pchild = GetStdHandle(std);
			break;
		}
		case EV_SPAWN_STD_DUP: {
			if ((*pfd)->kind != EVI_WIN_HND) return EV_ENOTSUP;
			*pparent = *pchild = *pfd;
			break;
		}
		case EV_SPAWN_STD_PIPE: {
			SECURITY_ATTRIBUTES attribs = { .nLength = sizeof attribs, .bInheritHandle = true };

			if (std == STD_INPUT_HANDLE) {
				if (!CreatePipe(pchild, pparent, &attribs, 0)) return -1;
			}
			else {
				if (!CreatePipe(pparent, pchild, &attribs, 0)) return -1;
			}

			if (!SetHandleInformation(*pparent, HANDLE_FLAG_INHERIT, 0)) return -1;

			break;
		}
	}

	return 0;
}

static char *evi_win_argv_to_cmdline(const char **argv) {
	size_t n = 0, buff_n = 0;

	for (const char **it = argv; *it; it++) {
		n++;
		buff_n += 1 /* " */ + strlen(*it) * 2 /* Assuming each one is \ */ + 1 /* " */ + 1 /* Trailing space / \0 */;
	}

	char *buff = malloc(buff_n);
	if (!buff) return NULL;

	char *curr = buff;

	for (size_t i = 0; i < n; i++) {
		const char *arg = argv[i];

		*(curr++) = '\"';

		size_t back_n = 0;

		for (const char *it = arg; *it; it++) {
			if (*it == '\\') back_n++;
			else if (*it == '\"') {
				for (size_t i = 0; i < back_n; i++) {
					*(curr++) = '\\';
					*(curr++) = '\\';
				}
				*(curr++) = '\\';
				*(curr++) = '\"';
				back_n = 0;
			}
			else {
				for (size_t i = 0; i < back_n; i++) {
					*(curr++) = '\\';
				}
				back_n = 0;
				*(curr++) = *it;
			}
		}

		for (size_t i = 0; i < back_n; i++) {
			*(curr++) = '\\';
			*(curr++) = '\\';
		}

		*(curr++) = '\"';

		if (i == n - 1) *(curr++) = '\0';
		else *(curr++) = ' ';
	}

	return buff;
}
static char *evi_win_envp_to_envblock(const char **envp) {
	if (!envp) return NULL;

	size_t n = 0, buff_n = 0;

	for (const char **it = envp; *it; it++) {
		n++;
		buff_n += strlen(*it) + 1 /* terminating \0 */;
	}

	char *buff = malloc(buff_n + 1 /* terminating \0 */);
	char *curr = buff;

	for (size_t i = 0; i < n; i++) {
		curr = strcpy(curr, envp[i]) + 1;
	}
	*curr = '\0';

	return buff;
}

static ev_code_t evi_sync_read(ev_handle_t fd, char *buff, size_t *pn) {
	switch (fd->kind) {
		case EVI_WIN_HND: {
			DWORD out_n;

			if (!ReadFile(fd->hnd, (void*)buff, *pn, &out_n, NULL)) {
				if (GetLastError() == ERROR_HANDLE_EOF || GetLastError() == ERROR_BROKEN_PIPE) {
					*pn = 0;
					return EV_OK;
				}

				return evi_win_conv_errno(GetLastError());
			}
			*pn = out_n;
			return EV_OK;
		}
		case EVI_WIN_SOCK: {
			int res = recv(fd->sock, (void*)buff, *pn, 0);
			if (res < 0) return evi_win_conv_errno(WSAGetLastError());

			*pn = res;
			return EV_OK;
		}
		default: return EV_EBADF;
	}
}
static ev_code_t evi_sync_write(ev_handle_t fd, char *buff, size_t *pn) {
	switch (fd->kind) {
		case EVI_WIN_HND: {
			DWORD out_n;

			if (!WriteFile(fd->hnd, (void*)buff, *pn, &out_n, NULL)) {
				if (GetLastError() == ERROR_HANDLE_EOF || GetLastError() == ERROR_BROKEN_PIPE) {
					*pn = 0;
					return EV_OK;
				}

				return evi_win_conv_errno(GetLastError());
			}
			*pn = out_n;
			return EV_OK;
		}
		case EVI_WIN_SOCK: {
			int res = send(fd->sock, (void*)buff, *pn, 0);
			if (res < 0) return evi_win_conv_errno(WSAGetLastError());

			*pn = res;
			return EV_OK;
		}
		default: return EV_EBADF;
	}
}
void ev_close(ev_t ev, ev_handle_t fd) {
	(void)ev;
	switch (fd->kind) {
		case EVI_WIN_HND:
			CloseHandle(fd->hnd);
			break;
		case EVI_WIN_SOCK:
			closesocket(fd->sock);
			break;
	}
}

static ev_code_t evi_sync_file_open(ev_handle_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	(void)mode;
	DWORD access = 0;
	DWORD access_others = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create_mode = 0;
	DWORD res_flags = 0;
	SECURITY_ATTRIBUTES sec_attribs = { 0 };
	sec_attribs.nLength = sizeof sec_attribs;

	if (flags & EV_OPEN_APPEND) {
		flags |= EV_OPEN_WRITE;
	}

	if (flags & EV_OPEN_READ) {
		access |= FILE_GENERIC_READ;
		access_others &= ~(FILE_SHARE_DELETE);
	}
	if (flags & EV_OPEN_WRITE) {
		access |= FILE_GENERIC_WRITE;
		access_others &= ~(FILE_SHARE_DELETE | FILE_SHARE_WRITE);

		if (!(flags & EV_OPEN_APPEND)) {
			access &= ~FILE_APPEND_DATA;
		}
	}

	switch (flags & (EV_OPEN_CREATE | EV_OPEN_TRUNC)) {
		case 0: create_mode = OPEN_EXISTING; break;
		case EV_OPEN_CREATE: create_mode = OPEN_ALWAYS; break;
		case EV_OPEN_TRUNC: create_mode = TRUNCATE_EXISTING; break;
		case EV_OPEN_CREATE | EV_OPEN_TRUNC: create_mode = CREATE_ALWAYS; break;
	}

	if (flags & EV_OPEN_DIRECT) {
		res_flags |= FILE_FLAG_WRITE_THROUGH;
	}

	if (flags & EV_OPEN_SHARED) {
		sec_attribs.bInheritHandle = true;
	}

	HANDLE hnd = CreateFile(path, access, access_others, NULL, create_mode, FILE_ATTRIBUTE_NORMAL | res_flags, NULL);
	if (hnd == INVALID_HANDLE_VALUE) return evi_win_conv_errno(GetLastError());

	*pres = evi_win_mkhnd(hnd);
	return EV_OK;
}
static ev_code_t evi_sync_file_read(ev_handle_t fd, const char *buff, size_t *n, size_t offset) {
	if (fd->kind != EVI_WIN_HND) return EV_EBADF;

	DWORD out_n;
	OVERLAPPED overlapped = { .Pointer = (void*)offset };

	if (!ReadFile(fd->hnd, (void*)buff, *n, &out_n, &overlapped)) {
		if (GetLastError() == ERROR_HANDLE_EOF || GetLastError() == ERROR_BROKEN_PIPE) {
			*n = 0;
			return EV_OK;
		}

		return evi_win_conv_errno(GetLastError());
	}
	*n = out_n;
	return EV_OK;
}
static ev_code_t evi_sync_file_write(ev_handle_t fd, char *buff, size_t *n, size_t offset) {
	if (fd->kind != EVI_WIN_HND) return EV_EBADF;

	DWORD out_n;
	OVERLAPPED overlapped = { .Pointer = (void*)offset };

	if (!WriteFile(fd->hnd, buff, *n, &out_n, &overlapped)) {
		if (GetLastError() == ERROR_HANDLE_EOF) {
			*n = 0;
			return EV_OK;
		}

		return evi_win_conv_errno(GetLastError());
	}
	*n = out_n;
	return EV_OK;
}
static ev_code_t evi_sync_file_sync(ev_handle_t fd) {
	if (fd->kind != EVI_WIN_HND) return EV_EBADF;
	if (!FlushFileBuffers(fd->hnd)) return evi_win_conv_errno(GetLastError());
	return EV_OK;
}
static ev_code_t evi_sync_file_stat(ev_handle_t fd, ev_stat_t *buff) {
	if (fd->kind != EVI_WIN_HND) return EV_EBADF;

	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(fd->hnd, &info)) return evi_win_conv_errno(GetLastError());

	// Fake it till we make it .-.

	if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
		buff->mode = 0555;
	}
	else {
		buff->mode = 0777;
	}

	if (info.dwFileAttributes & FILE_ATTRIBUTE_NORMAL) {
		buff->type = EV_STAT_REG;
	}
	else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		buff->type = EV_STAT_DIR;
	}
	else if (info.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) {
		buff->type = EV_STAT_BLK;
	}
	else if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		buff->type = EV_STAT_LINK;
		buff->mode = 0777;
	}

	buff->uid = 1000;
	buff->gid = 1000;

	buff->atime = evi_win_conv_filetime(info.ftLastAccessTime);
	buff->mtime = evi_win_conv_filetime(info.ftLastWriteTime);
	// The semantics of this are dubious, do we equate the creation of a file to the last change of its metadata
	// TODO: look into this further
	buff->ctime = evi_win_conv_filetime(info.ftCreationTime);

	buff->size = COMBINE64(info.nFileSizeLow, info.nFileSizeHigh);
	// TODO: does windows expose a preferred blk size somehow? For now, we pick a reasonable arbitrary blksize
	buff->blksize = 4096;

	buff->inode = COMBINE64(info.nFileIndexLow, info.nFileIndexHigh);
	buff->links = info.nNumberOfLinks;

	return EV_OK;
}

static ev_code_t evi_sync_dir_new(const char *path, int mode) {
	(void)mode;
	if (!CreateDirectory(path, NULL)) return evi_win_conv_errno(GetLastError());
	return EV_OK;
}
static ev_code_t evi_sync_dir_open(ev_dir_t *pres, const char *path) {
	char *pattern = malloc(strlen(path) + 3);
	if (!pattern) return EV_ENOMEM;

	sprintf(pattern, "%s\\*", path);
	evi_win_fix_path(pattern);

	WIN32_FIND_DATAA data;
	memset(&data, 0, sizeof data);
	HANDLE hnd = FindFirstFileA(pattern, &data);
	free(pattern);
	if (hnd == INVALID_HANDLE_VALUE) return evi_win_conv_errno(GetLastError());

	ev_dir_t res = malloc(sizeof *res);
	if (!res) return EV_ENOMEM;

	res->data = data;
	res->hnd = hnd;
	res->done = false;
	*pres = res;
	return EV_OK;
}
static ev_code_t evi_sync_dir_next(ev_dir_t dir, char **pname) {
	while (true) {
		if (dir->done) {
			*pname = NULL;
			return EV_OK;
		}

		*pname = strdup(dir->data.cFileName);
		if (!FindNextFileA(dir->hnd, &dir->data)) {
			if (GetLastError() == ERROR_NO_MORE_FILES) {
				dir->done = true;
			}
			else {
				return evi_win_conv_errno(GetLastError());
			}
		}

		if (!strcmp(*pname, ".")) continue;
		if (!strcmp(*pname, "..")) continue;
		return EV_OK;
	}
}
void ev_dir_close(ev_t ev, ev_dir_t dir) {
	(void)ev;
	FindClose(dir->hnd);
	free(dir);
}

static ev_code_t evi_sync_server_bind(ev_server_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
	SOCKET sock = evi_win_sock_new(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_errno(WSAGetLastError());

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&(int) { 1 }, sizeof(int)) < 0) {
		closesocket(sock);
		return evi_win_conv_errno(WSAGetLastError());
	}

	struct sockaddr_storage arg_addr;
	int len = evi_win_conv_addr(addr, port, &arg_addr);

	if (bind(sock, (void*)&arg_addr, len) < 0) {
		closesocket(sock);
		return evi_win_conv_errno(WSAGetLastError());
	}
	if (listen(sock, max_n) < 0) {
		closesocket(sock);
		return evi_win_conv_errno(WSAGetLastError());
	}

	*pres = (void*)(size_t)sock;
	return EV_OK;
}
static ev_code_t evi_sync_server_accept(ev_handle_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_server_t server) {
	struct sockaddr_storage addr = {};
	socklen_t addr_len = sizeof addr;

	SOCKET client = accept((SOCKET)(size_t)server, (void*)&addr, &addr_len);
	if (!client) return evi_win_conv_errno(WSAGetLastError());

	evi_win_conv_sockaddr(&addr, paddr, pport);

	*pres = (void*)(size_t)client;
	return EV_OK;
}
void ev_server_close(ev_t ev, ev_server_t server) {
	(void)ev;
	closesocket((SOCKET)(size_t)server);
}

static ev_code_t evi_sync_socket_connect(ev_handle_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	SOCKET sock = evi_win_sock_new(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_errno(WSAGetLastError());

	struct sockaddr_storage arg_addr;
	int len = evi_win_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_win_conv_errno(WSAGetLastError());

	*pres = evi_win_mksock(sock);
	return EV_OK;
}

static int evi_sync_spawn(
	ev_proc_t *pres,
	const char **argv, const char **envp,
	const char *cwd,
	ev_spawn_stdio_flags_t in_flags, ev_handle_t *pin,
	ev_spawn_stdio_flags_t out_flags, ev_handle_t *pout,
	ev_spawn_stdio_flags_t err_flags, ev_handle_t *perr
) {
	HANDLE in_parent, in_child;
	HANDLE out_parent, out_child;
	HANDLE err_parent, err_child;

	if (evi_win_child_std_new(STD_INPUT_HANDLE, &in_parent, &in_child, in_flags, pin) < 0) goto err;
	if (evi_win_child_std_new(STD_OUTPUT_HANDLE, &out_parent, &out_child, out_flags, pout) < 0) goto err_in_pipe;
	if (evi_win_child_std_new(STD_ERROR_HANDLE, &err_parent, &err_child, err_flags, perr) < 0) goto err_out_pipe;

	char *cmdline = evi_win_argv_to_cmdline(argv);
	if (!cmdline) goto err_err_pipe;

	char *envblock = evi_win_envp_to_envblock(envp);
	if (!envblock) goto err_cmdline;

	STARTUPINFOA start_info = { .cb = sizeof start_info };
	start_info.hStdInput  = in_child;
	start_info.hStdOutput = out_child;
	start_info.hStdError  = err_child;
	start_info.dwFlags |= STARTF_USESTDHANDLES;

	PROCESS_INFORMATION proc_info;
	BOOL res = CreateProcess(argv[0], cmdline, NULL, NULL, true, 0, envblock, cwd, &start_info, &proc_info);
	if (!res || !proc_info.hProcess) goto err_envblock;

	free(cmdline);
	free(envblock);

	if (in_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(in_child);
		*pin = evi_win_mkhnd(in_parent);
	}
	if (out_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(out_child);
		*pout = evi_win_mkhnd(out_parent);
	}
	if (err_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(err_child);
		*perr = evi_win_mkhnd(err_parent);
	}

	*pres = proc_info.hProcess;
	CloseHandle(proc_info.hThread);

	return 0;
err_envblock:
	free(envblock);
err_cmdline:
	free(cmdline);
err_err_pipe:
	if (err_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(err_parent);
		CloseHandle(err_child);
	}
err_out_pipe:
	if (out_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(out_parent);
		CloseHandle(out_child);
	}
err_in_pipe:
	if (in_flags == EV_SPAWN_STD_PIPE) {
		CloseHandle(in_parent);
		CloseHandle(in_child);
	}
err:
	return evi_win_conv_errno(GetLastError());
}
ev_code_t evi_sync_wait(ev_proc_t proc, int *psig, int *pcode) {
	switch (WaitForSingleObject(proc, INFINITE)) {
		case WAIT_ABANDONED:
			return EV_EDEADLK;
		case WAIT_OBJECT_0:
			break;
		case WAIT_TIMEOUT:
			return EV_ETIMEDOUT;
		case WAIT_FAILED:
			return evi_win_conv_errno(GetLastError());
	}

	DWORD code;
	if (!GetExitCodeProcess(proc, &code)) return evi_win_conv_errno(GetLastError());

	CloseHandle(proc);

	*psig = -1;
	*pcode = code;

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
		case EAI_NODATA: break;
		case EAI_NONAME: break;
		case EAI_SOCKTYPE: return EV_EINVAL;
		case EAI_BADFLAGS: return EV_EINVAL;
		case EAI_FAMILY: return EV_ENOTSUP;
		case EAI_MEMORY: return EV_ENOMEM;
		case EAI_AGAIN: return EV_EAGAIN;
		case EAI_FAIL: return EV_EIO;
	}

	size_t n = 0;
	for (struct addrinfo *it = list; it; it = it->ai_next) n++;

	ev_addrinfo_t res = malloc(sizeof *res + sizeof *res->addr * n);
	if (!res) return EV_ENOMEM;

	size_t i = 0;
	for (struct addrinfo *it = list; it; it = it->ai_next) {
		uint16_t port;
		ev_addr_t addr;
		evi_win_conv_sockaddr((void*)it->ai_addr, &addr, &port);

		bool found = false;

		for (size_t j = 0; j < i; j++) {
			if (!memcmp(&addr, &res->addr[j], sizeof addr)) {
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
			char *res = evi_win_getpath(CSIDL_PROFILE, NULL);
			if (!res) return evi_win_conv_errno(GetLastError());

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_RUNTIME:
		case EV_PATH_CACHE: {
			char *res = evi_win_getpath(CSIDL_LOCAL_APPDATA, "\\Temp");
			if (!res) return evi_win_conv_errno(GetLastError());

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_CONFIG: {
			char *res = evi_win_getpath(CSIDL_APPDATA, NULL);
			if (!res) return evi_win_conv_errno(GetLastError());

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_DATA: {
			char *res = evi_win_getpath(CSIDL_LOCAL_APPDATA, NULL);
			if (!res) return evi_win_conv_errno(GetLastError());

			*pres = res;
			return EV_OK;
		}
		case EV_PATH_CWD: {
			char *path = malloc(MAX_PATH + 1);
			if (!path) return evi_win_conv_errno(GetLastError());
			if (!GetCurrentDirectory(sizeof path, path)) return evi_win_conv_errno(GetLastError());

			path = realloc(path, strlen(path) + 1);
			*pres = path;
			return EV_OK;
		}
	}

	return EV_EINVAL;
}

static void evi_sleep(ev_time_t time) {
	Sleep(ev_timems(time));
}

int ev_realtime(ev_time_t *pres) {
	FILETIME time;
	GetSystemTimePreciseAsFileTime(&time);
	*pres = evi_win_conv_filetime(time);
	return EV_OK;
}
int ev_monotime(ev_time_t *pres) {
	LARGE_INTEGER counter, freq;
	QueryPerformanceCounter(&counter);
	QueryPerformanceFrequency(&freq);

	*pres = (ev_time_t) {
		.sec = counter.QuadPart / freq.QuadPart,
		.nsec = (uint64_t)(counter.QuadPart % freq.QuadPart) * 1000000000LL / freq.QuadPart,
	};


	return EV_OK;
}

static int evi_stdio_init(ev_handle_t *in, ev_handle_t *out, ev_handle_t *err) {
	*in = evi_win_mkhnd(GetStdHandle(STD_INPUT_HANDLE));
	*out = evi_win_mkhnd(GetStdHandle(STD_OUTPUT_HANDLE));
	*err = evi_win_mkhnd(GetStdHandle(STD_ERROR_HANDLE));

	return EV_OK;
}
static int evi_stdio_free(ev_handle_t in, ev_handle_t out, ev_handle_t err) {
	free(in);
	free(out);
	free(err);
	return EV_OK;
}
