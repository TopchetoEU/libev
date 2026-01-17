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

// FIXME: never before run code, shat it out in an evening.
// Consider windows as unsupported, until I can be bothered to cross-compile luajit

#define COMBINE64(a, b) (((uint64_t)(b) << 32) | (a))

static SOCKET evi_win_mksock(ev_proto_t proto, ev_addr_type_t type) {
	return socket(
		type == EV_ADDR_IPV4 ? AF_INET : AF_INET6,
		proto == EV_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
		proto == EV_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP
	);
}

static ev_code_t evi_sync_open(ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
	(void)mode;
	DWORD access = 0;
	DWORD access_others = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	DWORD create_mode = 0;
	DWORD res_flags = 0;

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

	HANDLE fd = CreateFile(path, access, access_others, NULL, create_mode, FILE_ATTRIBUTE_NORMAL | res_flags, NULL);
	if (fd == INVALID_HANDLE_VALUE) return evi_win_conv_errno(GetLastError());

	*pres = fd;
	return EV_OK;
}
static ev_code_t evi_sync_read(ev_fd_t fd, const char *buff, size_t *n, size_t offset) {
	DWORD out_n;
	OVERLAPPED overlapped = { .Pointer = (void*)offset };

	if (!ReadFile(fd, (void*)buff, *n, &out_n, &overlapped)) {
		if (GetLastError() == ERROR_HANDLE_EOF) {
			*n = 0;
			return EV_OK;
		}

		return evi_win_conv_errno(GetLastError());
	}
	*n = out_n;
	return EV_OK;
}
static ev_code_t evi_sync_write(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	DWORD out_n;
	OVERLAPPED overlapped = { .Pointer = (void*)offset };

	if (!WriteFile(fd, buff, *n, &out_n, &overlapped)) {
		if (GetLastError() == ERROR_HANDLE_EOF) {
			*n = 0;
			return EV_OK;
		}

		return evi_win_conv_errno(GetLastError());
	}
	*n = out_n;
	return EV_OK;
}
static ev_code_t evi_sync_stat(ev_fd_t fd, ev_stat_t *buff) {
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(fd, &info)) return evi_win_conv_errno(GetLastError());

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
void ev_close(ev_t ev, ev_fd_t fd) {
	CloseHandle(fd);
}

static ev_code_t evi_sync_mkdir(const char *path, int mode) {
	(void)mode;
	if (!CreateDirectory(path, NULL)) return evi_win_conv_errno(GetLastError());
	return EV_OK;
}
static ev_code_t evi_sync_opendir(ev_dir_t *pres, const char *path) {
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
static ev_code_t evi_sync_readdir(ev_dir_t dir, char **pname) {
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
void ev_closedir(ev_t ev, ev_dir_t dir) {
	(void)ev;
	FindClose(dir->hnd);
	free(dir);
}

static ev_code_t evi_sync_connect(ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	SOCKET sock = evi_win_mksock(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_errno(WSAGetLastError());

	struct sockaddr_storage arg_addr;
	int len = evi_win_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_win_conv_errno(WSAGetLastError());

	*pres = (void*)sock;
	return EV_OK;
}
static ev_code_t evi_sync_bind(ev_socket_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port, size_t max_n) {
	SOCKET sock = evi_win_mksock(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_errno(WSAGetLastError());

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int)) < 0) {
		close(sock);
		return evi_unix_conv_errno(errno);
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

	*pres = (void*)sock;
	return EV_OK;
}
static ev_code_t evi_sync_recv(ev_socket_t sock, char *buff, size_t *pn) {
	int res = recv((SOCKET)sock, (void*)buff, *pn, 0);
	if (res < 0) return evi_win_conv_errno(WSAGetLastError());

	*pn = res;
	return EV_OK;
}
static ev_code_t evi_sync_send(ev_socket_t sock, char *buff, size_t *pn) {
	int res = send((SOCKET)sock, (void*)buff, *pn, 0);
	if (res < 0) return evi_win_conv_errno(WSAGetLastError());

	*pn = res;
	return EV_OK;
}
static ev_code_t evi_sync_accept(ev_socket_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_socket_t server) {
	struct sockaddr_storage addr = {};
	socklen_t addr_len = sizeof addr;

	SOCKET client = accept((SOCKET)server, (void*)&addr, &addr_len);
	if (!client) return evi_win_conv_errno(WSAGetLastError());

	evi_win_conv_sockaddr(&addr, paddr, pport);

	*pres = (void*)client;
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

static char *evi_win_getpath(int id, const char *suffix) {
	char *res = suffix ? malloc(MAX_PATH + strlen(suffix) + 1) : malloc(MAX_PATH);
	if (!res) return NULL;
	if (SHGetFolderPath(NULL, id, NULL, 0, res) != S_OK) return NULL;

	if (suffix) strcpy(res, suffix);
	res = realloc(res, strlen(res) + 1);
	return res;
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

	// fprintf(stderr, "MONOTIME %lld.%.9u\n", pres->sec, pres->nsec);
	// fprintf(stderr, "MONOTIME MS %lld\n", ev_timems(*pres));

	return EV_OK;
}

static int evi_stdio_init(ev_fd_t *in, ev_fd_t *out, ev_fd_t *err) {
	*in = GetStdHandle(STD_INPUT_HANDLE);
	*out = GetStdHandle(STD_OUTPUT_HANDLE);
	*err = GetStdHandle(STD_ERROR_HANDLE);

	return EV_OK;
}
static int evi_stdio_free(ev_fd_t in, ev_fd_t out, ev_fd_t err) {
	return EV_OK;
}
