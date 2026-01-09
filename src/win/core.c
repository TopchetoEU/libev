#pragma once
#include <errno.h>
#pragma GCC diagnostic ignored "-Wunused-function"

#include "common.h"
#include "ev.h"

#include <windows.h>

#include <errhandlingapi.h>
#include <fileapi.h>
#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <processenv.h>
#include <psdk_inc/_ip_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>

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

static int evi_sync_open(ev_fd_t *pres, const char *path, ev_open_flags_t flags, int mode) {
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

	ev_fd_t res = malloc(sizeof *res);
	if (!res) return ENOMEM;

	res->kind = EVI_WIN_FILE;
	res->file = fd;

	*pres = res;
	return 0;
}
static int evi_sync_read(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	switch (fd->kind) {
		case EVI_WIN_FILE: {
			DWORD out_n;
			OVERLAPPED overlapped = { .Pointer = (void*)offset };

			if (!ReadFile(fd->file, buff, *n, &out_n, &overlapped)) {
				if (GetLastError() == ERROR_HANDLE_EOF) {
					*n = 0;
					return 0;
				}

				return evi_win_conv_errno(GetLastError());
			}
			*n = out_n;
			return 0;
		}
		case EVI_WIN_SOCK: {
			int res = recv(fd->socket, buff, *n, 0);
			if (res < 0) return evi_win_conv_sockerr(WSAGetLastError());

			*n = res;
			return 0;
		}
	}
}
static int evi_sync_write(ev_fd_t fd, char *buff, size_t *n, size_t offset) {
	switch (fd->kind) {
		case EVI_WIN_FILE: {
			DWORD out_n;
			OVERLAPPED overlapped = { .Pointer = (void*)offset };

			if (!WriteFile(fd->file, buff, *n, &out_n, &overlapped)) {
				if (GetLastError() == ERROR_HANDLE_EOF) {
					*n = 0;
					return 0;
				}

				return evi_win_conv_errno(GetLastError());
			}
			*n = out_n;
			return 0;
		}
		case EVI_WIN_SOCK: {
			int res = send(fd->socket, buff, *n, 0);
			if (res < 0) return evi_win_conv_sockerr(WSAGetLastError());

			*n = res;
			return 0;
		}
	}
}
static int evi_sync_stat(ev_fd_t fd, ev_stat_t *buff) {
	if (fd->kind != EVI_WIN_FILE) return EBADF;

	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(fd->file, &info)) return evi_win_conv_errno(GetLastError());

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

	buff->atime = evi_win_conv_timespec(info.ftLastAccessTime);
	buff->mtime = evi_win_conv_timespec(info.ftLastWriteTime);
	// The semantics of this are dubious, do we equate the creation of a file to the last change of its metadata
	// TODO: look into this further
	buff->ctime = evi_win_conv_timespec(info.ftCreationTime);

	buff->size = COMBINE64(info.nFileSizeLow, info.nFileSizeHigh);
	// TODO: does windows expose a preferred blk size somehow? For now, we pick a reasonable arbitrary blksize
	buff->blksize = 4096;

	buff->inode = COMBINE64(info.nFileIndexLow, info.nFileIndexHigh);
	buff->links = info.nNumberOfLinks;

	return 0;
}
void ev_close(ev_t ev, ev_fd_t fd) {
	switch (fd->kind) {
		case EVI_WIN_FILE:
			CloseHandle(fd->file);
			break;
		case EVI_WIN_SOCK:
			closesocket(fd->socket);
			break;
	}
	free(fd);
}

static int evi_sync_mkdir(const char *path, int mode) {
	if (!CreateDirectory(path, NULL)) return evi_win_conv_errno(GetLastError());
	return 0;
}
static int evi_sync_opendir(ev_dir_t *pres, const char *path) {
	char *pattern = malloc(strlen(path) + 3);
	if (!pattern) return ENOMEM;

	sprintf(pattern, "%s\\*", path);
	evi_win_fix_path(pattern);

	WIN32_FIND_DATAA data;
	memset(&data, 0, sizeof data);
	HANDLE hnd = FindFirstFileA(pattern, &data);
	free(pattern);
	if (hnd == INVALID_HANDLE_VALUE) return evi_win_conv_errno(GetLastError());

	ev_dir_t res = malloc(sizeof *res);
	if (!res) return ENOMEM;

	res->data = data;
	res->hnd = hnd;
	res->done = false;
	*pres = res;
	return 0;
}
static int evi_sync_readdir(ev_dir_t dir, char **pname) {
	while (true) {
		if (dir->done) {
			*pname = NULL;
			return 0;
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
		return 0;
	}
}
void ev_closedir(ev_t ev, ev_dir_t dir) {
	FindClose(dir->hnd);
	free(dir);
}


static int evi_sync_connect(ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	SOCKET sock = evi_win_mksock(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_sockerr(WSAGetLastError());

	struct sockaddr_storage arg_addr;
	int len = evi_win_conv_addr(addr, port, &arg_addr);

	if (connect(sock, (void*)&arg_addr, len) < 0) return evi_win_conv_sockerr(WSAGetLastError());

	ev_fd_t res = malloc(sizeof *res);
	if (!res) return ENOMEM;

	res->kind = EVI_WIN_SOCK;
	res->socket = sock;
	*pres = res;
	return 0;
}
static int evi_sync_bind(ev_fd_t *pres, ev_proto_t proto, ev_addr_t addr, uint16_t port) {
	SOCKET sock = evi_win_mksock(proto, addr.type);
	if (sock == INVALID_SOCKET) return evi_win_conv_sockerr(WSAGetLastError());

	struct sockaddr_storage arg_addr;
	int len = evi_win_conv_addr(addr, port, &arg_addr);

	if (bind(sock, (void*)&arg_addr, len) < 0) return evi_win_conv_sockerr(WSAGetLastError());

	ev_fd_t res = malloc(sizeof *res);
	if (!res) return ENOMEM;

	res->kind = EVI_WIN_SOCK;
	res->socket = sock;
	*pres = res;
	return 0;
}
static int evi_sync_accept(ev_fd_t *pres, ev_addr_t *paddr, uint16_t *pport, ev_fd_t server) {
	if (server->kind != EVI_WIN_SOCK) return EINVAL;

	struct sockaddr_storage addr;
	int addr_len;

	SOCKET client = accept(server->socket, (void*)&addr, &addr_len);
	if (!client) return evi_win_conv_sockerr(WSAGetLastError());

	evi_win_conv_sockaddr(&addr, paddr, pport);

	ev_fd_t res = malloc(sizeof *res);
	if (!res) return ENOMEM;

	res->kind = EVI_WIN_SOCK;
	res->socket = client;
	*pres = res;
	return 0;
}
static int evi_sync_getaddrinfo(ev_addrinfo_t *pres, const char *name, ev_addrinfo_flags_t flags) {
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
		case EAI_SOCKTYPE: return EINVAL;
		case EAI_BADFLAGS: return EINVAL;
		case EAI_FAMILY: return ENOTSUP;
		case EAI_MEMORY: return ENOMEM;
		case EAI_AGAIN: return EAGAIN;
		case EAI_FAIL: return EIO;
	}

	size_t n = 0;
	for (struct addrinfo *it = list; it; it = it->ai_next) n++;

	ev_addrinfo_t res = malloc(sizeof *res + sizeof *res->addr * n);
	if (!res) return ENOMEM;

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
	return 0;
}

static int evi_stdio_init(ev_fd_t *in, ev_fd_t *out, ev_fd_t *err) {
	*in = malloc(sizeof *in);
	if (!*in) return ENOMEM;
	(*in)->kind = EVI_WIN_FILE;
	(*in)->file = GetStdHandle(STD_INPUT_HANDLE);

	*out = malloc(sizeof *out);
	if (!*out) return ENOMEM;
	(*out)->kind = EVI_WIN_FILE;
	(*out)->file = GetStdHandle(STD_OUTPUT_HANDLE);

	*err = malloc(sizeof *err);
	if (!*err) return ENOMEM;
	(*err)->kind = EVI_WIN_FILE;
	(*err)->file = GetStdHandle(STD_ERROR_HANDLE);
}
static void evi_stdio_free(ev_fd_t in, ev_fd_t out, ev_fd_t err) {
	free(in);
	free(out);
	free(err);
}
