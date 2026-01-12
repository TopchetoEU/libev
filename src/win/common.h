#pragma once
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ev.h"
#include "ev/errno.h"
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <winsock2.h>
#include <ws2ipdef.h>

struct ev_fd {
	enum {
		EVI_WIN_FILE,
		EVI_WIN_SOCK,
	} kind;
	union {
		HANDLE file;
		SOCKET socket;
	};
};

struct ev_dir {
	HANDLE hnd;
	bool done;
	WIN32_FIND_DATAA data;
};

static ev_time_t evi_win_conv_filetime(FILETIME filetime) {
	static const uint64_t EPOCH_DIFFERENCE = 11644473600;

	uint64_t total_ticks = ((uint64_t)filetime.dwHighDateTime << 32) | (uint64_t)filetime.dwLowDateTime;

	return (ev_time_t) {
		.sec = (time_t)(total_ticks / 100000000) - EPOCH_DIFFERENCE,
		.nsec = (long)(total_ticks % 100000000) * 100,
	};
}
static ev_code_t evi_win_conv_errno(int winerr) {
	switch (winerr) {
		case ERROR_ACCESS_DENIED: return EV_EPERM;
		case ERROR_ACTIVE_CONNECTIONS: return EV_EAGAIN;
		case ERROR_ADDRESS_ALREADY_ASSOCIATED:  return EV_EADDRINUSE;
		case ERROR_ALREADY_EXISTS: return EV_EEXIST;
		case ERROR_BAD_DEVICE: return EV_ENODEV;
		case ERROR_BAD_EXE_FORMAT: return EV_ENOEXEC;
		case ERROR_BAD_NET_NAME: return EV_ENOENT;
		case ERROR_BAD_NET_RESP: return EV_ENOSYS;
		case ERROR_BAD_NETPATH: return EV_ENOENT;
		case ERROR_BAD_PATHNAME: return EV_ENOENT;
		case ERROR_BAD_PIPE: return EV_EPIPE;
		case ERROR_BAD_UNIT: return EV_ENODEV;
		case ERROR_BAD_USERNAME: return EV_EINVAL;
		case ERROR_BEGINNING_OF_MEDIA: return EV_EIO;
		// case ERROR_BROKEN_PIPE: return EV_EOF;
		case ERROR_BROKEN_PIPE: return EV_EPIPE;
		case ERROR_BUFFER_OVERFLOW: return EV_EFAULT;
		case ERROR_BUS_RESET: return EV_EIO;
		case ERROR_BUSY: return EV_EBUSY;
		case ERROR_CALL_NOT_IMPLEMENTED: return EV_ENOSYS;
		case ERROR_CANCELLED: return EV_EINTR;
		case ERROR_CANNOT_MAKE: return EV_EPERM;
		case ERROR_CANT_RESOLVE_FILENAME: return EV_ELOOP;
		case ERROR_CHILD_NOT_COMPLETE: return EV_EBUSY;
		case ERROR_COMMITMENT_LIMIT: return EV_EAGAIN;
		case ERROR_CONNECTION_ABORTED: return EV_ECONNABORTED;
		case ERROR_CONNECTION_REFUSED: return EV_ECONNREFUSED;
		case ERROR_CRC: return EV_EIO;
		case ERROR_DEV_NOT_EXIST: return EV_ENOENT;
		case ERROR_DEVICE_DOOR_OPEN: return EV_EIO;
		case ERROR_DEVICE_IN_USE: return EV_EAGAIN;
		case ERROR_DEVICE_REQUIRES_CLEANING: return EV_EIO;
		case ERROR_DIR_NOT_EMPTY: return EV_ENOTEMPTY;
		case ERROR_DIRECTORY: return EV_ENOTDIR;
		case ERROR_DISK_CORRUPT: return EV_EIO;
		case ERROR_DISK_FULL: return EV_ENOSPC;
		case ERROR_DS_GENERIC_ERROR: return EV_EIO;
		case ERROR_DUP_NAME: return EV_ENOTUNIQ;
		case ERROR_EA_LIST_INCONSISTENT: return EV_EINVAL;
		case ERROR_EA_TABLE_FULL: return EV_ENOSPC;
		case ERROR_EAS_DIDNT_FIT: return EV_ENOSPC;
		case ERROR_EAS_NOT_SUPPORTED: return EV_ENOTSUP;
		case ERROR_END_OF_MEDIA: return EV_ENOSPC;
		case ERROR_EOM_OVERFLOW: return EV_EIO;
		case ERROR_EXE_MACHINE_TYPE_MISMATCH: return EV_ENOEXEC;
		case ERROR_EXE_MARKED_INVALID: return EV_ENOEXEC;
		case ERROR_FILE_CORRUPT: return EV_EEXIST;
		case ERROR_FILE_EXISTS: return EV_EEXIST;
		case ERROR_FILE_INVALID: return EV_ENXIO;
		case ERROR_FILE_NOT_FOUND: return EV_ENOENT;
		case ERROR_FILEMARK_DETECTED: return EV_EIO;
		case ERROR_FILENAME_EXCED_RANGE: return EV_ENAMETOOLONG;
		case ERROR_GEN_FAILURE: return EV_EIO;
		case ERROR_HANDLE_DISK_FULL: return EV_ENOSPC;
		case ERROR_HANDLE_EOF: return EV_ENODATA;
		case ERROR_HOST_UNREACHABLE: return EV_EHOSTUNREACH;
		case ERROR_INSUFFICIENT_BUFFER: return EV_EINVAL;
		case ERROR_INVALID_ADDRESS: return EV_EINVAL;
		case ERROR_INVALID_AT_INTERRUPT_TIME: return EV_EINTR;
		case ERROR_INVALID_BLOCK_LENGTH: return EV_EIO;
		case ERROR_INVALID_DATA: return EV_EINVAL;
		case ERROR_INVALID_DRIVE: return EV_ENODEV;
		case ERROR_INVALID_EA_NAME: return EV_EINVAL;
		case ERROR_INVALID_EXE_SIGNATURE: return EV_ENOEXEC;
		case ERROR_INVALID_FLAGS: return EV_EBADF;
		case ERROR_INVALID_FUNCTION: return EV_EISDIR;
		// case ERROR_INVALID_FUNCTION: return EV_EINVAL;
		case ERROR_INVALID_HANDLE: return EV_EBADF;
		case ERROR_INVALID_NAME: return EV_ENOENT;
		case ERROR_INVALID_PARAMETER: return EV_EINVAL;
		case ERROR_INVALID_REPARSE_DATA: return EV_ENOENT;
		case ERROR_INVALID_SIGNAL_NUMBER: return EV_EINVAL;
		case ERROR_IO_DEVICE: return EV_EIO;
		case ERROR_IO_INCOMPLETE: return EV_EAGAIN;
		case ERROR_IO_PENDING: return EV_EAGAIN;
		case ERROR_IOPL_NOT_ENABLED: return EV_ENOEXEC;
		case ERROR_LOCK_VIOLATION: return EV_EBUSY;
		case ERROR_MAX_THRDS_REACHED: return EV_EAGAIN;
		case ERROR_META_EXPANSION_TOO_LONG: return EV_EINVAL;
		case ERROR_MOD_NOT_FOUND: return EV_ENOENT;
		case ERROR_MORE_DATA: return EV_EMSGSIZE;
		case ERROR_NEGATIVE_SEEK: return EV_EINVAL;
		case ERROR_NETNAME_DELETED: return EV_ECONNRESET;
		case ERROR_NETWORK_UNREACHABLE: return EV_ENETUNREACH;
		case ERROR_NO_DATA_DETECTED: return EV_EIO;
		case ERROR_NO_DATA: return EV_EPIPE;
		case ERROR_NO_MEDIA_IN_DRIVE: return EV_ENOMEDIUM;
		case ERROR_NO_MORE_FILES: return EV_ENOENT;
		case ERROR_NO_MORE_ITEMS: return EV_ENOENT;
		case ERROR_NO_MORE_SEARCH_HANDLES: return EV_ENFILE;
		case ERROR_NO_PROC_SLOTS: return EV_EAGAIN;
		case ERROR_NO_SIGNAL_SENT: return EV_EIO;
		case ERROR_NO_SYSTEM_RESOURCES: return EV_EFBIG;
		case ERROR_NO_TOKEN: return EV_EINVAL;
		case ERROR_NO_UNICODE_TRANSLATION: return EV_ECHARSET;
		case ERROR_NOACCESS: return EV_EACCES;
		case ERROR_NONE_MAPPED: return EV_EINVAL;
		case ERROR_NONPAGED_SYSTEM_RESOURCES: return EV_EAGAIN;
		case ERROR_NOT_CONNECTED: return EV_ENOTCONN;
		case ERROR_NOT_ENOUGH_MEMORY: return EV_ENOMEM;
		case ERROR_NOT_ENOUGH_QUOTA: return EV_EIO;
		case ERROR_NOT_OWNER: return EV_EPERM;
		case ERROR_NOT_READY: return EV_ENOMEDIUM;
		case ERROR_NOT_SAME_DEVICE: return EV_EXDEV;
		case ERROR_NOT_SUPPORTED: return EV_ENOTSUP;
		case ERROR_OPEN_FAILED: return EV_EIO;
		case ERROR_OPEN_FILES: return EV_EAGAIN;
		case ERROR_OPERATION_ABORTED: return EV_ECANCELED;
		case ERROR_OUTOFMEMORY: return EV_ENOMEM;
		case ERROR_PAGED_SYSTEM_RESOURCES: return EV_EAGAIN;
		case ERROR_PAGEFILE_QUOTA: return EV_EAGAIN;
		case ERROR_PATH_NOT_FOUND: return EV_ENOENT;
		case ERROR_PIPE_BUSY: return EV_EBUSY;
		case ERROR_PIPE_CONNECTED: return EV_EBUSY;
		case ERROR_PIPE_LISTENING: return EV_ECOMM;
		case ERROR_PIPE_NOT_CONNECTED: return EV_EPIPE;
		case ERROR_POSSIBLE_DEADLOCK: return EV_EDEADLK;
		case ERROR_PRIVILEGE_NOT_HELD: return EV_EPERM;
		case ERROR_PROC_NOT_FOUND: return EV_ESRCH;
		case ERROR_PROCESS_ABORTED: return EV_EFAULT;
		case ERROR_REM_NOT_LIST: return EV_ENOENT;
		case ERROR_SECTOR_NOT_FOUND: return EV_EINVAL;
		case ERROR_SEEK: return EV_ESPIPE;
		case ERROR_SEM_TIMEOUT: return EV_ETIMEDOUT;
		case ERROR_SERVICE_REQUEST_TIMEOUT: return EV_ETIMEDOUT;
		case ERROR_SETMARK_DETECTED: return EV_EIO;
		case ERROR_SHARING_BUFFER_EXCEEDED: return EV_ENOLCK;
		case ERROR_SHARING_VIOLATION: return EV_EBUSY;
		case ERROR_SIGNAL_PENDING: return EV_EBUSY;
		case ERROR_SIGNAL_REFUSED: return EV_EIO;
		case ERROR_SXS_CANT_GEN_ACTCTX: return EV_ELIBBAD;
		case ERROR_SYMLINK_NOT_SUPPORTED: return EV_EINVAL;
		case ERROR_THREAD_1_INACTIVE: return EV_EINVAL;
		case ERROR_TIMEOUT: return EV_EBUSY;
		case ERROR_TOO_MANY_LINKS: return EV_EMLINK;
		case ERROR_TOO_MANY_OPEN_FILES: return EV_EMFILE;
		case ERROR_UNEXP_NET_ERR: return EV_EIO;
		case ERROR_WAIT_NO_CHILDREN: return EV_ECHILD;
		case ERROR_WORKING_SET_QUOTA: return EV_EAGAIN;
		case ERROR_WRITE_PROTECT: return EV_EROFS;

		case WSAEACCES: return EV_EACCES;
		case WSAEADDRINUSE: return EV_EADDRINUSE;
		case WSAEADDRNOTAVAIL: return EV_EADDRNOTAVAIL;
		case WSAEAFNOSUPPORT: return EV_EAFNOSUPPORT;
		case WSAEALREADY: return EV_EALREADY;
		case WSAECONNABORTED: return EV_ECONNABORTED;
		case WSAECONNREFUSED: return EV_ECONNREFUSED;
		case WSAECONNRESET: return EV_ECONNRESET;
		case WSAEFAULT: return EV_EFAULT;
		case WSAEHOSTUNREACH: return EV_EHOSTUNREACH;
		case WSAEINTR: return EV_EINTR;
		case WSAEINVAL: return EV_EINVAL;
		case WSAEISCONN: return EV_EISCONN;
		case WSAEMFILE: return EV_EMFILE;
		case WSAEMSGSIZE: return EV_EMSGSIZE;
		case WSAENETUNREACH: return EV_ENETUNREACH;
		case WSAENOBUFS: return EV_ENOBUFS;
		case WSAENOTCONN: return EV_ENOTCONN;
		case WSAENOTSOCK: return EV_ENOTSOCK;
		case WSAEPFNOSUPPORT: return EV_EPFNOSUPPORT;
		case WSAEPROTONOSUPPORT: return EV_EPROTONOSUPPORT;
		case WSAESHUTDOWN: return EV_EPIPE;
		case WSAESOCKTNOSUPPORT: return EV_ESOCKTNOSUPPORT;
		case WSAETIMEDOUT: return EV_ETIMEDOUT;
		case WSAEWOULDBLOCK: return EV_EAGAIN;
		case WSAHOST_NOT_FOUND: return EV_ENOENT;
		case WSANO_DATA: return EV_ENOENT;

		default: return EV_EUNKNOWN;
	}
}
static char *evi_win_fix_path(char *path) {
	for (char *it = strchr(path, '/'); it; it = strchr(path, '/')) {
		*it = '\\';
	}

	return path;
}

static int evi_win_conv_addr(ev_addr_t addr, uint16_t port, struct sockaddr_storage *pres) {
	if (addr.type == EV_ADDR_IPV4) {
		struct sockaddr_in res;
		res.sin_family = AF_INET;
		res.sin_port = htons(port);
		// TODO: check if order is correct
		memcpy(&res.sin_addr, addr.v4, sizeof res.sin_addr);
		memcpy(pres, &res, sizeof res);
		return sizeof res;
	}
	else {
		SOCKADDR_IN6 res;
		res.sin6_family = AF_INET6;
		res.sin6_port = htons(port);
		for (size_t i = 0; i < 8; i++) {
			uint16_t netord = htons(addr.v6[i]);
			memcpy((void*)&res.sin6_addr + i * 2, &netord, 2);
		}
		memcpy(pres, &res, sizeof res);
		return sizeof res;
	}
}
static void evi_win_conv_sockaddr(struct sockaddr_storage *sockaddr, ev_addr_t *pres, uint16_t *pport) {
	if (sockaddr->ss_family == AF_INET) {
		struct sockaddr_in *sockaddr_in = (void*)sockaddr;

		*pport = ntohs(sockaddr_in->sin_port);
		pres->type = EV_ADDR_IPV4;
		memcpy(pres->v4, &sockaddr_in->sin_addr, sizeof sockaddr_in->sin_addr);
	}
	else {
		struct sockaddr_in6 *sockaddr_in6 = (void*)sockaddr;

		*pport = ntohs(sockaddr_in6->sin6_port);
		pres->type = EV_ADDR_IPV6;
		memcpy(pres->v6, &sockaddr_in6->sin6_addr, sizeof sockaddr_in6->sin6_addr);

		// for (size_t i = 0; i < 8; i++) {
		// 	pres->v6[i] = ntohs(pres->v6[i]);
		// }
	}
}

static int evi_win_init() {
	WSADATA data;
	int code = WSAStartup(MAKEWORD(2, 2), &data);
	if (code != 0) return -1;
	return 0;
}
static int evi_win_free() {
	if (WSACleanup() != 0) return -1;
	return 0;
}
