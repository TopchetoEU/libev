#pragma once
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ev.h"
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include <winsock2.h>
#include <ws2ipdef.h>

// TODO: create unified error codes (preferably identical to libuv)
#define ECOMM 70
#define ENOTUNIQ 76
#define ELIBBAD 80
#define	EUSERS 87
#define	ESOCKTNOSUPPORT	94
#define	EPFNOSUPPORT 96
#define ESHUTDOWN 108
#define ETOOMANYREFS 109
#define	EHOSTDOWN 112
#define	ESTALE 116
#define	EREMOTE 121
#define	EDQUOT 122
#define ENOMEDIUM 123

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
static int evi_win_conv_errno(int winerr) {
	switch (winerr) {
		case ERROR_ACCESS_DENIED: return EACCES;
		case ERROR_ACTIVE_CONNECTIONS: return EAGAIN;
		case ERROR_ALREADY_EXISTS: return EEXIST;
		case ERROR_BAD_DEVICE: return ENODEV;
		case ERROR_BAD_EXE_FORMAT: return ENOEXEC;
		case ERROR_BAD_NETPATH: return ENOENT;
		case ERROR_BAD_NET_NAME: return ENOENT;
		case ERROR_BAD_NET_RESP: return ENOSYS;
		case ERROR_BAD_PATHNAME: return ENOENT;
		case ERROR_BAD_PIPE: return EINVAL;
		case ERROR_BAD_UNIT: return ENODEV;
		case ERROR_BAD_USERNAME: return EINVAL;
		case ERROR_BEGINNING_OF_MEDIA: return EIO;
		case ERROR_BROKEN_PIPE: return EPIPE;
		case ERROR_BUSY: return EBUSY;
		case ERROR_BUS_RESET: return EIO;
		case ERROR_CALL_NOT_IMPLEMENTED: return ENOSYS;
		case ERROR_CANCELLED: return EINTR;
		case ERROR_CANNOT_MAKE: return EPERM;
		case ERROR_CHILD_NOT_COMPLETE: return EBUSY;
		case ERROR_COMMITMENT_LIMIT: return EAGAIN;
		case ERROR_CONNECTION_REFUSED: return ECONNREFUSED;
		case ERROR_CRC: return EIO;
		case ERROR_DEVICE_DOOR_OPEN: return EIO;
		case ERROR_DEVICE_IN_USE: return EAGAIN;
		case ERROR_DEVICE_REQUIRES_CLEANING: return EIO;
		case ERROR_DEV_NOT_EXIST: return ENOENT;
		case ERROR_DIRECTORY: return ENOTDIR;
		case ERROR_DIR_NOT_EMPTY: return ENOTEMPTY;
		case ERROR_DISK_CORRUPT: return EIO;
		case ERROR_DISK_FULL: return ENOSPC;
		case ERROR_DS_GENERIC_ERROR: return EIO;
		case ERROR_DUP_NAME: return ENOTUNIQ;
		case ERROR_EAS_DIDNT_FIT: return ENOSPC;
		case ERROR_EAS_NOT_SUPPORTED: return ENOTSUP;
		case ERROR_EA_LIST_INCONSISTENT: return EINVAL;
		case ERROR_EA_TABLE_FULL: return ENOSPC;
		case ERROR_END_OF_MEDIA: return ENOSPC;
		case ERROR_EOM_OVERFLOW: return EIO;
		case ERROR_EXE_MACHINE_TYPE_MISMATCH: return ENOEXEC;
		case ERROR_EXE_MARKED_INVALID: return ENOEXEC;
		case ERROR_FILEMARK_DETECTED: return EIO;
		case ERROR_FILENAME_EXCED_RANGE: return ENAMETOOLONG;
		case ERROR_FILE_CORRUPT: return EEXIST;
		case ERROR_FILE_EXISTS: return EEXIST;
		case ERROR_FILE_INVALID: return ENXIO;
		case ERROR_FILE_NOT_FOUND: return ENOENT;
		case ERROR_HANDLE_DISK_FULL: return ENOSPC;
		case ERROR_HANDLE_EOF: return ENODATA;
		case ERROR_INVALID_ADDRESS: return EINVAL;
		case ERROR_INVALID_AT_INTERRUPT_TIME: return EINTR;
		case ERROR_INVALID_BLOCK_LENGTH: return EIO;
		case ERROR_INVALID_DATA: return EINVAL;
		case ERROR_INVALID_DRIVE: return ENODEV;
		case ERROR_INVALID_EA_NAME: return EINVAL;
		case ERROR_INVALID_EXE_SIGNATURE: return ENOEXEC;
		case ERROR_INVALID_FUNCTION: return EINVAL;
		case ERROR_INVALID_HANDLE: return EBADF;
		case ERROR_INVALID_NAME: return ENOENT;
		case ERROR_INVALID_PARAMETER: return EINVAL;
		case ERROR_INVALID_SIGNAL_NUMBER: return EINVAL;
		case ERROR_IOPL_NOT_ENABLED: return ENOEXEC;
		case ERROR_IO_DEVICE: return EIO;
		case ERROR_IO_INCOMPLETE: return EAGAIN;
		case ERROR_IO_PENDING: return EAGAIN;
		case ERROR_LOCK_VIOLATION: return EBUSY;
		case ERROR_MAX_THRDS_REACHED: return EAGAIN;
		case ERROR_META_EXPANSION_TOO_LONG: return EINVAL;
		case ERROR_MOD_NOT_FOUND: return ENOENT;
		case ERROR_MORE_DATA: return EMSGSIZE;
		case ERROR_NEGATIVE_SEEK: return EINVAL;
		case ERROR_NETNAME_DELETED: return ENOENT;
		case ERROR_NOACCESS: return EFAULT;
		case ERROR_NONE_MAPPED: return EINVAL;
		case ERROR_NONPAGED_SYSTEM_RESOURCES: return EAGAIN;
		case ERROR_NOT_CONNECTED: return ENOLINK;
		case ERROR_NOT_ENOUGH_MEMORY: return ENOMEM;
		case ERROR_NOT_ENOUGH_QUOTA: return EIO;
		case ERROR_NOT_OWNER: return EPERM;
		case ERROR_NOT_READY: return ENOMEDIUM;
		case ERROR_NOT_SAME_DEVICE: return EXDEV;
		case ERROR_NOT_SUPPORTED: return ENOSYS;
		case ERROR_NO_DATA: return EPIPE;
		case ERROR_NO_DATA_DETECTED: return EIO;
		case ERROR_NO_MEDIA_IN_DRIVE: return ENOMEDIUM;
		case ERROR_NO_MORE_FILES: return ENOENT;
		case ERROR_NO_MORE_ITEMS: return ENOENT;
		case ERROR_NO_MORE_SEARCH_HANDLES: return ENFILE;
		case ERROR_NO_PROC_SLOTS: return EAGAIN;
		case ERROR_NO_SIGNAL_SENT: return EIO;
		case ERROR_NO_SYSTEM_RESOURCES: return EFBIG;
		case ERROR_NO_TOKEN: return EINVAL;
		case ERROR_OPEN_FAILED: return EIO;
		case ERROR_OPEN_FILES: return EAGAIN;
		case ERROR_OUTOFMEMORY: return ENOMEM;
		case ERROR_PAGED_SYSTEM_RESOURCES: return EAGAIN;
		case ERROR_PAGEFILE_QUOTA: return EAGAIN;
		case ERROR_PATH_NOT_FOUND: return ENOENT;
		case ERROR_PIPE_BUSY: return EBUSY;
		case ERROR_PIPE_CONNECTED: return EBUSY;
		case ERROR_PIPE_LISTENING: return ECOMM;
		case ERROR_PIPE_NOT_CONNECTED: return ECOMM;
		case ERROR_POSSIBLE_DEADLOCK: return EDEADLOCK;
		case ERROR_PRIVILEGE_NOT_HELD: return EPERM;
		case ERROR_PROCESS_ABORTED: return EFAULT;
		case ERROR_PROC_NOT_FOUND: return ESRCH;
		case ERROR_REM_NOT_LIST: return ENOENT;
		case ERROR_SECTOR_NOT_FOUND: return EINVAL;
		case ERROR_SEEK: return EINVAL;
		case ERROR_SERVICE_REQUEST_TIMEOUT: return EBUSY;
		case ERROR_SETMARK_DETECTED: return EIO;
		case ERROR_SHARING_BUFFER_EXCEEDED: return ENOLCK;
		case ERROR_SHARING_VIOLATION: return EBUSY;
		case ERROR_SIGNAL_PENDING: return EBUSY;
		case ERROR_SIGNAL_REFUSED: return EIO;
		case ERROR_SXS_CANT_GEN_ACTCTX: return ELIBBAD;
		case ERROR_THREAD_1_INACTIVE: return EINVAL;
		case ERROR_TIMEOUT: return EBUSY;
		case ERROR_TOO_MANY_LINKS: return EMLINK;
		case ERROR_TOO_MANY_OPEN_FILES: return EMFILE;
		case ERROR_UNEXP_NET_ERR: return EIO;
		case ERROR_WAIT_NO_CHILDREN: return ECHILD;
		case ERROR_WORKING_SET_QUOTA: return EAGAIN;
		case ERROR_WRITE_PROTECT: return EROFS;
		default: return EIO;
	}
}
static int evi_win_conv_sockerr(int sockerr) {
	switch (sockerr) {
		case WSAEINTR: return EINTR;
		case WSAEBADF: return EBADF;
		case WSAEACCES: return EACCES;
		case WSAEFAULT: return EFAULT;
		case WSAEINVAL: return EINVAL;
		case WSAEMFILE: return EMFILE;
		case WSAEWOULDBLOCK: return EWOULDBLOCK;
		case WSAEINPROGRESS: return EINPROGRESS;
		case WSAEALREADY: return EALREADY;
		case WSAENOTSOCK: return ENOTSOCK;
		case WSAEDESTADDRREQ: return EDESTADDRREQ;
		case WSAEMSGSIZE: return EMSGSIZE;
		case WSAEPROTOTYPE: return EPROTOTYPE;
		case WSAENOPROTOOPT: return ENOPROTOOPT;
		case WSAEPROTONOSUPPORT: return EPROTONOSUPPORT;
		case WSAESOCKTNOSUPPORT: return ESOCKTNOSUPPORT;
		case WSAEOPNOTSUPP: return EOPNOTSUPP;
		case WSAEPFNOSUPPORT: return EPFNOSUPPORT;
		case WSAEAFNOSUPPORT: return EAFNOSUPPORT;
		case WSAEADDRINUSE: return EADDRINUSE;
		case WSAEADDRNOTAVAIL: return EADDRNOTAVAIL;
		case WSAENETDOWN: return ENETDOWN;
		case WSAENETUNREACH: return ENETUNREACH;
		case WSAENETRESET: return ENETRESET;
		case WSAECONNABORTED: return ECONNABORTED;
		case WSAECONNRESET: return ECONNRESET;
		case WSAENOBUFS: return ENOBUFS;
		case WSAEISCONN: return EISCONN;
		case WSAENOTCONN: return ENOTCONN;
		case WSAESHUTDOWN: return ESHUTDOWN;
		case WSAETOOMANYREFS: return ETOOMANYREFS;
		case WSAETIMEDOUT: return ETIMEDOUT;
		case WSAECONNREFUSED: return ECONNREFUSED;
		case WSAELOOP: return ELOOP;
		case WSAENAMETOOLONG: return ENAMETOOLONG;
		case WSAEHOSTDOWN: return EHOSTDOWN;
		case WSAEHOSTUNREACH: return EHOSTUNREACH;
		case WSAENOTEMPTY: return ENOTEMPTY;
		// case WSAEPROCLIM: return EPROCLIM;
		case WSAEUSERS: return EUSERS;
		case WSAEDQUOT: return EDQUOT;
		case WSAESTALE: return ESTALE;
		case WSAEREMOTE: return EREMOTE;
		// case WSASYSNOTREADY: return SYSNOTREADY;
		// case WSAVERNOTSUPPORTED: return VERNOTSUPPORTED;
		// case WSANOTINITIALISED: return NOTINITIALISED;
		// case WSAEDISCON: return EDISCON;
		// case WSAENOMORE: return ENOMORE;
		// case WSAECANCELLED: return ECANCELLED;
		// case WSAEINVALIDPROCTABLE: return EINVALIDPROCTABLE;
		// case WSAEINVALIDPROVIDER: return EINVALIDPROVIDER;
		// case WSAEPROVIDERFAILEDINIT: return EPROVIDERFAILEDINIT;
		// case WSASYSCALLFAILURE: return SYSCALLFAILURE;
		// case WSASERVICE_NOT_FOUND: return SERVICE_NOT_FOUND;
		// case WSATYPE_NOT_FOUND: return TYPE_NOT_FOUND;
		// case WSA_E_NO_MORE: return _E_NO_MORE;
		// case WSA_E_CANCELLED: return _E_CANCELLED;
		// case WSAEREFUSED: return EREFUSED;
		// case WSAENETDOWN: return ENETDOWN;
		// case WSAEFAULT: return EFAULT;
		// case WSAENOTCONN: return ENOTCONN;
		// case WSAEINTR: return EINTR;
		// case WSAEINPROGRESS: return EINPROGRESS;
		// case WSAENETRESET: return ENETRESET;
		// case WSAENOTSOCK: return ENOTSOCK;
		// case WSAEOPNOTSUPP: return EOPNOTSUPP;
		// case WSAESHUTDOWN: return ESHUTDOWN;
		// case WSAEWOULDBLOCK: return EWOULDBLOCK;
		// case WSAEMSGSIZE: return EMSGSIZE;
		// case WSAEINVAL: return EINVAL;
		// case WSAECONNABORTED: return ECONNABORTED;
		// case WSAETIMEDOUT: return ETIMEDOUT;
		// case WSAECONNRESET: return ECONNRESET;
		default: return EIO;
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
