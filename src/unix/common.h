#include <stddef.h>
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma once

#include "ev/conf.h"
#include "ev.h"
#include "ev/errno.h"
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

static ev_socket_t evi_unix_mksock(int fd) {
	return (void*)(size_t)fd;
}
static int evi_unix_sock(ev_socket_t fd) {
	return (int)(size_t)fd;
}

#ifdef EV_USE_LINUX
	static ev_fd_t evi_unix_mkfd(int fd) {
		return (void*)(size_t)fd;
	}
	static void evi_unix_freefd(ev_fd_t fd) {
		(void)fd;
	}

	static int evi_unix_isfd(ev_fd_t fd) {
		(void)fd;
		return true;
	}
	static int evi_unix_fd(ev_fd_t fd) {
		return (int)(size_t)fd;
	}
	static char *evi_unix_at(ev_fd_t fd) {
		(void)fd;
		return NULL;
	}
#elif defined EV_USE_PTRTAG
	// NOTE: without O_PATH, a race condition could be triggered, where you open a file
	// with only creation flags and then try to stat it, but it gets deleted in the meantime
	// Unfortunately, there isn't a roundabout way around this

	static ev_fd_t evi_unix_mkfd(int fd) {
		return (ev_fd_t)(size_t)(fd << 1 | 1);
	}
	static ev_fd_t evi_unix_mkat(const char *path) {
		size_t len = strlen(path);
		char *at = malloc(len + 1);
		memcpy(at, path, len + 1);
		return (ev_fd_t)at;
	}
	static void evi_unix_freefd(ev_fd_t fd) {
		if (((size_t)fd & 1) == 0) free(fd);
	}

	static int evi_unix_isfd(ev_fd_t fd) {
		return (size_t)fd & 1;
	}
	static int evi_unix_fd(ev_fd_t fd) {
		return (int)((size_t)fd >> 1);
	}
	static char *evi_unix_at(ev_fd_t fd) {
		return (char*)fd;
	}
#else
	struct ev_fd {
		enum {
			EVI_UNIX_FD,
			EVI_UNIX_AT,
		} kind;
		union {
			int fd;
			char at[];
		};
	};

	static ev_fd_t evi_unix_mkfd(int fd) {
		ev_fd_t res = malloc(sizeof *res);
		if (!res) return NULL;
		res->kind = EVI_UNIX_FD;
		res->fd = fd;
		return res;
	}
	static ev_fd_t evi_unix_mkat(const char *path) {
		size_t len = strlen(path);
		ev_fd_t res = malloc(sizeof *res + len + 1);
		if (!res) return NULL;

		res->kind = EVI_UNIX_AT;
		memcpy(res->at, path, len + 1);
		return res;
	}
	static void evi_unix_freefd(ev_fd_t fd) {
		free(fd);
	}

	static int evi_unix_isfd(ev_fd_t fd) {
		return fd->kind == EVI_UNIX_FD;
	}
	static int evi_unix_fd(ev_fd_t fd) {
		return fd->fd;
	}
	static char *evi_unix_at(ev_fd_t fd) {
		return fd->at;
	}
#endif

static int evi_unix_conv_open_flags(ev_open_flags_t flags) {
	int res = 0;

	if (flags & EV_OPEN_APPEND) {
		flags |= EV_OPEN_WRITE;
		res |= O_APPEND;
	}

	if (flags & EV_OPEN_WRITE) {
		if (flags & EV_OPEN_READ) {
			res |= O_RDWR;
		}
		else {
			res |= O_WRONLY;
		}
	}
	else if (flags & EV_OPEN_READ) {
		res |= O_RDONLY;
	}
#ifdef EV_USE_LINUX
	else {
		res |= O_PATH;
	}
#endif

	if (flags & EV_OPEN_CREATE) res |= O_CREAT;
	if (flags & EV_OPEN_TRUNC) res |= O_TRUNC;
	if (flags & EV_OPEN_DIRECT) res |= O_SYNC;
	if (!(flags & EV_OPEN_SHARED)) res |= O_CLOEXEC;

	return res;
}
static void evi_unix_conf_stat_mode(int mode, ev_stat_type_t *ptype, uint32_t *pmode) {
	switch (mode & S_IFMT) {
		case S_IFREG: *ptype = EV_STAT_REG; break;
		case S_IFDIR: *ptype = EV_STAT_DIR; break;
		case S_IFLNK: *ptype = EV_STAT_LINK; break;
		case S_IFSOCK: *ptype = EV_STAT_SOCK; break;
		case S_IFIFO: *ptype = EV_STAT_FIFO; break;
		case S_IFCHR: *ptype = EV_STAT_CHAR; break;
		case S_IFBLK: *ptype = EV_STAT_BLK; break;
		default: *ptype = -1; break;
	}

	*pmode = mode & ~S_IFMT;
}
static void evi_unix_conv_stat(ev_stat_t *dst, struct stat *src) {
	evi_unix_conf_stat_mode(src->st_mode, &dst->type, &dst->mode);

	dst->mode = src->st_mode & ~S_IFMT;
	dst->uid = src->st_uid;
	dst->gid = src->st_gid;
	dst->atime = (ev_time_t) { .sec = src->st_atim.tv_sec, .nsec = src->st_atim.tv_nsec };
	dst->ctime = (ev_time_t) { .sec = src->st_ctim.tv_sec, .nsec = src->st_ctim.tv_nsec };
	dst->mtime = (ev_time_t) { .sec = src->st_mtim.tv_sec, .nsec = src->st_mtim.tv_nsec };
	dst->size = src->st_size;
	dst->inode = src->st_ino;
	dst->links = src->st_nlink;
	dst->blksize = src->st_blksize;
}

static ev_code_t evi_unix_conv_errno(int unixerr) {
	switch (unixerr) {
		case EPERM: return EV_EPERM;
		case ENOENT: return EV_ENOENT;
		case ESRCH: return EV_ESRCH;
		case EINTR: return EV_EINTR;
		case EIO: return EV_EIO;
		case ENXIO: return EV_ENXIO;
		case E2BIG: return EV_E2BIG;
		case ENOEXEC: return EV_ENOEXEC;
		case EBADF: return EV_EBADF;
		case ECHILD: return EV_ECHILD;
		case EAGAIN: return EV_EAGAIN;
		case ENOMEM: return EV_ENOMEM;
		case EACCES: return EV_EACCES;
		case EFAULT: return EV_EFAULT;
		case EBUSY: return EV_EBUSY;
		case EEXIST: return EV_EEXIST;
		case EXDEV: return EV_EXDEV;
		case ENODEV: return EV_ENODEV;
		case ENOTDIR: return EV_ENOTDIR;
		case EISDIR: return EV_EISDIR;
		case EINVAL: return EV_EINVAL;
		case ENFILE: return EV_ENFILE;
		case EMFILE: return EV_EMFILE;
		case ENOTTY: return EV_ENOTTY;
		case ETXTBSY: return EV_ETXTBSY;
		case EFBIG: return EV_EFBIG;
		case ENOSPC: return EV_ENOSPC;
		case ESPIPE: return EV_ESPIPE;
		case EROFS: return EV_EROFS;
		case EMLINK: return EV_EMLINK;
		case EPIPE: return EV_EPIPE;
		case ERANGE: return EV_ERANGE;
		case EDEADLK: return EV_EDEADLK;
		case ENAMETOOLONG: return EV_ENAMETOOLONG;
		case ENOLCK: return EV_ENOLCK;
		case ENOSYS: return EV_ENOSYS;
		case ENOTEMPTY: return EV_ENOTEMPTY;
		case ELOOP: return EV_ELOOP;
		case EUNATCH: return EV_EUNATCH;
		case ENODATA: return EV_ENODATA;
		case ENONET: return EV_ENONET;
		case ECOMM: return EV_ECOMM;
		case EPROTO: return EV_EPROTO;
		case EOVERFLOW: return EV_EOVERFLOW;
		case ENOTUNIQ: return EV_ENOTUNIQ;
		case ELIBBAD: return EV_ELIBBAD;
		case EILSEQ: return EV_EILSEQ;
		case ENOTSOCK: return EV_ENOTSOCK;
		case EDESTADDRREQ: return EV_EDESTADDRREQ;
		case EMSGSIZE: return EV_EMSGSIZE;
		case EPROTOTYPE: return EV_EPROTOTYPE;
		case ENOPROTOOPT: return EV_ENOPROTOOPT;
		case EPROTONOSUPPORT: return EV_EPROTONOSUPPORT;
		case ESOCKTNOSUPPORT: return EV_ESOCKTNOSUPPORT;
		case ENOTSUP: return EV_ENOTSUP;
		case EPFNOSUPPORT: return EV_EPFNOSUPPORT;
		case EAFNOSUPPORT: return EV_EAFNOSUPPORT;
		case EADDRINUSE: return EV_EADDRINUSE;
		case EADDRNOTAVAIL: return EV_EADDRNOTAVAIL;
		case ENETDOWN: return EV_ENETDOWN;
		case ENETUNREACH: return EV_ENETUNREACH;
		case ECONNABORTED: return EV_ECONNABORTED;
		case ECONNRESET: return EV_ECONNRESET;
		case ENOBUFS: return EV_ENOBUFS;
		case EISCONN: return EV_EISCONN;
		case ENOTCONN: return EV_ENOTCONN;
		case ESHUTDOWN: return EV_ESHUTDOWN;
		case ETIMEDOUT: return EV_ETIMEDOUT;
		case ECONNREFUSED: return EV_ECONNREFUSED;
		case EHOSTDOWN: return EV_EHOSTDOWN;
		case EHOSTUNREACH: return EV_EHOSTUNREACH;
		case EALREADY: return EV_EALREADY;
		case EREMOTEIO: return EV_EREMOTEIO;
		case ENOMEDIUM: return EV_ENOMEDIUM;
		case ECANCELED: return EV_ECANCELED;
		case -1: return EV_EUNKNOWN;
		default: return EV_EUNKNOWN;
	}
}
static ev_code_t evi_unix_conv_aierr(int aierr) {
	switch (aierr) {
		case EAI_BADFLAGS: return EV_EAI_BADFLAGS;
		case EAI_NONAME: return EV_EAI_NONAME;
		case EAI_AGAIN: return EV_EAI_AGAIN;
		case EAI_FAIL: return EV_EAI_FAIL;
		case EAI_FAMILY: return EV_EAI_FAMILY;
		case EAI_SOCKTYPE: return EV_EAI_SOCKTYPE;
		case EAI_SERVICE: return EV_EAI_SERVICE;
		case EAI_MEMORY: return EV_EAI_MEMORY;
		case EAI_OVERFLOW: return EV_EAI_OVERFLOW;
		#ifdef EV_USE_LINUX
			case EAI_NODATA: return EV_EAI_NODATA;
			case EAI_ADDRFAMILY: return EV_EAI_ADDRFAMILY;
			case EAI_CANCELED: return EV_EAI_CANCELED;
		#endif

		default: return EV_EUNKNOWN;
	}
}

static int evi_unix_conv_addr(ev_addr_t addr, uint16_t port, struct sockaddr_storage *pres) {
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
		struct sockaddr_in6 res;
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
static void evi_unix_conv_sockaddr(struct sockaddr_storage *sockaddr, ev_addr_t *pres, uint16_t *pport) {
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

		for (size_t i = 0; i < 8; i++) {
			pres->v6[i] = ntohs(pres->v6[i]);
		}
	}
}
