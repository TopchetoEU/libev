#pragma once

#include <errno.h>
#include <ev/conf.h>
#include <ev.h>
#include <ev/errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined EV_USE_PTRTAG
	// NOTE: without O_PATH, a race condition could be triggered, where you open a file
	// with only creation flags and then try to stat it, but it gets deleted in the meantime
	// Unfortunately, there isn't a roundabout way around this

	static ev_handle_t evi_generic_mkfd(FILE *fd) {
		return (ev_handle_t)(((size_t)fd) | 1);
	}
	static ev_handle_t evi_generic_mkat(const char *path) {
		size_t len = strlen(path);
		char *at = malloc(len + 1);
		memcpy(at, path, len + 1);
		return (ev_handle_t)at;
	}
	static void evi_generic_freefd(ev_handle_t fd) {
		if (((size_t)fd & 1) == 0) free(fd);
	}

	static int evi_generic_isfd(ev_handle_t fd) {
		return (size_t)fd & 1;
	}
	static FILE *evi_generic_fd(ev_handle_t fd) {
		return (FILE*)((size_t)fd & ~1);
	}
	static char *evi_generic_at(ev_handle_t fd) {
		return (char*)((size_t)fd & ~1);
	}
#else
	struct ev_hnd {
		enum {
			EVI_UNIX_FD,
			EVI_UNIX_AT,
		} kind;
		union {
			int fd;
			char at[];
		};
	};

	static ev_handle_t evi_generic_mkfd(int fd) {
		ev_handle_t res = malloc(sizeof *res);
		if (!res) return NULL;
		res->kind = EVI_UNIX_FD;
		res->fd = fd;
		return res;
	}
	static ev_handle_t evi_generic_mkat(const char *path) {
		size_t len = strlen(path);
		ev_handle_t res = malloc(sizeof *res + len + 1);
		if (!res) return NULL;

		res->kind = EVI_UNIX_AT;
		memcpy(res->at, path, len + 1);
		return res;
	}
	static void evi_generic_freefd(ev_handle_t fd) {
		free(fd);
	}

	static int evi_generic_isfd(ev_handle_t fd) {
		return fd->kind == EVI_UNIX_FD;
	}
	static int evi_generic_fd(ev_handle_t fd) {
		return fd->fd;
	}
	static char *evi_generic_at(ev_handle_t fd) {
		return fd->at;
	}
#endif

static ev_code_t evi_generic_conv_errno(int errno, ev_code_t fallback) {
	switch (errno) {
		#ifdef EPERM
			case EPERM: return EV_EPERM;
		#endif
		#ifdef ENOENT
			case ENOENT: return EV_ENOENT;
		#endif
		#ifdef ESRCH
			case ESRCH: return EV_ESRCH;
		#endif
		#ifdef EINTR
			case EINTR: return EV_EINTR;
		#endif
		#ifdef EIO
			case EIO: return EV_EIO;
		#endif
		#ifdef ENXIO
			case ENXIO: return EV_ENXIO;
		#endif
		#ifdef E2BIG
			case E2BIG: return EV_E2BIG;
		#endif
		#ifdef ENOEXEC
			case ENOEXEC: return EV_ENOEXEC;
		#endif
		#ifdef EBADF
			case EBADF: return EV_EBADF;
		#endif
		#ifdef ECHILD
			case ECHILD: return EV_ECHILD;
		#endif
		#ifdef EAGAIN
			case EAGAIN: return EV_EAGAIN;
		#endif
		#ifdef ENOMEM
			case ENOMEM: return EV_ENOMEM;
		#endif
		#ifdef EACCES
			case EACCES: return EV_EACCES;
		#endif
		#ifdef EFAULT
			case EFAULT: return EV_EFAULT;
		#endif
		#ifdef ENOTBLK
			case ENOTBLK: return EV_ENOTBLK;
		#endif
		#ifdef EBUSY
			case EBUSY: return EV_EBUSY;
		#endif
		#ifdef EEXIST
			case EEXIST: return EV_EEXIST;
		#endif
		#ifdef EXDEV
			case EXDEV: return EV_EXDEV;
		#endif
		#ifdef ENODEV
			case ENODEV: return EV_ENODEV;
		#endif
		#ifdef ENOTDIR
			case ENOTDIR: return EV_ENOTDIR;
		#endif
		#ifdef EISDIR
			case EISDIR: return EV_EISDIR;
		#endif
		#ifdef EINVAL
			case EINVAL: return EV_EINVAL;
		#endif
		#ifdef ENFILE
			case ENFILE: return EV_ENFILE;
		#endif
		#ifdef EMFILE
			case EMFILE: return EV_EMFILE;
		#endif
		#ifdef ENOTTY
			case ENOTTY: return EV_ENOTTY;
		#endif
		#ifdef ETXTBSY
			case ETXTBSY: return EV_ETXTBSY;
		#endif
		#ifdef EFBIG
			case EFBIG: return EV_EFBIG;
		#endif
		#ifdef ENOSPC
			case ENOSPC: return EV_ENOSPC;
		#endif
		#ifdef ESPIPE
			case ESPIPE: return EV_ESPIPE;
		#endif
		#ifdef EROFS
			case EROFS: return EV_EROFS;
		#endif
		#ifdef EMLINK
			case EMLINK: return EV_EMLINK;
		#endif
		#ifdef EPIPE
			case EPIPE: return EV_EPIPE;
		#endif
		#ifdef EDOM
			case EDOM: return EV_EDOM;
		#endif
		#ifdef ERANGE
			case ERANGE: return EV_ERANGE;
		#endif
		default: return fallback;
	}
}
