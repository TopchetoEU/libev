#pragma once

#include "ev.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
	else {
		res |= O_PATH;
	}

	if (flags & EV_OPEN_CREATE) res |= O_CREAT;
	if (flags & EV_OPEN_TRUNC) res |= O_TRUNC;
	if (flags & EV_OPEN_DIRECT) res |= O_SYNC;

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
	dst->atime = (struct timespec) { .tv_sec = src->st_atim.tv_sec, .tv_nsec = src->st_atim.tv_nsec };
	dst->ctime = (struct timespec) { .tv_sec = src->st_ctim.tv_sec, .tv_nsec = src->st_ctim.tv_nsec };
	dst->mtime = (struct timespec) { .tv_sec = src->st_mtim.tv_sec, .tv_nsec = src->st_mtim.tv_nsec };
	dst->size = src->st_size;
	dst->inode = src->st_ino;
	dst->links = src->st_nlink;
	dst->blksize = src->st_blksize;
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
