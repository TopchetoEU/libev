#ifndef EV_ERRNO_H
#define EV_ERRNO_H

// These have more or less been ripped from libuv

#define EV_SIGDEF(X) \
	X(OK, 0, "no error occurred") \
	X(EPERM, -1, "operation not permitted") \
	X(ENOENT, -2, "no such file or directory") \
	X(ESRCH, -3, "no such process") \
	X(EINTR, -4, "interrupted system call") \
	X(EIO, -5, "i/o error") \
	X(ENXIO, -6, "no such device or address") \
	X(E2BIG, -7, "argument list too long") \
	X(ENOEXEC, -8, "exec format error") \
	X(EBADF, -9, "bad file descriptor") \
	X(ECHILD, -10, "no child processes") \
	X(EAGAIN, -11, "resource temporarily unavailable") \
	X(ENOMEM, -12, "not enough memory") \
	X(EACCES, -13, "permission denied") \
	X(EFAULT, -14, "bad address in system call argument") \
	X(ENOTBLK, -15, "Block device required") \
	X(EBUSY, -16, "resource busy or locked") \
	X(EEXIST, -17, "file already exists") \
	X(EXDEV, -18, "cross-device link not permitted") \
	X(ENODEV, -19, "no such device") \
	X(ENOTDIR, -20, "not a directory") \
	X(EISDIR, -21, "illegal operation on a directory") \
	X(EINVAL, -22, "invalid argument") \
	X(ENFILE, -23, "file table overflow") \
	X(EMFILE, -24, "too many open files") \
	X(ENOTTY, -25, "inappropriate ioctl for device") \
	X(ETXTBSY, -26, "text file is busy") \
	X(EFBIG, -27, "file too large") \
	X(ENOSPC, -28, "no space left on device") \
	X(ESPIPE, -29, "invalid seek") \
	X(EROFS, -30, "read-only file system") \
	X(EMLINK, -31, "too many links") \
	X(EPIPE, -32, "broken pipe") \
	X(EDOM, -33, "numerical argument out of domain") \
	X(ERANGE, -34, "result too large") \
	X(EDEADLK, -35, "resource deadlock avoided") \
	X(ENAMETOOLONG, -36, "name too long") \
	X(ENOLCK, -37, "no locks available") \
	X(ENOSYS, -38, "function not implemented") \
	X(ENOTEMPTY, -39, "directory not empty") \
	X(ELOOP, -40, "too many symbolic links encountered") \
	X(EUNATCH, -49, "protocol driver not attached") \
	X(ENODATA, -61, "no data available") \
	X(ENONET, -64, "machine is not on the network") \
	X(ECOMM, -70, "communication error on send") \
	X(EPROTO, -71, "protocol error") \
	X(EOVERFLOW, -75, "value too large for defined data type") \
	X(ENOTUNIQ, -76, "Name not unique on network") \
	X(ELIBBAD, -80, "accessing a corrupted shared library") \
	X(EILSEQ, -84, "illegal byte sequence") \
	X(ENOTSOCK, -88, "socket operation on non-socket") \
	X(EDESTADDRREQ, -89, "destination address required") \
	X(EMSGSIZE, -90, "message too long") \
	X(EPROTOTYPE, -91, "protocol wrong type for socket") \
	X(ENOPROTOOPT, -92, "protocol not available") \
	X(EPROTONOSUPPORT, -93, "protocol not supported") \
	X(ESOCKTNOSUPPORT, -94, "socket type not supported") \
	X(ENOTSUP, -95, "operation not supported") \
	X(EPFNOSUPPORT, -96, "operation not supported on socket") \
	X(EAFNOSUPPORT, -97, "address family not supported") \
	X(EADDRINUSE, -98, "address already in use") \
	X(EADDRNOTAVAIL, -99, "address not available") \
	X(ENETDOWN, -100, "network is down") \
	X(ENETUNREACH, -101, "network is unreachable") \
	X(ECONNABORTED, -103, "software caused connection abort") \
	X(ECONNRESET, -104, "connection reset by peer") \
	X(ENOBUFS, -105, "no buffer space available") \
	X(EISCONN, -106, "socket is already connected") \
	X(ENOTCONN, -107, "socket is not connected") \
	X(ESHUTDOWN, -108, "cannot send after transport endpoint shutdown") \
	X(ETIMEDOUT, -110, "connection timed out") \
	X(ECONNREFUSED, -111, "connection refused") \
	X(EHOSTDOWN, -112, "host is down") \
	X(EHOSTUNREACH, -113, "host is unreachable") \
	X(EALREADY, -114, "connection already in progress") \
	X(EREMOTEIO, -121, "remote I/O error") \
	X(ENOMEDIUM, -123, "no medium found") \
	X(ECANCELED, -125, "operation canceled") \
	X(EAI_BADFLAGS, -1001, "bad ai_flags value") \
	X(EAI_NONAME, -1002, "unknown node or service") \
	X(EAI_AGAIN, -1003, "temporary failure") \
	X(EAI_FAIL, -1004, "permanent failure") \
	X(EAI_NODATA, -1005, "no address") \
	X(EAI_FAMILY, -1006, "ai_family not supported") \
	X(EAI_SOCKTYPE, -1007, "socket type not supported") \
	X(EAI_SERVICE, -1008, "service not available for socket type") \
	X(EAI_ADDRFAMILY, -1009, "address family not supported") \
	X(EAI_MEMORY, -1010, "out of memory") \
	X(EAI_OVERFLOW, -1012, "argument buffer overflow") \
	X(EAI_CANCELED, -1101, "request canceled") \
	X(ECHARSET, -2001, "invalid Unicode character") \
	X(EUNKNOWN, -3000, "unknown OS-specific error") \

typedef enum {
	#define EV_SIGDEF_ENUM_X(name, code, msg) EV_##name = code,
	EV_SIGDEF(EV_SIGDEF_ENUM_X)
	#undef EV_SIGDEF_ENUM_X
} ev_code_t;

#endif
