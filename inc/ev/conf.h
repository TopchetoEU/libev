#ifndef EV_CONF_H
#define EV_CONF_H

#pragma once

// 1. Detect target

#if defined __linux
	#ifndef EV_USE_POSIX
		#define EV_USE_POSIX
	#endif
	#ifndef EV_USE_LINUX
		#define EV_USE_LINUX
	#endif
#elif defined __unix__
	#ifndef EV_USE_POSIX
		#define EV_USE_POSIX
	#endif
#elif defined WIN32
	#ifndef EV_USE_WIN32
		#define EV_USE_WIN32
	#endif
#endif

// 2. Apply user overrides for the system

#if defined EV_NO_USE_WIN32
	#undef EV_USE_WIN32
#endif
#if defined EV_NO_USE_UNIX
	#undef EV_USE_POSIX
	#undef EV_USE_LINUX
#endif
#if defined EV_NO_USE_LINUX
	#undef EV_USE_LINUX
	#undef EV_USE_URING
#endif

// 3. Infer sensible defaults for features from target

#define EV_USE_PTRTAG

#ifdef EV_USE_LINUX
	#define EV_USE_MULTITHREAD
	// Uring is rather unstable, so disabled by default
	// Build with -DEV_USE_URING to enable
	// #define EV_USE_URING
	#define EV_USE_EPOLL
#elif defined EV_USE_POSIX
	#define EV_USE_MULTITHREAD
	#define EV_USE_POLL
#elif defined EV_USE_WIN32
	#define EV_USE_MULTITHREAD
#endif

#if __STDC_VERSION__ >= 201100L
	#define EV_USE_ATOMIC
#endif

// 4. Apply user blacklists for features

#ifdef EV_NO_USE_URING
	#undef EV_USE_URING
#endif
#ifdef EV_NO_USE_EPOLL
	#undef EV_USE_EPOLL
#endif
#ifdef EV_NO_USE_MULTITHREAD
	#undef EV_USE_MULTITHREAD
#endif
#ifdef EV_NO_USE_ATOMIC
	#undef EV_USE_ATOMIC
#endif
#ifdef EV_NO_USE_PTHREAD
	#undef EV_USE_PTHREAD
#endif
#ifdef EV_NO_USE_PTRTAG
	#undef EV_USE_PTRTAG
#endif

// 5. Add gnu sources on linux (required for uring)

#ifdef EV_USE_LINUX
	#define _GNU_SOURCE
#endif

#endif
