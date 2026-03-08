#ifndef EV_CONF_H
#define EV_CONF_H

#pragma once

// 1. Detect target

#if defined __unix__ && !defined EV_USE_POSIX
	#define EV_USE_POSIX
#endif
#if defined __linux && !defined EV_USE_LINUX
	#ifndef EV_USE_POSIX
		#define EV_USE_POSIX
	#endif
	#define EV_USE_LINUX
#endif
#if defined WIN32 && !defined EV_USE_WIN32
	#define EV_USE_WIN32
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
	#define EV_USE_URING
#elif defined EV_USE_POSIX
	#define EV_USE_MULTITHREAD
#elif defined EV_USE_WIN32
	#define EV_USE_MULTITHREAD
#endif

// 4. Apply user blacklists for features

#if defined EV_NO_USE_URING
	#undef EV_USE_URING
#endif
#ifdef EV_NO_USE_MULTITHREAD
	#undef EV_USE_PTHREAD
#endif
#ifdef EV_NO_USE_PTHREAD
	#undef EV_USE_PTHREAD
#endif
#if defined EV_NO_USE_PTRTAG
	#undef EV_USE_PTRTAG
#endif

// 5. Add gnu sources on linux (required for uring)

#if defined EV_USE_LINUX
	#define _GNU_SOURCE
#endif

#endif
