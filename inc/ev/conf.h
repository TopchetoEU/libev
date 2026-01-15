#ifndef EV_CONF_H
#define EV_CONF_H

#pragma once

// 1. Infer sensible defaults

#if defined __unix__
	#ifndef EV_USE_UNIX
		#define EV_USE_UNIX
	#endif

	#if !defined __linux
		#ifndef EV_USE_LINUX
			#define EV_USE_LINUX
		#endif
		#ifndef EV_USE_URING
			#define EV_USE_URING
		#endif
	#endif

	#ifndef EV_USE_MULTITHREAD
		#define EV_USE_MULTITHREAD
	#endif
	#ifndef EV_USE_PTHREAD
		#define EV_USE_PTHREAD
	#endif
#elif defined WIN32
	#define EV_USE_WIN32
#endif

#define EV_USE_PTRTAG

// 2. Reflect user-defined blacklist overrides

#if defined EV_NO_USE_WIN32
	#undef EV_USE_WIN32
#endif
#if defined EV_NO_USE_UNIX
	#undef EV_USE_UNIX
#endif
#if defined EV_NO_USE_LINUX
	#undef EV_USE_LINUX
	#undef EV_USE_URING
#endif
#if defined EV_NO_USE_URING
	#undef EV_USE_URING
#endif
#ifdef EV_NO_USE_MULTITHREAD
	#undef EV_USE_PTHREAD
	#undef EV_USE_MULTITHREAD
#endif
#ifdef EV_NO_USE_PTHREAD
	#undef EV_USE_PTHREAD
#endif
#if defined EV_NO_USE_PTRTAG
	#undef EV_USE_PTRTAG
#endif

// 3. Setup other defines, if they depend on above config

#if defined EV_USE_URING
	#define _GNU_SOURCE
#endif

#endif
