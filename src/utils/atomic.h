#pragma once

#include <ev/conf.h>
#include <ev/sync.h>
#include <ev/errno.h>
#include <ev.h>

#include <assert.h>

#if defined EV_USE_ATOMIC
	#include <stdatomic.h>

	#define ev_atom(T) _Atomic(T)
#else
	#define ev_atom(T) volatile T
#endif
