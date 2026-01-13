#pragma once

#include "ev.h"
#include "ev/errno.h"
#include <assert.h>

#ifdef EV_USE_WIN32
	#include <winsock2.h>
	#include <windows.h>

	typedef HANDLE ev_thread_t[1];
	typedef CRITICAL_SECTION ev_mutex_t[1];
	typedef CONDITION_VARIABLE ev_cond_t[1];

	#define ev_thread_new(th, entry, args) (CreateThread(NULL, 0, (void*)(entry), (args), 0, NULL) ? 0 : -1)
	#define ev_thread_free_join(th) (WaitForSingleObject(th, INFINITE) ? 0 : -1)
	#define ev_thread_cancel(th) (CancelSynchronousIo(th) ? 0 : -1)

	#define ev_mutex_new(mut) (void)InitializeCriticalSection(mut)
	#define ev_mutex_free(mut) (void)DeleteCriticalSection(mut)
	#define ev_mutex_lock(mut) (void)EnterCriticalSection(mut)
	#define ev_mutex_unlock(mut) (void)LeaveCriticalSection(mut)

	#define ev_cond_new(cond) (void)InitializeConditionVariable(cond)
	// #define ev_cond_free(cond) (DeleteConditionVariable(cond), 0)
	#define ev_cond_free(cond) ((void)cond)
	#define ev_cond_wait(cond, mut) (void)SleepConditionVariableCS(cond, mut, INFINITE)
	static inline ev_code_t ev_cond_timewait(ev_cond_t cond, ev_mutex_t mut, ev_time_t timeout) {
		ev_time_t curr;
		ev_monotime(&curr);

		int64_t ms = ev_timems(ev_timesub(timeout, curr));
		if (ms < 0) ms = 0;

		if (!SleepConditionVariableCS(cond, mut, ms)) return EV_ETIMEDOUT;
		return 0;
	}
	#define ev_cond_broadcast(cond) (void)WakeAllConditionVariable(cond)
	#define ev_cond_signal(cond) (void)WakeConditionVariable(cond)
#elif defined EV_USE_PTHREAD
	#include <errno.h>
	#include <pthread.h>

	typedef pthread_t ev_thread_t[1];
	typedef pthread_mutex_t ev_mutex_t[1];
	typedef pthread_cond_t ev_cond_t[1];

	#define ev_thread_new(th, entry, args) pthread_create(th, (const pthread_attr_t*)NULL, entry, args)
	#define ev_thread_cancel(th) (void)pthread_cancel(*(th))

	static inline void *ev_thread_free_join(ev_thread_t th) {
		void *ret;
		pthread_join(*th, &ret);
		return ret;
	}

	#define ev_mutex_new(mut) (void)pthread_mutex_init(mut, (const pthread_mutexattr_t *)NULL)
	#define ev_mutex_free(mut) (void)pthread_mutex_destroy(mut)
	#define ev_mutex_lock(mut) (void)pthread_mutex_lock(mut)
	#define ev_mutex_unlock(mut) (void)pthread_mutex_unlock(mut)

	static inline void ev_cond_new(ev_cond_t cond) {
		pthread_condattr_t attr[1];
		pthread_condattr_init(attr);
		pthread_condattr_setclock(attr, CLOCK_MONOTONIC);
		pthread_cond_init(cond, attr);
		pthread_condattr_destroy(attr);
	}
	#define ev_cond_free(cond) pthread_cond_destroy(cond)
	#define ev_cond_signal(cond) (void)pthread_cond_signal(cond)
	#define ev_cond_broadcast(cond) (void)pthread_cond_signal(cond)
	#define ev_cond_wait(cond, mut) (void)pthread_cond_wait(cond, mut)
	static inline ev_code_t ev_cond_timewait(ev_cond_t cond, ev_mutex_t mut, ev_time_t timeout) {
		int code = pthread_cond_timedwait(cond, mut, &(struct timespec) { .tv_sec = timeout.sec, .tv_nsec = timeout.nsec });
		if (code == ETIMEDOUT) return EV_ETIMEDOUT;
		return 0;
	}
#else
	typedef struct {} pthread_mutex_t[1];

	#define ev_mutex_new(mut) (0)
	#define ev_mutex_free(mut) (0)
	#define ev_mutex_lock(mut) (0)
	#define ev_mutex_unlock(mut) (0)
#endif
