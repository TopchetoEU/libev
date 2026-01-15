#pragma once

#include "ev/conf.h"
#include "ev.h"
#include "ev/errno.h"
#include <assert.h>
#include <stdlib.h>

#if defined EV_USE_WIN32 && defined EV_USE_MULTITHREAD
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
#elif defined EV_USE_PTHREAD && defined EV_USE_MULTITHREAD
	#include <errno.h>
	#include <pthread.h>
	#include <signal.h>

	typedef pthread_t ev_thread_t[1];
	typedef pthread_mutex_t ev_mutex_t[1];
	typedef pthread_cond_t ev_cond_t[1];

	typedef struct {
		void (*entry)(void *pargs);
		void *pargs;
	} *ev_thread_args_t;

	static void ev_thread_sighandle(int sig) {
		(void)sig;
	}
	static void *ev_thread_entry(void *pargs) {
		ev_thread_args_t args = pargs;
		void (*entry)(void *pargs) = args->entry;
		void *entry_pargs = args->pargs;
		free(args);

		struct sigaction sig_act = {
			.sa_handler = ev_thread_sighandle,
			.sa_flags = 0,
		};
		sigemptyset(&sig_act.sa_mask);

		sigaction(SIGUSR1, &sig_act, NULL);

		entry(entry_pargs);
		return NULL;
	}

	static inline int ev_thread_new(ev_thread_t th, void (*entry)(void *pargs), void *pargs) {
		ev_thread_args_t args = malloc(sizeof *args);
		args->entry = entry;
		args->pargs = pargs;
		return pthread_create(th, (const pthread_attr_t*)NULL, ev_thread_entry, args);
	}
	#define ev_thread_cancel(th) (void)pthread_kill(*(th), SIGUSR1)

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
	typedef struct {} ev_mutex_t[1];

	#define ev_mutex_new(mut)
	#define ev_mutex_free(mut)
	#define ev_mutex_lock(mut)
	#define ev_mutex_unlock(mut)
#endif
