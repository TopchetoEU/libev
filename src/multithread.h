#pragma once

#include "ev/conf.h"

#ifdef EV_USE_WIN32
	#include <winsock2.h>
	#include <windows.h>

	typedef HANDLE ev_thread_t[1];
	typedef CRITICAL_SECTION ev_mutex_t[1];
	typedef CONDITION_VARIABLE ev_cond_t[1];

	#define ev_thread_new(th, entry, args) (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(entry), (args), 0, NULL) ? 0 : -1)
	#define ev_thread_free_join(th) (WaitForSingleObject(th, INFINITE) ? 0 : -1)

	#define ev_mutex_new(mut) ((InitializeCriticalSection(mut)), 0)
	#define ev_mutex_free(mut) (DeleteCriticalSection(mut), 0)
	#define ev_mutex_lock(mut) (EnterCriticalSection(mut), 0)
	#define ev_mutex_unlock(mut) (LeaveCriticalSection(mut), 0)

	#define ev_cond_new(cond) (InitializeConditionVariable(cond), 0)
	// #define ev_cond_free(cond) (DeleteConditionVariable(cond), 0)
	#define ev_cond_free(cond) ((void)cond)
	#define ev_cond_wait(cond, mut) (SleepConditionVariableCS(cond, mut, INFINITE) ? 0 : -1)
	#define ev_cond_broadcast(cond) (WakeAllConditionVariable(cond), 0)
	#define ev_cond_signal(cond) (WakeConditionVariable(cond), 0)



#elif defined EV_USE_PTHREAD
	#include <pthread.h>

	typedef pthread_t ev_thread_t[1];
	typedef pthread_mutex_t ev_mutex_t[1];
	typedef pthread_cond_t ev_cond_t[1];

	#define ev_thread_new(th, entry, args) pthread_create(th, (const pthread_attr_t*)NULL, entry, args)

	static inline void *ev_thread_free_join(ev_thread_t th) {
		void *ret;
		pthread_join(*th, &ret);
		return ret;
	}

	#define ev_mutex_new(mut) pthread_mutex_init(mut, (const pthread_mutexattr_t *)NULL)
	#define ev_mutex_free(mut) pthread_mutex_destroy(mut)
	#define ev_mutex_lock(mut) pthread_mutex_lock(mut)
	#define ev_mutex_unlock(mut) pthread_mutex_unlock(mut)

	#define ev_cond_new(cond) pthread_cond_init(cond, (const pthread_condattr_t *)NULL)
	#define ev_cond_free(cond) pthread_cond_destroy(cond)
	#define ev_cond_signal(cond) pthread_cond_signal(cond)
	#define ev_cond_broadcast(cond) pthread_cond_signal(cond)
	#define ev_cond_wait(cond, mut) pthread_cond_wait(cond, mut)
#else
	typedef struct {} pthread_mutex_t[1];

	#define ev_mutex_new(mut) (0)
	#define ev_mutex_free(mut) (0)
	#define ev_mutex_lock(mut) (0)
	#define ev_mutex_unlock(mut) (0)
#endif
