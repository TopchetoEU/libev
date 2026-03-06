#pragma once
#include "ev.h"
#include "multithread.h"
#include <stdio.h>

typedef struct {
	struct ev_pool_worker *next_worker;
} *ev_pool_t, ev_pool_s;
typedef struct ev_pool_worker {
	struct ev_pool_worker *next;
	ev_t ev;
	ev_mutex_t lock;
	ev_cond_t cond;

	ev_thread_t thread;

	ev_worker_t worker;
	void *udata;
	void *args;

	bool kys;
} *ev_pool_worker_t;

static void evi_pool_worker_entry(void *pargs) {
	ev_pool_worker_t worker = (ev_pool_worker_t)pargs;

	ev_mutex_lock(worker->lock);

	while (true) {
		while (worker->worker && !worker->kys) {
			void *udata = worker->udata;
			ev_worker_t cb = worker->worker;
			void *args = worker->args;

			ev_mutex_unlock(worker->lock);
			ev_code_t code = cb(args);
			ev_mutex_lock(worker->lock);

			worker->worker = NULL;
			worker->args = NULL;
			worker->udata = NULL;

			ev_push(worker->ev, udata, code);
		}
		if (worker->kys) break;

		ev_cond_wait(worker->cond, worker->lock);
	}

	ev_mutex_unlock(worker->lock);
}

static ev_code_t evi_pool_exec(ev_t ev, ev_pool_t pool, void *udata, ev_worker_t worker, void *pargs) {
	for (ev_pool_worker_t it = pool->next_worker; it; it = it->next) {
		ev_mutex_lock(it->lock);
		if (!it->worker) {
			it->worker = worker;
			it->args = pargs;
			it->udata = udata;
			ev_begin(ev);
			ev_cond_broadcast(it->cond);
			ev_mutex_unlock(it->lock);
			return EV_OK;
		}
		ev_mutex_unlock(it->lock);
	}

	ev_pool_worker_t pool_worker = malloc(sizeof *pool_worker);
	if (!pool_worker) return EV_ENOMEM;

	ev_cond_new(pool_worker->cond);
	ev_mutex_new(pool_worker->lock);

	pool_worker->ev = ev;
	pool_worker->kys = false;

	pool_worker->worker = worker;
	pool_worker->args = pargs;
	pool_worker->udata = udata;

	pool_worker->next = pool->next_worker;
	pool->next_worker = pool_worker;

	fprintf(stderr, "started a new thread\n");
	if (ev_thread_new(pool_worker->thread, evi_pool_worker_entry, pool_worker) < 0) {
		ev_cond_free(pool_worker->cond);
		free(pool_worker);
		return EV_EAGAIN;
	}

	ev_begin(ev);
	return EV_OK;
}

static void evi_pool_init(ev_pool_t pool) {
	pool->next_worker = NULL;
}
static void evi_pool_free(ev_pool_t pool) {
	while (pool->next_worker) {
		ev_pool_worker_t curr = pool->next_worker;
		pool->next_worker = curr->next;

		ev_mutex_lock(curr->lock);
		curr->kys = true;
		ev_thread_cancel(curr->thread);
		ev_cond_broadcast(curr->cond);
		ev_mutex_unlock(curr->lock);

		ev_thread_free_join(curr->thread);

		ev_cond_free(curr->cond);
		ev_mutex_free(curr->lock);
		free(curr);
	}

	pool->next_worker = NULL;
}
