libev is a dead-simple alternative to libuv for performing platform-specific operations in a non-blocking and platform-independent way.

## Core architecture

This library uses a ticket + message queue system at its core. Imagine you are at a fast food restaurant. More often than not, you make an order, and you are returned a sequential ticket. Then, when your order is ready, your number is called and you collect your order. The system, utilized by this library is more or less the same. When you make a request, the request function creates a ticket (`ev_next`), and when the request is done, it pushes the ticket to the message queue (`ev_push`). Eventually, the client will collect the ticket and call its callback (`ev_poll`).

Of course, you can (and are encouraged to) implement some sort of callback system on top of this system (in my lua wrapper, this is done with a simple table of ticket id -> callback).

You might wonder why a ticket system is used instead of a callback-based system (like libuv). The simple answer is that passing managed (and garbage-collected callbacks) to unmanaged code is a major PITA, to say the least.

## Why not libuv?

libuv has a notoriously difficult build process - in comparison, libev is a unity build - you can build it with a single gcc command. Also, as mentioned above, the callback nature of libuv makes it a PITA to use in managed languages. libuv also, for some reason, decides to implement an utterly baffling OOP inheritance chain of different handles. libev does none of that and is mostly procedural. Last but not least, libuv is a whopping 70K lines of code, while libev doesn't even clock in at 2K LOC, and yet does more or less the same things libuv does.

# Why libuv?

Make no mistake, libev is a hobby project and is largely untested, while libuv has been battle-tested for more than 10 years, so you can count on it. Also, libev still doesn't offer support for some of the stuff libuv offers (but it is trivially simple to implement them, as libev exposes a `ev_exec` function, which executes a function in the threadpool of libev and returns the result as a ticket message).

# General pattern of usage

An example luajit FFI wrapper has been included, so that you can get an idea of how to use the library. Every function has been documented in the header, you can take a look at that. But at a high level, this is what you want to do (in pseudocode):

```
map<ev_ticket_t, coroutine> callbacks = {};
list<coroutine> tasks = [];
ev_loop_t loop = ev_init();

func sync_call(function ev_func, ev_t loop, ...) {
	ev_ticket_t ticket = ev_func(loop, ...);
	callbacks[ticket] = curr_coroutine;
	return coro_yield();
}

func run_loop() {
	while (true) {
		foreach (task in tasks) {
			coro_resume(task);
		}

		// Exit out when all tasks & tickets are done
		if (!ev_busy(loop)) ev_free(loop);

		ev_ticket_t ticket;
		int err;
		if (!ev_poll(loop, true, &ticket, &err)) break;

		coro_resume(callbacks[ticket], err);
		delete callbacks[ticket];
	}
}

callbacks += coroutine {
	ev_fd_t stdout = ev_stdout(loop);
	ev_fd_t f;
	sync_call(ev_open, loop, &f, "myfile.txt", EV_OPEN_READ);

	size_t i = 0;
	while (true) {
		size_t n = 1024;
		char buff[1024];

		sync_call(ev_read, loop, f, &n, buff, i);
		if (n == 0) break;

		i += n;
		sync_call(ev_write, loop, stdout, &n, buff, i);
	}
};

```
