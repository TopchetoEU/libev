libev is a dead-simple alternative to libuv for performing platform-specific operations in a non-blocking and platform-independent way.

## Core architecture

This library works more or less the same way as libuv - a thread pool is used for blocking operations, which then push their results to a message queue, while non-blocking operations push their results on the queue when the non-blocking operation's callback is called.

Where libev differs from libuv is that it ONLY does IO, and instead of using callbacks to deliver messages, a `void*` is passed to the IO function, which then is returned from the message polling function, alongside an error code. It is up to the user code to determine what the semantic meaning of this user data is.

Of course, you can (and are encouraged to) implement some sort of callback system on top of this system (in my lua wrapper, this is done with a simple table of incremental udata -> callback).

## Why not libuv?

libuv has a notoriously difficult build process - in comparison, libev is a unity build - you can build it with a single gcc command. Also, the callback nature of libuv makes it a PITA to use in managed languages. libuv also, for some reason, decides to implement an utterly baffling OOP inheritance chain of different handles. libev does none of that and is mostly procedural. Last but not least, libuv is a whopping 70K lines of code, while libev doesn't even clock in at 2K LOC, and yet does more or less the same things libuv does (except for event loop management, which is delegated to client code, but a quality implementation should fit in under 5K LOC).

# Why libuv?

Make no mistake, libev is a hobby project and is largely untested, while libuv has been battle-tested for more than 10 years, so you can most likely count on it. Also, libev still doesn't offer support for some of the stuff libuv offers (but it is trivially simple to implement them, as libev exposes a `ev_exec` function, which executes a function in the threadpool of libev and returns the result in the message queue).

# General pattern of usage

An example luajit FFI wrapper has been included, so that you can get an idea of how to use the library. Every function has been documented in the header, you can take a look at that. But at a high level, this is what you want to do (in pseudocode):

```
map<ev_ticket_t, coroutine> callbacks = {};
list<coroutine> tasks = [];
int next_udata = 0;
ev_loop_t loop = ev_init();

func sync_call(function ev_func, ev_t loop, ...) {
	int udata = ++next_udata;
	ev_ticket_t ticket = ev_func(loop, udata, ...);
	callbacks[udata] = curr_coroutine;
	return coro_yield();
}

func run_loop() {
	while (true) {
		foreach (task in tasks) {
			coro_resume(task);
		}

		// Exit out when all tasks & tickets are done
		if (!ev_busy(loop)) ev_free(loop);

		void *udata;
		int err;
		if (!ev_poll(loop, true, &udata, &err)) break;

		coro_resume(callbacks[(int)udata], err);
		delete callbacks[(int)udata];
	}
}

tasks += coroutine {
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
