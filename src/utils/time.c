#pragma once

#include <ev/conf.h>
#include <ev.h>

ev_time_t ev_timeadd(ev_time_t a, ev_time_t b) {
	ev_time_t res = { .sec = a.sec + b.sec, .nsec = a.nsec + b.nsec };
	if (res.nsec > 1000000000) {
		res.nsec -= 1000000000;
		res.sec += 1;
	}
	return res;
}
ev_time_t ev_timesub(ev_time_t a, ev_time_t b) {
	if (a.nsec < b.nsec) {
		a.nsec += 1000000000;
		a.sec -= 1;
	}

	ev_time_t res = { .sec = a.sec - b.sec, .nsec = a.nsec - b.nsec };
	if (res.nsec > 1000000000) {
		res.sec += 1;
		res.nsec -= 1000000000;
	}

	return res;
}
int ev_timecmp(ev_time_t a, ev_time_t b) {
	if (a.sec != b.sec) return a.sec < b.sec ? -1 : 1;
	if (a.nsec != b.nsec) return a.nsec < b.nsec ? -1 : 1;
	return 0;
}
int64_t ev_timems(ev_time_t time) {
	return time.sec * 1000 + (time.nsec + 999999) / 1000000;
}
