#pragma once

#include <ev/conf.h>
#include <ev.h>

#include <ctype.h>
#include <string.h>

static bool ev_parse_ipv4(const char *str, ev_addr_t *pres) {
	ev_addr_t res;
	res.type = EV_ADDR_IPV4;

	const char *it = str;

	for (int i = 0; i < 4; i++) {
		uint64_t part = 0;

		if (!isdigit(*it)) return false;

		while (isdigit(*it)) {
			if (part > 100) return false;
			part = part * 10 + *it - '0';
			it++;
		}

		if (part > 255) return false;

		if (*it == '.') {
			if (i == 3) return false;
			it++;
		}
		if (*it == '\0' && i != 3) return false;

		res.v4[i] = part;
	}

	if (*it != '\0') return false;

	if (pres) *pres = res;
	return true;
}
static bool ev_parse_ipv6(const char *str, ev_addr_t *pres) {
	ev_addr_t res = { 0 };
	res.type = EV_ADDR_IPV6;

	const char *it = str;
	int zeroes_i = -1;
	int i = 0;

	if (it[0] == ':' && it[1] == ':') {
		it += 2;
		zeroes_i = 0;

		if (*it == '\0') {
			*pres = res;
			return true;
		}
	}

	for (i = 0; i < 8; i++) {
		if (!isxdigit(*it)) return false;

		for (int j = 0; j < 4; j++) {
			if (!isxdigit(*it)) break;

			res.v6[i] <<= 4;
			if (isdigit(*it)) res.v6[i] |= *it - '0';
			if (islower(*it)) res.v6[i] |= *it - 'a' + 10;
			if (isupper(*it)) res.v6[i] |= *it - 'A' + 10;
			it++;
		}

		if (*it == ':') {
			it++;
			continue;
		}

		if (it[0] == ':' && it[1] == ':') {
			if (zeroes_i != -1) return false;
			zeroes_i = i;
			it += 2;
		}

		if (*it == '\0') break;
	}

	if (*it != '\0') return false;

	if (zeroes_i > 0) {
		int trailing_n = i - zeroes_i;
		memmove(res.v6 + (16 - trailing_n), res.v6 + zeroes_i, sizeof *res.v6 * trailing_n);
	}

	if (pres) *pres = res;
	return true;
}

bool ev_parse_ip(const char *str, ev_addr_t *pres) {
	if (ev_parse_ipv4(str, pres)) return true;
	if (ev_parse_ipv6(str, pres)) return true;
	return false;
}
bool ev_cmpaddr(ev_addr_t a, ev_addr_t b) {
	if (a.type != b.type) return false;
	if (a.type == EV_ADDR_IPV4) {
		return !memcmp(a.v4, b.v4, sizeof a.v4);
	}
	else {
		return !memcmp(a.v6, b.v6, sizeof a.v6);
	}
}
