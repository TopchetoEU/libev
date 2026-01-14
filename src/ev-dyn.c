#include "ev/dyn.h"
#include "ev/errno.h"
#include <stdlib.h>
#include <ffi.h>
#include <stdbool.h>
#include <string.h>

#ifndef ffi_type_slonglong
	#if LONG_MAX == 2147483647
		#define ffi_type_slonglong ffi_type_sint32
	#elif LONG_MAX == FFI_64_BIT_MAX
		#define ffi_type_slonglong ffi_type_sint64
	#else
		#error "long long size not supported"
	#endif
#endif

struct ev_dyn_sig {
	ffi_cif cif;
	void *func;

	ffi_type *ret;

	size_t params_n;
	ffi_type *params[];
};
struct ev_dyn_args {
	ev_dyn_sig_t sig;
	void *pret;
	void *args[];
};

static void free_type(ffi_type *type) {
	if (type->type == FFI_TYPE_STRUCT) {
		for (ffi_type **curr = type->elements; *curr; curr++) {
			free_type(*curr);
		}

		free(type->elements);
		free(type);
	}
}

static ev_code_t parse_type(const char **pstr, ffi_type **pres) {
	const char *type = *pstr;

	if (*type == 'v') {
		*pstr = type + 1;
		*pres = &ffi_type_void;
		return EV_OK;
	}
	else if (*type == '*') {
		*pstr = type + 1;
		*pres = &ffi_type_pointer;
		return EV_OK;
	}
	else if (*type == 'b') {
		*pstr = type + 1;
		*pres = &ffi_type_schar;
		return EV_OK;
	}
	else if (*type == 'c') {
		*pstr = type + 1;
		*pres = &ffi_type_schar;
		return EV_OK;
	}
	else if (*type == 'i') {
		type++;
		if (*type == 'l') {
			type++;
			if (*type == 'l') {
				*pstr = type + 1;
				*pres = &ffi_type_slonglong;
				return EV_OK;
			}
			*pstr = type;
			*pres = &ffi_type_slong;
			return EV_OK;
		}
		else if (*type == 's') {
			*pstr = type + 1;
			*pres = &ffi_type_sshort;
			return EV_OK;
		}
		else if (*type == '8') {
			*pstr = type + 1;
			*pres = &ffi_type_sint8;
			return EV_OK;
		}
		else if (*type == '1') {
			type++;
			if (*type == '6') {
				*pstr = type + 1;
				*pres = &ffi_type_sint16;
				return EV_OK;
			}
			else return EV_EINVAL;
		}
		else if (*type == '3') {
			type++;
			if (*type == '2') {
				*pstr = type + 1;
				*pres = &ffi_type_sint32;
				return EV_OK;
			}
			else return EV_EINVAL;
		}
		else if (*type == '6') {
			type++;
			if (*type == '4') {
				*pstr = type + 1;
				*pres = &ffi_type_sint64;
				return EV_OK;
			}
			else return EV_EINVAL;
		}
		else  {
			*pstr = type;
			*pres = &ffi_type_sint;
			return EV_OK;
		}
	}
	else if (*type == 'f') {
		*pstr = type + 1;
		*pres = &ffi_type_float;
		return EV_OK;
	}
	else if (*type == 'd') {
		type++;
		if (*type == 'l') {
			*pstr = type + 1;
			*pres = &ffi_type_float;
			return EV_OK;
		}
		else {
			*pstr = type;
			*pres = &ffi_type_double;
			return EV_OK;
		}
	}
	else if (*type == '(') {
		ffi_type **els = malloc(sizeof *els * 16);
		size_t cap = 16, n = 0;
		ev_code_t code;

		while (*type != ')') {
			size_t old_cap = cap;
			while (n >= cap) cap *= 2;
			if (old_cap != cap) els = realloc(els, sizeof *els * cap);

			code = parse_type(&type, &els[n]);
			if (code != EV_OK) goto free_els;

			n++;
		}

		els = realloc(els, sizeof *els * (n + 1));
		els[n] = NULL;

		ffi_type *res = malloc(sizeof *res);
		if (!res) goto free_els;

		res->type = FFI_TYPE_STRUCT;
		res->elements = els;
		*pstr = type + 1;
		*pres = res;
		return EV_OK;

	free_els:
		for (size_t i = 0; i < n; i++) {
			free_type(els[i]);
		}
		free(els);
		return code;
	}
	else return EV_EINVAL;
}

ev_code_t ev_dyn_sig_new(void *func, const char *sig, ev_dyn_sig_t *pres) {
	ev_dyn_sig_t res = malloc(sizeof *res + sizeof *res->params * 16);
	size_t cap = 16, n = 0;
	ev_code_t code;

	if ((code = parse_type(&sig, &res->ret)) != EV_OK) {
		free(res);
		return code;
	}

	while (*sig) {
		if (n >= cap) {
			cap *= 2;
			res = realloc(res, sizeof *res + sizeof *res->params * cap);
		}

		if ((code = parse_type(&sig, &res->params[n])) != EV_OK) goto error;
		n++;
	}

	res->func = func;
	res->params_n = n;

	if (ffi_prep_cif(&res->cif, FFI_DEFAULT_ABI, n, res->ret, res->params) != FFI_OK) {
		code = EV_EINVAL;
		goto error;
	}

	*pres = res;
	return EV_OK;

error:
	free_type(res->ret);
	for (size_t i = 0; i < n; i++) {
		free_type(res->params[i]);
	}
	free(res);
	return code;
}
void ev_dyn_sig_free(ev_dyn_sig_t sig) {
	if (!sig) return;

	free_type(sig->ret);

	for (size_t i = 0; i < sig->params_n; i++) {
		free_type(sig->params[i]);
	}

	free(sig);
}

ev_dyn_args_t ev_dyn_args_new(ev_dyn_sig_t sig, void *pret, void **args) {
	size_t args_n = 0;
	for (void **it = args; *it; it++) args_n++;

	ev_dyn_args_t res = malloc(sizeof *res + sizeof *res->args * (args_n + 1));
	if (!res) return NULL;

	res->sig = sig;
	res->pret = pret;
	memcpy(res->args, args, sizeof *res->args * (args_n + 1));

	return res;
}

int ev_dyn_cb(void *pargs) {
	ev_dyn_args_t args = pargs;
	ffi_call(&args->sig->cif, args->sig->func, args->pret, args->args);
	free(pargs);
	return EV_OK;
}
