#ifndef EV_DYN_H
#define EV_DYN_H

#include "ev/errno.h"

// A simple wrapper around libffi, so that ev_exec can be used by dynamic languages

typedef struct ev_dyn_sig *ev_dyn_sig_t;
typedef struct ev_dyn_args *ev_dyn_args_t;

// Creates a signature, that can then be used in ev_dyn_args_t
// First type is the return type, the rest are the arguments, no variadic args allowed
// Return EINVAL if sig's syntax is invalid
//
// Types:
//     v -> void (may not be used as a standalone argument)
//     c -> char
//     is -> int
//     i -> int
//     il -> long int
//     ill -> long long int
//     f -> float
//     d -> double
//     dl -> long double
//     i8 -> int8_t
//     i16 -> int16_t
//     i32 -> int32_t
//     i64 -> int64_t
//     * -> a pointer
//     (...types) -> structure of the given types
//
// Example: struct { int a; int b; }* (int a, int b, my_ptr_t *c) -> (ii)ii*
ev_code_t ev_dyn_sig_new(void *func, const char *sig, ev_dyn_sig_t *pres);
// Releases all resources, used by this signature
// It goes without saying that this must be called after all callbacks, depending on these have begun execution
void ev_dyn_sig_free(ev_dyn_sig_t sig);

// Creates arguments for ev_dyn_cb. Freeing the structure is handled by ev_dyn_cb
// Returns NULL when out of memory (aka EV_ENOMEM is implied)
ev_dyn_args_t ev_dyn_args_new(ev_dyn_sig_t sig, void *pret, void **args);

// A callback, usable in ev_exec. Always will report EV_OK
// Must be passed a ev_dyn_args_t
//
// Example usage:
//     ev_dyn_sig_t sig;
//     ev_dyn_mksig(printf, "i*ii", &sig);
//
//     int res;
//
//     const char *fmt = "A = %d, B = %d\n";
//     int a = 10;
//     int b = 5;
//     ev_exec(ev_dyn_cb, ev_dyn_mkargs(sig, &res, (void[]) { &fmt, &a, &b }));
int ev_dyn_cb(void *pargs);

#endif
