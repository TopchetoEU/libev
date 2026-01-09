libev is a dead-simple library for performing platform-specific operations in a non-blocking and platform-independent way.

## Core architecture

This library uses an event loop in its core - you perform operations, which return a "ticket id". Then, in a single poll queue, you eventually get a response, containing that ticket ID.

This architecture still lets you implement a callback-based workflow - just store a map of tickets -> callbacks. However, it doesn't force you to use C callbacks, which can be a pain for managed languages.

## Why not libuv?

libuv aims to solve the same problem, but is too complex for its own good - hell, you need to run three scripts just to compile the darn thing. Also, it uses callbacks to signal the program that the work is done. If the implementation lives exclusively in C-land, this is fine. However, callbacks across the FFI boundary in most non-C languages are slow and clunky.

Those are non-issues in most cases, but it doesn't scratch my "its so complex" itch.
