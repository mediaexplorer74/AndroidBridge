#pragma once

// Well-known TLS slots. What data goes in which slot is arbitrary unless otherwise noted.
enum {
	TLS_SLOT_SELF = 0, // The kernel requires this specific slot for x86.
	TLS_SLOT_THREAD_ID,
	TLS_SLOT_ERRNO,

	// These two aren't used by bionic itself, but allow the graphics code to
	// access TLS directly rather than using the pthread API.
	TLS_SLOT_OPENGL_API = 3,
	TLS_SLOT_OPENGL = 4,

	// This slot is only used to pass information from the dynamic linker to
	// libc.so when the C library is loaded in to memory. The C runtime init
	// function will then clear it. Since its use is extremely temporary,
	// we reuse an existing location that isn't needed during libc startup.
	TLS_SLOT_BIONIC_PREINIT = TLS_SLOT_OPENGL_API,

	TLS_SLOT_STACK_GUARD = 5, // GCC requires this specific slot for x86.
	TLS_SLOT_DLERROR,

	BIONIC_TLS_SLOTS // Must come last!
};
