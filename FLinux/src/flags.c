
#include <syscall/mm.h>
#include <flags.h>

struct _flags *cmdline_flags;

void flags_init()
{
	cmdline_flags = (struct _flags *)mm_static_alloc(sizeof(struct _flags));
	strcpy_s(cmdline_flags->global_session_id, sizeof(cmdline_flags->global_session_id), DEFAULT_SESSION_ID);
}

void flags_afterfork_parent()
{
}

void flags_afterfork_child()
{
	cmdline_flags = (struct _flags *)mm_static_alloc(sizeof(struct _flags));
}
