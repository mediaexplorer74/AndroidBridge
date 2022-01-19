
#pragma once

#include <stdbool.h>

#define MAX_SESSION_ID_LEN	8
#define DEFAULT_SESSION_ID	"default"

struct _flags
{
	char global_session_id[MAX_SESSION_ID_LEN];
	/* DBT flags */
	bool dbt_trace;
	bool dbt_trace_all;
};

extern struct _flags *cmdline_flags;

void flags_init();
void flags_afterfork_parent();
void flags_afterfork_child();
