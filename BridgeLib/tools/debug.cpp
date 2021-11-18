#include "pch.h"
#include "tools.h"
#include <stdio.h>

void DebugLog(char* pszFormat, ...) {

	static char s_acBuf[2048]; // this here is a caveat!

	va_list args;

	va_start(args, pszFormat);

	vsnprintf(s_acBuf, 2048, pszFormat, args);

	OutputDebugStringA(s_acBuf);

	va_end(args);
}