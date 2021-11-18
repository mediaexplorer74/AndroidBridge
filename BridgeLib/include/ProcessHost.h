#pragma once


#if !defined(DLL_EXPORT)
#define DLL_EXPORT _declspec(dllimport)
#endif

extern "C" DLL_EXPORT int RunHost();
