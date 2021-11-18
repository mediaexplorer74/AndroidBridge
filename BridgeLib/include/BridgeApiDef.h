#pragma once



#if !defined(DLL_EXPORT)
#ifdef __cplusplus
#define BRIDGE_API extern "C" _declspec(dllimport)

#else
#define BRIDGE_API _declspec(dllimport)
#endif

#else

#define BRIDGE_API extern "C" _declspec(dllexport)
#endif

