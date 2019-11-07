/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2018, CJSC Aktiv-Soft. All rights reserved.         *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Данный файл содержит переопределение функций Windows для               *
* *nix-платформ                                                          *
*************************************************************************/

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define RUTOKENECP
#define TOKEN
#define FAST
#define RSAMODULUSBITS 1024
#define RSA

#ifdef _WIN32

void createThread(uintptr_t* thread, unsigned int size, void (* funct)(void*), void* arg)
{
	*thread = _beginthread(funct, size, arg);
}

#endif

#if defined(__unix__) || defined(__APPLE__)

#include <dlfcn.h>
#include <sys/time.h>
#include <pthread.h>

typedef void* HMODULE;

static HMODULE LoadLibrary(const char* path)
{
	return dlopen(path, RTLD_NOW);
}

static unsigned long GetTickCount(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0) {
		return 0;
	}
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static BOOL FreeLibrary(HMODULE module)
{
	// return value is inverted in order to correspond to Windows behavior:
	return !dlclose(module);
}

static ptrdiff_t GetProcAddress(HMODULE module, const char* proc_name)
{
	return (ptrdiff_t)(dlsym(module, proc_name));
}

#define uintptr_t pthread_t

static void createThread(uintptr_t* thread, pthread_attr_t* attr, void* funct, void* arg)
{
	pthread_create(thread, attr, funct, arg);
}



#ifdef __APPLE__
const char DEFAULTLIBRARYNAME[] = "./librtpkcs11ecp.dylib";
#else
const char DEFAULTLIBRARYNAME[] = "./librtpkcs11ecp.so";
#endif

#endif // __unix__ || __APPLE__



