/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "mosquitto.h"

#if defined(WITH_MEMORY_TRACKING) && defined(WITH_BROKER)
#  if defined(__APPLE__) || defined(__FreeBSD__) || defined(__linux__)
#    define REAL_WITH_MEMORY_TRACKING
#  endif
#endif

#ifdef REAL_WITH_MEMORY_TRACKING
#  if defined(__APPLE__)
#    include <malloc/malloc.h>
#    define malloc_usable_size malloc_size
#  elif defined(__FreeBSD__)
#    include <malloc_np.h>
#  else
#    include <malloc.h>
#  endif
#endif

static unsigned long memcount = 0;
static unsigned long max_memcount = 0;

static size_t mem_limit = 0;
void mosquitto_memory_set_limit(size_t lim)
{
	mem_limit = lim;
}

unsigned long mosquitto_memory_used(void)
{
	return memcount;
}

unsigned long mosquitto_max_memory_used(void)
{
	return max_memcount;
}


#ifdef WITH_REAL_MEMORY_TRACKING

BROKER_EXPORT void *mosquitto_malloc(size_t size)
{
	void *mem;

	if(mem_limit && memcount + size > mem_limit){
		return NULL;
	}
	mem = malloc(size);
	if(mem){
		memcount += malloc_usable_size(mem);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}

	return mem;
}

BROKER_EXPORT void *mosquitto_realloc(void *ptr, size_t size)
{
	void *mem;
	size_t free_size = ptr != NULL ? malloc_usable_size(ptr) : 0;

	/* Avoid counter underflow due to mismatched memory allocation function usage */
	if(free_size > memcount){
		free_size = memcount;
	}
	if(mem_limit && memcount - free_size + size > mem_limit){
		return NULL;
	}
	mem = realloc(ptr, size);
	if(mem){
		memcount -= free_size;
		memcount += malloc_usable_size(mem);
		if(memcount > max_memcount){
			max_memcount = memcount;
		}
	}else if(size == 0){
		memcount -= free_size;
	}

	return mem;
}

BROKER_EXPORT void mosquitto_free(void *mem)
{
	if(!mem){
		return;
	}
	size_t free_size = malloc_usable_size(mem);
	free(mem);

	/* Avoid counter underflow due to mismatched memory function allocation usage */
	if(free_size > memcount){
		free_size = memcount;
	}
	memcount -= free_size;
}

#else /* #ifdef WITH_REAL_MEMORY_TRACKING */

BROKER_EXPORT void *mosquitto_malloc(size_t size)
{
	return malloc(size);
}

BROKER_EXPORT void *mosquitto_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

BROKER_EXPORT void mosquitto_free(void *mem)
{
	free(mem);
}

#endif /* #ifdef WITH_REAL_MEMORY_TRACKING */

BROKER_EXPORT void *mosquitto_calloc(size_t nmemb, size_t size)
{
	void *mem;
	const size_t alloc_size = nmemb * size;
	mem = mosquitto_malloc(alloc_size);
	if(mem){
		memset(mem, 0, alloc_size);
	}
	return mem;
}

BROKER_EXPORT char *mosquitto_strdup(const char *s)
{
	char *str;
	size_t size = strlen(s) + 1;

	str = mosquitto_malloc(size);
	if(str){
		memcpy(str, s, size);
	}
	return str;
}

BROKER_EXPORT char *mosquitto_strndup(const char *s, size_t n)
{
	char *str;
	size_t size = strnlen(s, n);

	if(size > n){
		size = n;
	}
	str = mosquitto_malloc(size + 1);
	if(str){
		memcpy(str, s, size);
	}
	str[size] = 0;
	return str;
}
