/*
Copyright (c) 2023 Cedalo GmbH

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

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"

#ifdef __cplusplus
}
#endif

#define kMinInputLength 1
#define kMaxInputLength 268435455U

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mosquitto *context = NULL;
	uint8_t *data_heap;

	//if(size < kMinInputLength || size > kMaxInputLength){
		//return 0;
	//}

	db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
	log__init(db.config);

	data_heap = (uint8_t *)malloc(size);
	memcpy(data_heap, data, size);


	context = context__init();
	context->state = mosq_cs_active;
	context->in_packet.command = data_heap[0];
	context->in_packet.payload = (uint8_t *)data_heap;
	context->in_packet.packet_length = size;
	context->in_packet.remaining_length = size-1;
	context->in_packet.pos = 1;

	handle__packet(context);

	context__cleanup(context, true);

	free(db.config);

	return 0;
}
