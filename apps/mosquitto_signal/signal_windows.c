/*
Copyright (c) 2024 Roger Light <roger@atchoo.org>

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
#ifdef WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <psapi.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mosquitto_signal.h"

void signal_all(const char *eventname)
{
	DWORD processes[2048], cbneeded, count;
	int pid;

	if(!EnumProcesses(processes, sizeof(processes), &cbneeded)){
		fprintf(stderr, "Error enumerating processes.\n");
		return;
	}

	count = cbneeded / sizeof(DWORD);
	for(int i=0; i<count; i++){
		if(processes[i]){
			HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if(hproc){
				HMODULE hmod;
				DWORD modcount;
				char procname[MAX_PATH];
				if(EnumProcessModules(hproc, &hmod, sizeof(hmod), &cbneeded)){
					GetModuleBaseName(hproc, hmod, procname, sizeof(procname));
					if(!strcasecmp(procname, "mosquitto.exe")){
						pid = GetProcessId(hproc);
						signal_one(pid, eventname);
					}
				}
				CloseHandle(hproc);
			}
		}
	}
}

void signal_one(int pid, const char *eventname)
{
	HANDLE evt;
	char eventbuf[MAX_PATH+1];
	BOOL res;

	snprintf(eventbuf, sizeof(eventbuf), "mosq%d_%s", pid, eventname);
	evt = OpenEvent(EVENT_MODIFY_STATE, FALSE, eventbuf);
	if(evt){
		res = PulseEvent(evt);
		CloseHandle(evt);
	}
}
