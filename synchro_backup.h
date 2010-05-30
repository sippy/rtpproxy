/*
 * Copyright (c) 2010 Keyyo
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: synchro_backup.h,v 1.0 2010/04/15 11:10:08 pmaymat Exp $
 *
 * Author      : Philippe Maymat (Keyyo)
 * Description : Usefull functions for communication between a main proxy and
 * 		 a slave
 */

#ifndef __SYNCHRO_BACKUP_H__
#define __SYNCHRO_BACKUP_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "rtpp_defines.h"
#include "rtpp_session.h"


struct sess_infos_list
{
	char* call_id;
	char* mess;
	time_t time;
	struct sess_infos_list* next;

};

int add_session_message(const char* call_id, const char * message);
int remove_all_session_infos(const char* call_id);
int save_sessions_infos(struct cfg* cf);

int send_synchro_message(struct cfg *cf, const char * mess, ...);
int receive_synchro_message(const int port);

int parse_ha_optarg(struct cfg *, char *);

#endif
