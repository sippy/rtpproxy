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
 * $Id: synchro_backup.c,v 1.0 2010/04/15 11:10:08 pmaymat Exp $
 *
 * Author      : Philippe Maymat (Keyyo)
 * Description : Usefull functions for communication between a main proxy and
 * 		 a slave
 */

#include <fcntl.h>
#include <time.h>

#include "rtpp_network.h"
#include "rtpp_util.h"
#include "synchro_backup.h"

#define BUFLEN 8*1024

static struct sess_infos_list sessions_infos;

static struct sess_infos_list* last_sess_infos = &sessions_infos;

int add_session_message(const char* call_id, const char * message)
{

	last_sess_infos->next = malloc (sizeof(sessions_infos));
	last_sess_infos=last_sess_infos->next;
	last_sess_infos->call_id = strdup(call_id);
	last_sess_infos->mess = strdup(message);
	last_sess_infos->time = time ( NULL );
	last_sess_infos->next = NULL;

	return 1;
}

int remove_all_session_infos(const char* call_id)
{
	int removed = 0;
	struct sess_infos_list* ptr = &sessions_infos;

	while (ptr->next)
	{
		if((strcmp(ptr->next->call_id,call_id)==0)||(time ( NULL ) - ptr->next->time > 3600))
		{
			struct sess_infos_list* tptr = ptr->next;
			ptr->next = tptr->next;
			free (tptr->call_id);
			free (tptr->mess);
			free (tptr);
			removed++;
		}
		else
			ptr=ptr->next;
	}

	last_sess_infos = ptr;

	return removed;
}

int save_sessions_infos(struct cfg* cf)
{
	int written=0;
	time_t tt;

	tt= time ( NULL );

	if(cf->ha.stored_sessions_file)
	{
		rtpp_log_write(RTPP_LOG_INFO, cf, "High avaibility : save_sessions_infos called (%s)",cf->ha.stored_sessions_file);

		struct sess_infos_list* ptr = &sessions_infos;
		FILE* hd = fopen(cf->ha.stored_sessions_file,"w");

		fprintf(hd,"%d\n",(int)tt);

		rtpp_log_write(RTPP_LOG_DBUG, cf, "High avaibility : timestamp %d wrote",tt);


		while((ptr=ptr->next))
		{
			fprintf(hd,"%s\n",ptr->mess);
			written++;
			rtpp_log_write(RTPP_LOG_DBUG, cf, "High avaibility : %s wrote",ptr->mess);
		}

		fclose(hd);
	}
	else written = -1;

	return written;
}


int send_data_to_backup(struct cfg* cf, const char* message)
{
        struct sockaddr_in si_other;

	int s, slen=sizeof(si_other);

	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
		{printf("socket");return 0;}

	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(cf->ha.send_to_port);

	if (inet_aton(cf->ha.send_to_ip, (struct in_addr *)&si_other.sin_addr)==0)
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

	if (sendto(s, message, strlen(message)+1, 0, (const struct sockaddr *)&si_other, slen)==-1)
		rtpp_log_ewrite(RTPP_LOG_ERR, cf, "High avaibility : Socket error in sending %s to %s:%i",message,cf->ha.send_to_ip,cf->ha.send_to_port);

	rtpp_log_write(RTPP_LOG_DBUG, cf, "High avaibility : %s sent to %s:%i",message,cf->ha.send_to_ip,cf->ha.send_to_port);

	close(s);

	return 0;
}

int receive_synchro_message(const int port)
{
	struct sockaddr_in si_me, si_other;
	int s=0;
	unsigned int slen=sizeof(si_other);
	int len = 0;
	char message[BUFLEN];
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
		{printf("socket");return 0;}

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, (const struct sockaddr *)&si_me, sizeof(si_me))==-1)
		{printf("bind");return 0;}

	if ((len=recvfrom(s, &message, BUFLEN, 0, (struct sockaddr *)&si_other, &slen))==-1)
		printf("Received packet from %s:%d\n Data: %s\n\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), message);

	close(s);
	return 0;
}

int send_synchro_message(struct cfg *cf, const char * mess, ...)
{


	va_list parms;
	va_start(parms,mess);
	char mess_to_send[BUFLEN];

	if(strcmp(mess,"Append_sess")==0)
	{
		//parameters for this action are:   Call_id port_local: remote_ip remote_port from_tag weak
		char* call_id = va_arg(parms, char*);
		int port_local = va_arg(parms, int);
		char* remote_ip = va_arg(parms, char*);
		int remote_port = va_arg(parms, int);
		char* from_tag = va_arg(parms, char*);
		int weak = va_arg(parms, int);

		// synchro_rtp_proxy_message construction
		snprintf(mess_to_send, BUFLEN, "SYNC_RTPPROXY 1.0 APPEND_SESS %s %i %s %i %s %i %d",call_id,port_local,remote_ip,remote_port,from_tag, weak,(int)time ( NULL ));

		//send message
		// Check if High Avaibility mode is activated
		if(cf->ha.is_activated)
			send_data_to_backup(cf,mess_to_send);
		if(cf->ha.stored_sessions_file!=NULL)
			add_session_message(call_id,mess_to_send);
	}
	if(strcmp(mess,"Update_address")==0)
	{
		//parameters for this action are:  call_id, pidx , addr, port, from_tag, to_tag
		char* call_id = va_arg(parms, char*);
		int pidx = va_arg(parms, int);
		char* addr = va_arg(parms, char*);
		char* port = va_arg(parms, char*);
		char* from_tag = va_arg(parms, char*);
		char* to_tag = va_arg(parms, char*);

		// synchro_rtp_proxy_message construction
		snprintf(mess_to_send, BUFLEN, "SYNC_RTPPROXY 1.0 UPDATE_ADDRESS %s %i %s %s %s %s %d",call_id,pidx,addr,port,from_tag, to_tag,(int) time ( NULL ));

		//send message
		// Check if High Avaibility mode is activated
		if(cf->ha.is_activated)
			send_data_to_backup(cf,mess_to_send);
		if(cf->ha.stored_sessions_file!=NULL)
			add_session_message(call_id,mess_to_send);
	}
	if(strcmp(mess,"Lookup_sess")==0)
	{
		//parameters for this action are:   Call_id ip port_local from_tag to_tag
		char* call_id = va_arg(parms, char*);
		char* ip = va_arg(parms, char*);
		int port = va_arg(parms, int);
		int port_local = va_arg(parms, int);
		char* from_tag = va_arg(parms, char*);
		char* to_tag = va_arg(parms, char*);
		int weak = va_arg(parms, int);

		// synchro_rtp_proxy_message construction
		snprintf(mess_to_send, BUFLEN, "SYNC_RTPPROXY 1.0 LOOKUP_SESS %s %s %i %i %s %s %i %d",call_id,ip,port,port_local,from_tag, to_tag, weak,(int)time ( NULL ));

		//send message
		if(cf->ha.is_activated)
			send_data_to_backup(cf,mess_to_send);

		if(cf->ha.stored_sessions_file!=NULL)
			add_session_message(call_id,mess_to_send);
	}
	if(strcmp(mess,"Remove_sess")==0)
	{
		//parameters for this action are:   call_id, from_tag, to_tag
		char* call_id = va_arg(parms, char*);
		char* from_tag = va_arg(parms, char*);
		char* to_tag = va_arg(parms, char*);
		int weak = va_arg(parms, int);

		// synchro_rtp_proxy_message construction
		snprintf(mess_to_send, BUFLEN, "SYNC_RTPPROXY 1.0 REMOVE_SESS %s %s %s %i %d", call_id, from_tag, to_tag, weak, (int)time ( NULL ));

		//send message
		if(cf->ha.is_activated)
			send_data_to_backup(cf,mess_to_send);
		if(cf->ha.stored_sessions_file!=NULL)
			remove_all_session_infos(call_id);
	}
	va_end(parms);

	return 0;
}

int
parse_ha_optarg(struct cfg *cf, char *optarg)
{
    char *pch;

    pch = strtok(optarg, ":/");

    if (pch != NULL) {
        cf->ha.listen_ip = strdup(pch);
        pch = strtok(NULL, ":/");
        if (pch != NULL) {
            cf->ha.listen_port = atoi(pch);
        } else {
            free(cf->ha.listen_ip);
            cf->ha.listen_ip = NULL;
            warnx("\"%s\": ip:port/ip:port not configured", optarg);
            return -1;
        }
        if (!IS_VALID_PORT(cf->ha.listen_port)) {
            warnx("\"%s\" : port is out of range", optarg);
            return -1;
        }
        pch = strtok(NULL, ":/");
        if (pch != NULL) {
            cf->ha.send_to_ip = strdup(pch);
            pch = strtok (NULL, ":/");
            if (pch != NULL) {
                cf->ha.send_to_port = atoi(pch);
            } else {
                free(cf->ha.listen_ip);
                cf->ha.listen_ip = NULL;
                free(cf->ha.send_to_ip);
                cf->ha.send_to_ip = NULL;
                warnx("\"%s\": ip:port/ip:port not configured", optarg);
                return -1;
            }
            if (!IS_VALID_PORT(cf->ha.send_to_port)) {
                warnx("\"%s\" : port is out of range", optarg);
                return -1;
            }
            cf->ha.is_activated = 1;
            cf->start_rtp_idx++;
        } else {
            free(cf->ha.listen_ip);
            cf->ha.listen_ip = NULL;
            warnx("\"%s\": ip:port/ip:port not configured", optarg);
            return -1;
        }
        return 0;
    }
    warnx("%s: ip:port not configured", optarg);
    return -1;
}

int
init_syncfd(struct cfg *cf)
{
    struct sockaddr_storage ifsin;
    int i, syncfd, flags;
    char strport[30];

    snprintf(strport, 10, "%d", cf->ha.listen_port);

    i = (cf->umode == 6) ? AF_INET6 : AF_INET;

    if (setbindhost(sstosa(&ifsin), i, cf->ha.listen_ip, strport) != 0)
        return -1;

    syncfd = socket(i, SOCK_DGRAM, 0);
    if (syncfd == -1) {
        warn("High avaibility :can't create socket");
        return -1;
    }
    if (bind(syncfd, sstosa(&ifsin), SS_LEN(&ifsin)) < 0) {
        warn("High avaibility :can't bind to a socket");
        close(syncfd);
        return -1;
    }
    flags = fcntl(syncfd, F_GETFL);
    fcntl(syncfd, F_SETFL, flags | O_NONBLOCK);

    return syncfd;
}
