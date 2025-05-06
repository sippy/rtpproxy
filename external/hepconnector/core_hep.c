/*
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
 *
 *  Copyright (c) 2010-2016 <Alexandr Dubovikov>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the <SIPCAPTURE>. The name of the SIPCAPTURE may not be used to
 * endorse or promote products derived from this software without specific
 * prior written permission.

 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * Copyright (c) 2018 Maksym Sobolyev <sobomax@gmail.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
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
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

//#define USE_ZLIB

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#if defined(RTPP_DEBUG)
#include <assert.h>
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#include "hep_api.h"
#include "core_hep.h"
#include "hepconnector.h"

#if defined(RTPP_MODULE)
#include "rtpp_module.h"
#endif

pthread_mutex_t lock;

#ifdef USE_SSL
static int initSSL(struct hep_ctx *ctp);
#endif

static int send_data(struct hep_ctx *, void *buf, unsigned int len);

#ifdef USE_ZLIB
static void *
compress_data(void *data, unsigned int *len)
{
    void *zipData;
    unsigned long dlen;
    int status;

    dlen = compressBound(*len);

    zipData  = malloc(dlen); /* give a little bit memmory */
    if (zipData == NULL)
        return (NULL);

    /* do compress */
    status = compress(zipData, &dlen, data, *len);
    if (status != Z_OK) {
        free(zipData);
        return (NULL);
    }
    *len = dlen;

    return (zipData);
}
#endif /* USE_ZLIB */

void
hep_gen_dtor(struct hep_ctx *ctp)
{

    if (ctp->hep_hdr != NULL) {
        free(ctp->hep_hdr);
        ctp->hep_hdr = NULL;
    }
}

int hep_gen_fill(struct hep_ctx *ctp, rc_info_t *rcinfo)
{
    struct hep_generic *hg;

    if (ctp->hep_hdr == NULL) {
        hg = malloc(sizeof(struct hep_generic));
        if (hg == NULL) {
            return (-1);
        }
        ctp->hep_hdr = hg;
        /* total */
        memset(hg, 0, sizeof(struct hep_generic));
    } else {
        hg = ctp->hep_hdr;
        memset(hg, 0, ctp->hdr_len);
    }
    ctp->hdr_len = sizeof(struct hep_generic);

    /* header set */
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    /* IP proto */
    hg->ip_family.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->ip_family.chunk.type_id   = htons(HEP_TID_PF);
    hg->ip_family.data = rcinfo->ip_family;
    hg->ip_family.chunk.length = htons(sizeof(hg->ip_family));

    /* Proto ID */
    hg->ip_proto.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->ip_proto.chunk.type_id   = htons(HEP_TID_PID);
    hg->ip_proto.data = rcinfo->ip_proto;
    hg->ip_proto.chunk.length = htons(sizeof(hg->ip_proto));

    /* SRC PORT */
    hg->src_port.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->src_port.chunk.type_id   = htons(HEP_TID_SP);
    hg->src_port.data = htons(rcinfo->src_port);
    hg->src_port.chunk.length = htons(sizeof(hg->src_port));

    /* DST PORT */
    hg->dst_port.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->dst_port.chunk.type_id   = htons(HEP_TID_DP);
    hg->dst_port.data = htons(rcinfo->dst_port);
    hg->dst_port.chunk.length = htons(sizeof(hg->dst_port));

    /* TIMESTAMP SEC */
    hg->time_sec.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->time_sec.chunk.type_id   = htons(HEP_TID_TS_S);
    hg->time_sec.data = htonl(rcinfo->time_sec);
    hg->time_sec.chunk.length = htons(sizeof(hg->time_sec));

    /* TIMESTAMP USEC */
    hg->time_usec.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->time_usec.chunk.type_id   = htons(HEP_TID_TS_MS);
    hg->time_usec.data = htonl(rcinfo->time_usec);
    hg->time_usec.chunk.length = htons(sizeof(hg->time_usec));

    /* Protocol TYPE */
    hg->proto_t.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->proto_t.chunk.type_id   = htons(HEP_TID_PT);
    hg->proto_t.data = rcinfo->proto_type;
    hg->proto_t.chunk.length = htons(sizeof(hg->proto_t));

    /* Capture ID */
    hg->capt_id.chunk.vendor_id = htons(HEP_VID_GEN);
    hg->capt_id.chunk.type_id   = htons(HEP_TID_CAID);
    hg->capt_id.data = htons(ctp->capt_id);
    hg->capt_id.chunk.length = htons(sizeof(hg->capt_id));

    return (0);
}

int
hep_gen_append(struct hep_ctx *ctp, uint16_t vendor_id,
  uint16_t type_id, const void *data, uint16_t dlen)
{
    struct hep_generic *hg;
    hep_chunk_t *chunk;
    uint16_t tlen;

    tlen = sizeof(hep_chunk_t) + dlen;
    hg = realloc(ctp->hep_hdr, ctp->hdr_len + tlen);
    if (hg == NULL)
        return (-1);
    chunk = (hep_chunk_t *)((char *)hg + ctp->hdr_len);
    chunk->vendor_id = htons(vendor_id);
    chunk->type_id = htons(type_id);
    chunk->length = htons(tlen);
    memcpy(&chunk->data, data, dlen);
    ctp->hdr_len += tlen;
    if (hg != ctp->hep_hdr)
        ctp->hep_hdr = hg;

    return (0);
}

#define HGA_O_RET(ctx, vid, tid, dp, dl, rv) \
    if (hep_gen_append((ctx), (vid), (tid), (dp), (dl)) != 0) { \
        return (rv); \
    }

int
send_hep(struct hep_ctx *ctp, rc_info_t *rcinfo, void *data, unsigned int len)
{
    int sendzip;
#ifdef USE_ZLIB
    void *dtp;
    int freezip;

    freezip = 0;
#endif

#if defined(RTPP_DEBUG)
    assert(ctp->hep_version == 3);
#endif

    sendzip = 0;
    if (ctp->pl_compress) {
#ifdef USE_ZLIB
        dtp = compress_data(data, &len);
        if (dtp != NULL) {
            sendzip =  1;
            if (dtp != data)
                 freezip = 1;
            data = dtp;
        }
#else
#if defined(RTPP_DEBUG)
        abort();
#endif
#endif /* USE_ZLIB */
    }
    /* IPv4 */
    if(rcinfo->ip_family == AF_INET) {
        /* SRC IP */
        HGA_O_RET(ctp, HEP_VID_GEN, HEP_TID_SA4, rcinfo->src.p4, sizeof(*rcinfo->src.p4), -1);

        /* DST IP */
        HGA_O_RET(ctp, HEP_VID_GEN, HEP_TID_DA4, rcinfo->dst.p4, sizeof(*rcinfo->dst.p4), -1);
    }
#ifdef USE_IPV6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        HGA_O_RET(ctp, HEP_VID_GEN, HEP_TID_SA6, rcinfo->src.p6, sizeof(*rcinfo->src.p6), -1);
        
        /* DST IPv6 */
        HGA_O_RET(ctp, HEP_VID_GEN, HEP_TID_DA6, rcinfo->dst.p6, sizeof(*rcinfo->dst.p6), -1);
    }
#endif

    /* Payload */
    HGA_O_RET(ctp, HEP_VID_GEN, sendzip ? HEP_TID_PL_GZ : HEP_TID_PL_RAW, data, len, -1);

    /* auth key */
    if(ctp->capt_password != NULL) {
          /* Auth key */
          HGA_O_RET(ctp, HEP_VID_GEN, HEP_TID_AKEY, ctp->capt_password, strlen(ctp->capt_password), -1);
    }

    //fprintf(stderr, "LEN: [%d] vs [%d] = IPLEN:[%d] LEN:[%d] CH:[%d]\n", ctp->hep_hdr->header.length, ntohs(ctp->hep_hdr->header.length), iplen, len, sizeof(struct hep_chunk));

    /* make sleep after 100 errors */
     if(ctp->errorsCount > 50) {
        fprintf(stderr, "HEP server is down... retrying after sleep...\n");
	if(!ctp->usessl) {
	     sleep(2);
             if(init_hepsocket_blocking(ctp)) { 
				ctp->initfails++; 	
	     	     }
	     	     ctp->errorsCount = 0;
        }
#ifdef USE_SSL
        else {
		sleep(2);
		 if(initSSL(ctp)) {
	 	  	ctp->initfails++;
	    		}
	    		ctp->errorsCount = 0;
       	 }
#endif /* USE SSL */

     }

    /* Fix total lengh */
    ctp->hep_hdr->header.length = htons(ctp->hdr_len);
    /* send this packet out of our socket */
    if(send_data(ctp, ctp->hep_hdr, ctp->hdr_len)) {
        ctp->errorsCount++;    
    }

#ifdef USE_ZLIB
    if (freezip)
        free(data);
#endif
    return (0);
}

static int send_data (struct hep_ctx *ctp, void *buf, unsigned int len) {

	/* send this packet out of our socket */
	//int r = 0;
	void * p = buf;
	//int sentbytes = 0;

	if(!ctp->usessl) {
	        	if(send(ctp->sock, p, len, 0) == -1) {
	    	        	fprintf(stderr, "send error\n");
            			return -1;
	        	}
          	ctp->sendPacketsCount++;
	  /* while (sentbytes < len){
	        	if( (r = send(ctp->sock, p, len - sentbytes, MSG_NOSIGNAL )) == -1) {
	    	        	fprintf(stderr, "send error\n");
        			return -1;
	        	}
	        	if (r != len - sentbytes)
			    fprintf(stderr, "send:multiple calls: %d\n", r);

        		sentbytes += r;
	        	p += r;
        	}
        	ctp->sendPacketsCount++;
	  */
        }
#ifdef USE_SSL
        else {
            if(SSL_write(ctp->ssl, buf, len) < 0) {            
		fprintf(stderr, "capture: couldn't re-init ssl socket\r\n");
                return -1;                
            }
	    ctp->sendPacketsCount++;
        }
#endif        
	/* RESET ERRORS COUNTER */
	return 0;
}

int init_hepsocket (struct hep_ctx *ctp) {

    long arg;
    int res, s;

    if(ctp->sock) {
        close(ctp->sock);
        ctp->sock = 0;
    }

    if ((s = getaddrinfo(ctp->capt_host, ctp->capt_port, ctp->hints, &ctp->ai)) != 0) {
        fprintf(stderr, "capture: getaddrinfo: %s\n", gai_strerror(s));
        goto e0;
    }

    if((ctp->sock = socket(ctp->ai->ai_family, ctp->ai->ai_socktype, ctp->ai->ai_protocol)) < 0) {
        fprintf(stderr, "Sender socket creation failed: %s\n", strerror(errno));
        goto e0;
    }

    res = connect(ctp->sock, ctp->ai->ai_addr, (socklen_t)(ctp->ai->ai_addrlen));
    if(res < 0) {
        goto e1;
    }

    // Set non-blocking
    if((arg = fcntl(ctp->sock, F_GETFL, NULL)) < 0) {
        fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
        goto e1;
    }
    arg |= O_NONBLOCK;
    if( fcntl(ctp->sock, F_SETFL, arg) < 0) {
        fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
        goto e1;
    }

    return (0);
e1:
    close(ctp->sock);
    ctp->sock = 0;
e0:
    return (-1);
}

int init_hepsocket_blocking (struct hep_ctx *ctp) {

    int s;
    struct timeval tv;
    fd_set myset;

    if(ctp->sock) close(ctp->sock);

    if ((s = getaddrinfo(ctp->capt_host, ctp->capt_port, ctp->hints, &ctp->ai)) != 0) {            
            fprintf(stderr, "capture: getaddrinfo: %s\n", gai_strerror(s));
            return 2;
    }

    if((ctp->sock = socket(ctp->ai->ai_family, ctp->ai->ai_socktype, ctp->ai->ai_protocol)) < 0) {
             fprintf(stderr, "Sender socket creation failed: %s\n", strerror(errno));
             return 1;
    }

     if (connect(ctp->sock, ctp->ai->ai_addr, (socklen_t)(ctp->ai->ai_addrlen)) == -1) {
         select(ctp->sock + 1 , NULL, &myset, NULL, &tv);
         if (errno != EINPROGRESS) {
             fprintf(stderr, "Sender socket creation failed: %s\n", strerror(errno));
             return 1;    
          }
    }


    return 0;
}



#ifdef USE_SSL
SSL_CTX* initCTX(void) {
        const SSL_METHOD *method;
        SSL_CTX *ctx;

        OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
        SSL_load_error_strings();   /* Bring in and register error messages */

        /* we use SSLv3 */
        method = SSLv3_client_method();  /* Create new client-method instance */

        ctx = SSL_CTX_new(method);   /* Create new context */
        if ( ctx == NULL ) {
                ERR_print_errors_fp(stderr);
                abort();
        }
        return ctx;
}
 
 
void showCerts(SSL* ssl) {
        
        X509 *cert;
        char *line;

        cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
        if ( cert != NULL ) {
                fprintf(stderr, "Server certificates:\n");
                line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                fprintf(stderr, "Subject: %s\n", line);
                free(line);       /* free the malloc'ed string */
                line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                fprintf(stderr, "Issuer: %s\n", line);
                free(line);       /* free the malloc'ed string */
                X509_free(cert);     /* free the malloc'ed certificate copy */
        }
        else
                fprintf(stderr, "No certificates.\n");
}

static int initSSL(struct hep_ctx *ctp) {

        long ctx_options;

        /* if(ctp->ssl) SSL_free(ctp->ssl);
        if(ctp->ctx) SSL_CTX_free(ctp->ctx);
        */

        if(init_hepsocket_blocking(ctp)) {
                fprintf(stderr, "capture: couldn't init hep socket\r\n");
                return 1;
        }


        ctp->ctx = initCTX();

        /* workaround bug openssl */
        ctx_options = SSL_OP_ALL;   
        ctx_options |= SSL_OP_NO_SSLv2;
        SSL_CTX_set_options(ctp->ctx, ctx_options);
                
        /*extra*/
        SSL_CTX_ctrl(ctp->ctx, BIO_C_SET_NBIO, 1, NULL);

        /* create new SSL connection state */
        ctp->ssl = SSL_new(ctp->ctx);

        SSL_set_connect_state(ctp->ssl);

        /* attach socket */
        SSL_set_fd(ctp->ssl, ctp->sock);    /* attach the socket descriptor */
                
        /* perform the connection */
        if ( SSL_connect(ctp->ssl) == -1 )  {
              ERR_print_errors_fp(stderr);
              return 1;
        }                 
                          
        showCerts(ctp->ssl);   

        return 0;
}
#endif /* use SSL */
