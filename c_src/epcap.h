/*
 * Copyright (c) 2009, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>

#include <sys/select.h>

#include <pcap.h>

#define EPCAP_VERSION   "0.03"

#define MAXBUFLEN       4096    /* Largest message accepted on stdin */
#define PKTLENHDR       2       /* 2 byte packet length header */

#define SNAPLEN         65535
#define PROMISC         1       /* true */
#define TIMEOUT         0       /* ms, 0 = block indefinitely */

#define EPCAP_FILTER    "tcp and port 80"

#define PCAP_ERRBUF(x) do { \
    if ((x) == NULL) \
    errx(EXIT_FAILURE, "%s: %s", #x, errbuf); \
} while (0);

#define IS_NULL(x) do { \
    if ((x) == NULL) \
    errx(EXIT_FAILURE, "%s", #x); \
} while (0);

#define IS_FALSE(x) do { \
    if ((x) != 0) \
    errx(EXIT_FAILURE, "%s", #x); \
} while (0);

#define IS_LTZERO(x) do { \
    if ((x) < 0) \
    errx(EXIT_FAILURE, "%s", #x); \
} while (0);

#define VERBOSE(x, ...) do { \
    if (ep->verbose >= x) { \
        (void)fprintf (stderr, __VA_ARGS__); \
    } \
} while (0)


extern char *__progname;


typedef struct {
    pcap_t *p;          /* pcap handle */
    int promisc;        /* promiscuous mode */
    int verbose;        /* debugging messages */
    int runasuser;      /* if setuid, run as the calling user */
    size_t snaplen;     /* packet capture length */
    u_int32_t timeout;  /* capture timeout */
    char *filt;         /* packet filter */
    char *dev;          /* device to snoop */
    char *user;         /* run as unprivileged user */
    char *group;        /* run as unprivilted group */
    char *chroot;       /* chroot directory */
    char *file;         /* filename in case we read from pcap file */
} EPCAP_STATE;


int epcap_priv_drop(EPCAP_STATE *ep);
void epcap_priv_issetuid(EPCAP_STATE *ep);

