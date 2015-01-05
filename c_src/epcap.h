/* Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
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
#include <sys/uio.h>
#include <err.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <netinet/in.h>

#include <pcap.h>

#if defined(__SVR4) && defined(__sun)
#define u_int8_t            uint8_t
#define u_int16_t           uint16_t
#define u_int32_t           uint32_t
#define u_int64_t           uint64_t
#endif

#if !defined(PCAP_NETMASK_UNKNOWN)
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#define EPCAP_VERSION   "0.4.0"

#define SNAPLEN         65535

/* On Linux, 0 will block until the next packet is received.
 * On BSD, 0 will block until the snaplen buffer is full.
 */
#define TIMEOUT         500     /* ms, 0 = block indefinitely */

#define EPCAP_USER      "nobody"
#define EPCAP_CHROOT    "/var/empty"
#define EPCAP_FILTER    ""      /* match any packet */

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

enum {
    EPCAP_OPT_PROMISC = 1 << 0,     /* enable promiscuous mode */
    EPCAP_OPT_RUNASUSER = 1 << 1,   /* setuid: drop privs to calling user */
    EPCAP_OPT_RFMON = 1 << 2,       /* enable monitor mode */
    EPCAP_OPT_INJECT = 1 << 3,      /* enable packet injection */
};

typedef struct {
    pcap_t *p;          /* pcap handle */
    int datalink;       /* dlt */
    int opt;            /* options */
    int verbose;        /* debug messages */
    size_t snaplen;     /* packet capture length */
    u_int32_t timeout;  /* capture timeout */
    int bufsz;          /* pcap buf size */
    char *filt;         /* packet filter */
    char *dev;          /* device to snoop */
    char *user;         /* run as unprivileged user */
    char *group;        /* run as unprivilted group */
    char *chroot;       /* chroot directory */
    char *file;         /* filename in case we read from pcap file */
} EPCAP_STATE;


int epcap_priv_drop(EPCAP_STATE *);
void epcap_priv_issetuid(EPCAP_STATE *);
int epcap_priv_rlimits(int);
