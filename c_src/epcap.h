/* Copyright (c) 2009-2020 Michael Santos <michael.santos@gmail.com>. All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <unistd.h>

#include <pcap.h>

#if defined(__SVR4) && defined(__sun)
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#define u_int64_t uint64_t
#endif

#if !defined(PCAP_NETMASK_UNKNOWN)
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#define EPCAP_VERSION "0.4.0"

#define SNAPLEN 65535

/* On Linux, 0 will block until the next packet is received.
 * On BSD, 0 will block until the snaplen buffer is full.
 */
#define TIMEOUT 500 /* ms, 0 = block indefinitely */

#define EPCAP_USER "nobody"
#define EPCAP_CHROOT "/var/empty"
#define EPCAP_FILTER "" /* match any packet */

#define EPCAP_ENCODE_ERR(x)                                                    \
  do {                                                                         \
    if ((x) != 0)                                                              \
      exit(ENOMEM);                                                            \
  } while (0);

#define VERBOSE(x, ...)                                                        \
  do {                                                                         \
    if (ep->verbose >= x) {                                                    \
      (void)fprintf(stderr, __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

extern char *__progname;

enum {
  EPCAP_OPT_PROMISC = 1 << 0,   /* enable promiscuous mode */
  EPCAP_OPT_RUNASUSER = 1 << 1, /* setuid: drop privs to calling user */
  EPCAP_OPT_RFMON = 1 << 2,     /* enable monitor mode */
  EPCAP_OPT_INJECT = 1 << 3,    /* enable packet injection */
};

typedef struct {
  pcap_t *p;                     /* pcap handle */
  int fdctl[2];                  /* control descriptor for supervisor process */
  int datalink;                  /* dlt */
  int opt;                       /* options */
  int verbose;                   /* debug messages */
  int snaplen;                   /* packet capture length */
  int timeout;                   /* capture timeout */
  int time_unit;                 /* microseconds, timestamp */
  int bufsz;                     /* pcap buf size */
  int direction;                 /* capture direction */
  char *filt;                    /* packet filter */
  char *dev;                     /* device to snoop */
  char *user;                    /* run as unprivileged user */
  char *group;                   /* run as unprivilted group */
  char *chroot;                  /* chroot directory */
  char *file;                    /* filename in case we read from pcap file */
  char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error */
} EPCAP_STATE;

int epcap_priv_drop(EPCAP_STATE *);
int epcap_priv_runasuser(EPCAP_STATE *ep);

int restrict_process_capture();
int restrict_process_supervisor();

#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval, long long maxval,
                   const char **errstrp);
#endif

#ifndef HAVE_SETPROCTITLE
void spt_init(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);
#endif
