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
#include <ei.h>

#include "epcap.h"

static int epcap_open(EPCAP_STATE *);
static int epcap_init(EPCAP_STATE *);
static void epcap_loop(EPCAP_STATE *);
static void epcap_ctrl(const char *);
void epcap_response(u_char *, const struct pcap_pkthdr *, const u_char *);
static void epcap_send_free(ei_x_buff *);
static void epcap_send(EPCAP_STATE *);
static void gotsig(int);
static ssize_t read_exact(int, void *, ssize_t);
static void usage(EPCAP_STATE *);

int child_exited = 0;

extern char **environ;

/* On some platforms (Linux), poll() (used by pcap)
 * will return EINVAL if RLIMIT_NOFILES < numfd */
#ifndef EPCAP_RLIMIT_NOFILES
#define EPCAP_RLIMIT_NOFILES 0
#warning "Using default value of EPCAP_RLIMIT_NOFILES=0"
#endif


    int
main(int argc, char *argv[])
{
    EPCAP_STATE *ep = NULL;
    pid_t pid = 0;
    int ch = 0;
    int fd = 0;


    IS_NULL(ep = calloc(1, sizeof(EPCAP_STATE)));

    ep->snaplen = SNAPLEN;
    ep->timeout = TIMEOUT;

    while ( (ch = getopt(argc, argv, "b:d:e:f:g:hi:MPs:t:u:vX")) != -1) {
        switch (ch) {
            case 'b':
                ep->bufsz = atoi(optarg);
                break;
            case 'd':   /* chroot directory */
                IS_NULL(ep->chroot = strdup(optarg));
                break;
            case 'e': {
                char *name = NULL;
                char *value = NULL;
                IS_NULL(name = strdup(optarg));
                IS_NULL(value = strchr(name, '='));
                *value = '\0'; value++;
                IS_FALSE(setenv(name, value, 0));
                free(name);
                }
                break;
            case 'f':
                IS_NULL(ep->file = strdup(optarg));
                ep->opt |= EPCAP_OPT_RUNASUSER;
                break;
            case 'g':
                IS_NULL(ep->group = strdup(optarg));
                break;
            case 'i':
                IS_NULL(ep->dev = strdup(optarg));
                break;
            case 'M':
                ep->opt |= EPCAP_OPT_RFMON;
                break;
            case 'P':
                ep->opt |= EPCAP_OPT_PROMISC;
                break;
            case 's':
                ep->snaplen = (size_t)atoi(optarg);
                break;
            case 't':
                ep->timeout = (u_int32_t)atoi(optarg);
                break;
            case 'u':
                IS_NULL(ep->user = strdup(optarg));
                break;
            case 'v':
                ep->verbose++;
                break;
            case 'X':
                ep->opt |= EPCAP_OPT_INJECT;
                break;
            case 'h':
            default:
                usage(ep);
        }
    }

    argc -= optind;
    argv += optind;

    IS_NULL(ep->filt = strdup( (argc == 1) ? argv[0] : EPCAP_FILTER));

    if (ep->verbose > 0) {
        for ( ; *environ; environ++)
            VERBOSE(2, "env:%s\n", *environ);
    }

    IS_LTZERO(fd = open("/dev/null", O_RDWR));

    epcap_priv_issetuid(ep);
    IS_LTZERO(epcap_open(ep));
    if (epcap_priv_drop(ep) < 0)
        exit (1);

    signal(SIGCHLD, gotsig);

    switch (pid = fork()) {
        case -1:
            err(EXIT_FAILURE, "fork");
        case 0:
            IS_LTZERO(dup2(fd, STDIN_FILENO));
            IS_LTZERO(close(fd));
            IS_LTZERO(epcap_init(ep));
            IS_LTZERO(epcap_priv_rlimits(EPCAP_RLIMIT_NOFILES));
            epcap_loop(ep);
            break;
        default:
            if ( (dup2(fd, STDOUT_FILENO) < 0) ||
                (close(fd) < 0))
                goto CLEANUP;

            if (!(ep->opt & EPCAP_OPT_INJECT))
                pcap_close(ep->p);

            if (epcap_priv_rlimits(0) < 0)
                goto CLEANUP;

            epcap_send(ep);

CLEANUP:
            (void)kill(pid, SIGTERM);
            break;
    }

    exit (0);
}


    static void
epcap_send(EPCAP_STATE *ep)
{
    const int fd = STDIN_FILENO;
    ssize_t n = 0;
    unsigned char buf[SNAPLEN] = {0};
    u_int16_t len = 0;

    for ( ; ; ) {
        if (child_exited)
            return;

        n = read_exact(fd, buf, sizeof(len));

        if (n != sizeof(len)) {
            VERBOSE(1, "epcap_send: header len != %lu: %ld",
                    (unsigned long)sizeof(len), (long)n);
            return;
        }

        len = (buf[0] << 8) | buf[1];

        VERBOSE(2, "epcap_send: packet len = %u", len);

        if (len >= sizeof(buf))
            return;

        n = read_exact(fd, buf, len);

        if (n != len) {
            VERBOSE(1, "epcap_send: len = %u, read = %ld",
                    len, (long)n);
            return;
        }

        if (ep->opt & EPCAP_OPT_INJECT) {
            n = pcap_inject(ep->p, buf, len);

            if (n < 0) {
                VERBOSE(0, "epcap_send: %s", pcap_geterr(ep->p));
                return;
            }
            else if (n != len) {
                VERBOSE(1, "epcap_send: len = %u, sent = %ld",
                        len, (long)n);
            }
        }
        else {
            VERBOSE(2, "epcap_send: ignoring: len = %u", len);
        }
    }
}


    static int
epcap_open(EPCAP_STATE *ep)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (ep->file) {
        PCAP_ERRBUF(ep->p = pcap_open_offline(ep->file, errbuf));
    } else {
        if (ep->dev == NULL)
            PCAP_ERRBUF(ep->dev = pcap_lookupdev(errbuf));

#ifdef HAVE_PCAP_CREATE
        PCAP_ERRBUF(ep->p = pcap_create(ep->dev, errbuf));
        (void)pcap_set_snaplen(ep->p, ep->snaplen);
        (void)pcap_set_promisc(ep->p, ep->opt & EPCAP_OPT_PROMISC);
        (void)pcap_set_timeout(ep->p, ep->timeout);
        if (ep->bufsz > 0)
            (void)pcap_set_buffer_size(ep->p, ep->bufsz);
        switch (pcap_activate(ep->p)) {
            case 0:
                break;
            case PCAP_WARNING:
            case PCAP_ERROR:
            case PCAP_WARNING_PROMISC_NOTSUP:
            case PCAP_ERROR_NO_SUCH_DEVICE:
            case PCAP_ERROR_PERM_DENIED:
                pcap_perror(ep->p, "pcap_activate: ");
                exit(EXIT_FAILURE);
            default:
                exit(EXIT_FAILURE);
        }
#else
        PCAP_ERRBUF(ep->p = pcap_open_live(ep->dev, ep->snaplen,
                    ep->opt & EPCAP_OPT_PROMISC, ep->timeout, errbuf));
#endif

        /* monitor mode */
#ifdef PCAP_ERROR_RFMON_NOTSUP
        if (pcap_can_set_rfmon(ep->p) == 1)
            (void)pcap_set_rfmon(ep->p, ep->opt & EPCAP_OPT_RFMON);
#endif
    }

    ep->datalink = pcap_datalink(ep->p);

    return 0;
}


    static int
epcap_init(EPCAP_STATE *ep)
{
    struct bpf_program fcode = {0};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    u_int32_t ipaddr = 0;
    u_int32_t ipmask = 0;


    if (pcap_lookupnet(ep->dev, &ipaddr, &ipmask, errbuf) == -1) {
        VERBOSE(1, "%s", errbuf);
        ipmask = PCAP_NETMASK_UNKNOWN;
    }

    VERBOSE(2, "[%s] Using filter: %s\n", __progname, ep->filt);

    if (pcap_compile(ep->p, &fcode, ep->filt, 1 /* optimize == true */, ipmask) != 0) {
        VERBOSE(1, "pcap_compile: %s", pcap_geterr(ep->p));
        return -1;
    }

    if (pcap_setfilter(ep->p, &fcode) != 0) {
        VERBOSE(1, "pcap_setfilter: %s", pcap_geterr(ep->p));
        return -1;
    }

    return 0;

}


    static void
epcap_loop(EPCAP_STATE *ep)
{
    int rv = -1;

    rv = pcap_loop(ep->p, -1, epcap_response, (u_char *)ep);

    switch (rv) {
        case -2:
            break;
        case -1:    /* error reading packet */
            VERBOSE(1, "%s", pcap_geterr(ep->p));
            break;
        default:
            if (ep->file)
                epcap_ctrl("eof");
            break;
    }
}

    static void
epcap_ctrl(const char *ctrl_evt)
{
    ei_x_buff msg;

    IS_FALSE(ei_x_new_with_version(&msg));
    IS_FALSE(ei_x_encode_tuple_header(&msg, 2));
    IS_FALSE(ei_x_encode_atom(&msg, "epcap"));
    IS_FALSE(ei_x_encode_atom(&msg, ctrl_evt));

    epcap_send_free(&msg);
}

    void
epcap_response(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    EPCAP_STATE *ep = (EPCAP_STATE *)user;
    ei_x_buff msg = {0};

    IS_FALSE(ei_x_new_with_version(&msg));

    /* {packet, DatalinkType, Time, ActualLength, Packet} */
    IS_FALSE(ei_x_encode_tuple_header(&msg, 5));
    IS_FALSE(ei_x_encode_atom(&msg, "packet"));

    /* DataLinkType */
    IS_FALSE(ei_x_encode_long(&msg, ep->datalink));

    /* {MegaSec, Sec, MicroSec} */
    IS_FALSE(ei_x_encode_tuple_header(&msg, 3));
    IS_FALSE(ei_x_encode_long(&msg, abs(hdr->ts.tv_sec / 1000000)));
    IS_FALSE(ei_x_encode_long(&msg, hdr->ts.tv_sec % 1000000));
    IS_FALSE(ei_x_encode_long(&msg, hdr->ts.tv_usec));

    /* ActualLength} */
    IS_FALSE(ei_x_encode_long(&msg, hdr->len));

    /* Packet */
    IS_FALSE(ei_x_encode_binary(&msg, pkt, hdr->caplen));

    /* } */

    epcap_send_free(&msg);
}

    static void
epcap_send_free(ei_x_buff *msg)
{
    u_int16_t len = 0;
    struct iovec iov[2];

    len = htons(msg->index);

    iov[0].iov_base = (void *)&len;
    iov[0].iov_len = sizeof(len);
    iov[1].iov_base = msg->buff;
    iov[1].iov_len = msg->index;

    if (writev(STDOUT_FILENO, iov, sizeof(iov)/sizeof(iov[0])) !=
            sizeof(len) + msg->index)
        errx(EXIT_FAILURE, "write packet failed: %d", msg->index);

    ei_x_free(msg);
}

    static ssize_t
read_exact(int fd, void *buf, ssize_t len)
{
    ssize_t i = 0;
    ssize_t got = 0;

    do {
        if ((i = read(fd, buf + got, len - got)) <= 0)
            return i;
        got += i;
    } while (got < len);

    return len;
}

    static void
gotsig(int sig)
{
    switch (sig) {
        case SIGCHLD:
            child_exited = 1;
            break;
        default:
            break;
    }
}

    static void
usage(EPCAP_STATE *ep)
{
    (void)fprintf(stderr, "%s, %s\n", __progname, EPCAP_VERSION);
    (void)fprintf(stderr,
            "usage: %s <options>\n"
            "              -d <directory>   chroot directory\n"
            "              -i <interface>   interface to snoop\n"
            "              -f <filename>    read from file instead of live capture\n"
#ifdef PCAP_ERROR_RFMON_NOTSUP
            "              -M               wireless monitor (rfmon) mode\n"
#endif
            "              -P               promiscuous mode\n"
            "              -g <group>       unprivileged group\n"
            "              -u <user>        unprivileged user\n"
#ifdef HAVE_PCAP_CREATE
            "              -b <size>        PCAP buf size\n"
#endif
            "              -s <length>      packet capture length\n"
            "              -t <millisecond> capture timeout\n"
            "              -e <key>=<val>   set an environment variable\n"
            "              -v               verbose mode\n"
            "              -X               enable sending packets\n",
            __progname
            );

    exit (EXIT_FAILURE);
}
