/* Copyright (c) 2009-2013, Michael Santos <michael.santos@gmail.com>
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

int epcap_open(EPCAP_STATE *ep);
int epcap_init(EPCAP_STATE *ep);
void epcap_loop(EPCAP_STATE *ep);
void epcap_ctrl(const char *ctrl_evt);
void epcap_response(struct pcap_pkthdr *hdr, const u_char *pkt, unsigned int datalink);
void epcap_send_free(ei_x_buff *msg);
void epcap_watch();
void gotsig(int sig);
void usage(EPCAP_STATE *ep);

int child_exited = 0;

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

    while ( (ch = getopt(argc, argv, "d:f:g:hi:MPs:t:u:v")) != -1) {
        switch (ch) {
            case 'd':   /* chroot directory */
                IS_NULL(ep->chroot = strdup(optarg));
                break;
            case 'f':
                IS_NULL(ep->file = strdup(optarg));
                ep->runasuser = 1;
                break;
            case 'g':
                IS_NULL(ep->group = strdup(optarg));
                break;
            case 'i':
                IS_NULL(ep->dev = strdup(optarg));
                break;
            case 'M':
                ep->rfmon = 1;
                break;
            case 'P':
                ep->promisc = 1;
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
            case 'h':
            default:
                usage(ep);
        }
    }

    argc -= optind;
    argv += optind;

    IS_NULL(ep->filt = strdup( (argc == 1) ? argv[0] : EPCAP_FILTER));

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

            pcap_close(ep->p);

            if (epcap_priv_rlimits(0) < 0)
                goto CLEANUP;

            epcap_watch();

CLEANUP:
            (void)kill(pid, SIGTERM);
            break;
    }

    exit (0);
}


    void
epcap_watch()
{
    int fd = STDIN_FILENO;
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if (child_exited == 0)
        (void)select(fd+1, &rfds, NULL, NULL, NULL);
}


    int
epcap_open(EPCAP_STATE *ep)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (ep->file) {
        PCAP_ERRBUF(ep->p = pcap_open_offline(ep->file, errbuf));
    } else {
        if (ep->dev == NULL)
            PCAP_ERRBUF(ep->dev = pcap_lookupdev(errbuf));

        PCAP_ERRBUF(ep->p = pcap_open_live(ep->dev, ep->snaplen, ep->promisc, ep->timeout, errbuf));

        /* monitor mode */
#ifdef PCAP_ERROR_RFMON_NOTSUP
        if (pcap_can_set_rfmon(ep->p) == 1)
            (void)pcap_set_rfmon(ep->p, ep->rfmon);
#endif
    }

    return (0);
}


    int
epcap_init(EPCAP_STATE *ep)
{
    struct bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];

    u_int32_t ipaddr = 0;
    u_int32_t ipmask = 0;


    if (pcap_lookupnet(ep->dev, &ipaddr, &ipmask, errbuf) == -1) {
        VERBOSE(1, "%s", errbuf);
        ipmask=PCAP_NETMASK_UNKNOWN;
    }

    VERBOSE(2, "[%s] Using filter: %s\n", __progname, ep->filt);

    if (pcap_compile(ep->p, &fcode, ep->filt, 1 /* optimize == true */, ipmask) != 0) {
        VERBOSE(1, "pcap_compile: %s", pcap_geterr(ep->p));
        return (-1);
    }

    if (pcap_setfilter(ep->p, &fcode) != 0) {
        VERBOSE(1, "pcap_setfilter: %s", pcap_geterr(ep->p));
        return (-1);
    }

    return (0);

}


    void
epcap_loop(EPCAP_STATE *ep)
{
    pcap_t *p = ep->p;
    struct pcap_pkthdr *hdr = NULL;
    const u_char *pkt = NULL;

    int read_packet = 1;
    int datalink = pcap_datalink(p);

    while (read_packet) {
        switch (pcap_next_ex(p, &hdr, &pkt)) {
            case 0:     /* timeout */
                VERBOSE(1, "timeout reading packet");
                break;
            case 1:     /* got packet */
                epcap_response(hdr, pkt, datalink);
                break;
            case -2:    /* eof */
                VERBOSE(1, "end of file");
                epcap_ctrl("eof");
                read_packet = 0;
                break;
            case -1:    /* error reading packet */
                VERBOSE(1, "%s", pcap_geterr(p));
                /* fall through */
            default:
                read_packet = 0;
        }
    }
}

void epcap_ctrl(const char *ctrl_evt)
{
    ei_x_buff msg;

    IS_FALSE(ei_x_new_with_version(&msg));
    IS_FALSE(ei_x_encode_tuple_header(&msg, 2));
    IS_FALSE(ei_x_encode_atom(&msg, "epcap"));
    IS_FALSE(ei_x_encode_atom(&msg, ctrl_evt));

    epcap_send_free(&msg);
}

    void
epcap_response(struct pcap_pkthdr *hdr, const u_char *pkt, unsigned int datalink)
{
    ei_x_buff msg;


    IS_FALSE(ei_x_new_with_version(&msg));

    /* {packet, DatalinkType, Time, ActualLength, Packet} */
    IS_FALSE(ei_x_encode_tuple_header(&msg, 5));
    IS_FALSE(ei_x_encode_atom(&msg, "packet"));

    /* DataLinkType */
    IS_FALSE(ei_x_encode_long(&msg, datalink));

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

void epcap_send_free(ei_x_buff *msg)
{
    u_int16_t len = 0;

    len = htons(msg->index);
    if (write(STDOUT_FILENO, &len, sizeof(len)) != sizeof(len))
        errx(EXIT_FAILURE, "write header failed");

    if (write(STDOUT_FILENO, msg->buff, msg->index) != msg->index)
        errx(EXIT_FAILURE, "write packet failed: %d", msg->index);

    ei_x_free(msg);
}

    void
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

    void
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
            "              -s <length>      packet capture length\n"
            "              -t <millisecond> capture timeout\n"
            "              -v               verbose mode\n",
            __progname
            );

    exit (EXIT_FAILURE);
}
