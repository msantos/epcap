/* Copyright (c) 2009, Michael Santos <michael.santos@gmail.com>
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

#define SNAPLEN         65535
#define PROMISC         1       /* true */
#define TIMEOUT         500     /* ms */

#define EPCAP_FILTER    "tcp and port 80"

pcap_t *epcap_open(char *dev, int promisc);
int epcap_init(EPCAP_STATE *ep);
void epcap_loop(pcap_t *p);
void epcap_response(const u_char *pkt, struct pcap_pkthdr *hdr);
void epcap_watch();
void usage(EPCAP_STATE *ep);


    int
main(int argc, char *argv[])
{
    EPCAP_STATE *ep = NULL;
    pid_t pid = 0;
    int ch = 0;


    IS_NULL(ep = (EPCAP_STATE *)calloc(1, sizeof(EPCAP_STATE)));

    while ( (ch = getopt(argc, argv, "d:g:hi:Pu:v")) != -1) {
        switch (ch) {
            case 'd':   /* chroot directory */
                IS_NULL(ep->chroot = strdup(optarg));
                break;
            case 'g':
                IS_NULL(ep->group = strdup(optarg));
                break;
            case 'i':
                IS_NULL(ep->dev = strdup(optarg));
                break;
            case 'P':
                ep->promisc = 1;
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

    IS_NULL(ep->p = epcap_open(ep->dev, ep->promisc));
    if (epcap_priv_drop(ep) != 0)
        exit (1);

    switch (pid = fork()) {
        case -1:
            err(EXIT_FAILURE, "fork");
        case 0:
            (void)close(fileno(stdin));
            IS_LTZERO(epcap_init(ep));
            epcap_loop(ep->p);
            break;
        default:
            (void)close(fileno(stdout));
            pcap_close(ep->p);
            epcap_watch();
            (void)kill(pid, SIGTERM);
            break;
    }

    free(ep->filt);
    free(ep);

    exit (0);
}


    void
epcap_watch()
{
    int fd = fileno(stdin);
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    (void)select(fd+1, &rfds, NULL, NULL, NULL);

}


    pcap_t *
epcap_open(char *dev, int promisc)
{
    pcap_t *p = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];


    if (dev == NULL)
        PCAP_ERRBUF(dev = pcap_lookupdev(errbuf));

    PCAP_ERRBUF(p = pcap_open_live(dev, SNAPLEN, promisc, TIMEOUT, errbuf));

    return (p);
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
        return (-1);
    }

    VERBOSE(2, "[%s] Using filter: %s\n", __progname, ep->filt);

    if (pcap_compile(ep->p, &fcode, ep->filt, 1 /* optimize == true */, ipmask) != 0) {
        VERBOSE(1, "pcap_compile: %s", pcap_geterr(ep->p));
        return (-1);
    }

    if (pcap_setfilter(ep->p, &fcode) != 0) {
        VERBOSE(EXIT_FAILURE, "pcap_setfilter: %s", pcap_geterr(ep->p));
        return (-1);
    }

    return (0);

}


    void
epcap_loop(pcap_t *p)
{
    struct pcap_pkthdr hdr;
    const u_char *pkt = NULL;

    for ( ; ; ) {
        pkt = pcap_next(p, &hdr);
        if (pkt == NULL)
            continue;

        epcap_response(pkt, &hdr);
    }
}


    void
epcap_response(const u_char *pkt, struct pcap_pkthdr *hdr)
{
    ei_x_buff msg;
    u_int16_t len = 0;


    /* [ */
    IS_FALSE(ei_x_new_with_version(&msg));
    IS_FALSE(ei_x_encode_list_header(&msg, 2));

    /* {time, {MegaSec, Sec, MicroSec}} */
    IS_FALSE(ei_x_encode_tuple_header(&msg, 2));
    IS_FALSE(ei_x_encode_atom(&msg, "time"));

    IS_FALSE(ei_x_encode_tuple_header(&msg, 3));
    IS_FALSE(ei_x_encode_long(&msg, abs(hdr->ts.tv_sec / 1000000)));
    IS_FALSE(ei_x_encode_long(&msg, hdr->ts.tv_sec % 1000000));
    IS_FALSE(ei_x_encode_long(&msg, hdr->ts.tv_usec));

    /* {packet, Packet} */
    IS_FALSE(ei_x_encode_tuple_header(&msg, 2));
    IS_FALSE(ei_x_encode_atom(&msg, "packet"));
    IS_FALSE(ei_x_encode_binary(&msg, pkt, hdr->caplen));

    /* ] */
    IS_FALSE(ei_x_encode_empty_list(&msg));

    len = htons(msg.index);
    if (write(fileno(stdout), &len, sizeof(len)) != sizeof(len))
        errx(EXIT_FAILURE, "write header failed");

    if (write(fileno(stdout), msg.buff, msg.index) != msg.index)
        errx(EXIT_FAILURE, "write packet failed: %d", msg.index);

    ei_x_free(&msg);
}


    void
usage(EPCAP_STATE *ep)
{
    (void)fprintf(stderr, "%s, %s\n", __progname, EPCAP_VERSION);
    (void)fprintf(stderr,
            "usage: %s <options>\n"
            "              -d <directory>   chroot directory\n"
            "              -g <group>       unprivileged group\n"
            "              -u <user>        unprivileged user\n"
            "              -v               verbose mode\n",
            __progname
            );

    exit (EXIT_FAILURE);
}


