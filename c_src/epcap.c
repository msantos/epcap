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
#include <ei.h>
#include <stdint.h>

#ifdef RESTRICT_PROCESS_capsicum
#include <sys/procdesc.h>
#endif

#include "epcap.h"

#define PIPE_READ 0
#define PIPE_WRITE 1

#ifdef HAVE_SETPROCTITLE
#define EPCAP_TITLE_CAPTURE "capture"
#define EPCAP_TITLE_SUPERVISOR "supervisor"
#else
#define EPCAP_TITLE_CAPTURE "[epcap] capture"
#define EPCAP_TITLE_SUPERVISOR "[epcap] supervisor"
#endif

enum { EPCAP_TIME_UNIT_TIMESTAMP = 0, EPCAP_TIME_UNIT_MICROSECOND = 1 };

static int epcap_open(EPCAP_STATE *);
static int epcap_init(EPCAP_STATE *);
static void epcap_loop(EPCAP_STATE *);
static void epcap_ctrl(const char *);
void epcap_response(u_char *, const struct pcap_pkthdr *, const u_char *);
static void epcap_send_free(ei_x_buff *);
static int epcap_send(EPCAP_STATE *);
static ssize_t read_exact(int, void *, ssize_t);
static void usage(EPCAP_STATE *);

void signal_handler(int sig);
int signal_init(void);

extern char **environ;

#ifdef RESTRICT_PROCESS_capsicum
int pdfd;
#endif
pid_t pid;

int main(int argc, char *argv[]) {
  EPCAP_STATE *ep = NULL;
  int ch = 0;
  int fd = 0;

#ifndef HAVE_SETPROCTITLE
  spt_init(argc, argv);
#endif

  ep = calloc(1, sizeof(EPCAP_STATE));

  if (ep == NULL)
    exit(ENOMEM);

  ep->snaplen = SNAPLEN;
  ep->timeout = TIMEOUT;

  while ((ch = getopt(argc, argv, "b:d:e:f:g:hi:MPs:T:t:u:Q:vX")) != -1) {
    switch (ch) {
    case 'b':
      ep->bufsz = strtonum(optarg, INT32_MIN, INT32_MAX, NULL);
      if (errno)
        exit(errno);
      break;
    case 'd': /* chroot directory */
      ep->chroot = strdup(optarg);

      if (ep->chroot == NULL)
        exit(ENOMEM);

      break;
    case 'e': {
      char *name = NULL;
      char *value = NULL;

      name = strdup(optarg);

      if (name == NULL)
        exit(ENOMEM);

      value = strchr(name, '=');

      if (value == NULL)
        exit(EINVAL);

      *value = '\0';
      value++;

      if (setenv(name, value, 0) < 0)
        exit(errno);

      free(name);
    } break;
    case 'f':
      ep->file = strdup(optarg);

      if (ep->file == NULL)
        exit(ENOMEM);

      ep->opt |= EPCAP_OPT_RUNASUSER;
      break;
    case 'g':
      ep->group = strdup(optarg);

      if (ep->group == NULL)
        exit(ENOMEM);

      break;
    case 'i':
      ep->dev = strdup(optarg);

      if (ep->dev == NULL)
        exit(ENOMEM);

      break;
    case 'M':
      ep->opt |= EPCAP_OPT_RFMON;
      break;
    case 'P':
      ep->opt |= EPCAP_OPT_PROMISC;
      break;
    case 's':
      ep->snaplen = strtonum(optarg, INT32_MIN, INT32_MAX, NULL);
      if (errno)
        exit(errno);
      break;
    case 'T':
      ep->time_unit = strtonum(optarg, 0, 1, NULL);
      if (errno)
        exit(errno);
      break;
    case 't':
      ep->timeout = strtonum(optarg, INT32_MIN, INT32_MAX, NULL);
      if (errno)
        exit(errno);
      break;
    case 'u':
      ep->user = strdup(optarg);

      if (ep->user == NULL)
        exit(ENOMEM);

      break;
    case 'v':
      ep->verbose++;
      break;
    case 'X':
      ep->opt |= EPCAP_OPT_INJECT;
      break;
    case 'Q':
      if (strcmp(optarg, "in") == 0) {
        ep->direction = PCAP_D_IN;
      } else if (strcmp(optarg, "out") == 0) {
        ep->direction = PCAP_D_OUT;
      } else {
        ep->direction = PCAP_D_INOUT;
      }
      break;
    case 'h':
    default:
      usage(ep);
    }
  }

  argc -= optind;
  argv += optind;

  ep->filt = strdup((argc == 1) ? argv[0] : EPCAP_FILTER);

  if (ep->filt == NULL)
    exit(ENOMEM);

  if (ep->verbose > 0) {
    for (; *environ; environ++)
      VERBOSE(2, "env:%s\n", *environ);
  }

  fd = open("/dev/null", O_RDWR);

  if (fd < 0)
    exit(errno);

  if (epcap_priv_runasuser(ep) < 0)
    exit(errno);

  if (epcap_open(ep) < 0)
    exit(errno);

  if (epcap_priv_drop(ep) < 0)
    exit(errno);

  if (pipe(ep->fdctl) < 0)
    exit(errno);

#ifdef RESTRICT_PROCESS_capsicum
  pid = pdfork(&pdfd, 0);
#else
  pid = fork();
#endif
  switch (pid) {
  case -1:
    exit(errno);
  case 0:
    if (dup2(fd, STDIN_FILENO) < 0)
      exit(errno);

    if (close(fd) < 0)
      exit(errno);

    if (close(ep->fdctl[PIPE_READ]) < 0)
      exit(errno);

    setproctitle(EPCAP_TITLE_CAPTURE);

    if (epcap_init(ep) < 0)
      exit(errno);

    if (restrict_process_capture() < 0)
      exit(errno);

    epcap_ctrl("ready");
    epcap_loop(ep);
    break;
  default:
    if (signal_init() < 0)
      goto CLEANUP;

    if ((dup2(fd, STDOUT_FILENO) < 0) || (close(fd) < 0))
      goto CLEANUP;

    if (close(ep->fdctl[PIPE_WRITE]) < 0)
      exit(errno);

    if (!(ep->opt & EPCAP_OPT_INJECT))
      pcap_close(ep->p);

    setproctitle(EPCAP_TITLE_SUPERVISOR);

    if (restrict_process_supervisor() < 0)
      goto CLEANUP;

    (void)epcap_send(ep);

  CLEANUP:
#ifdef RESTRICT_PROCESS_capsicum
    (void)pdkill(pdfd, SIGTERM);
#else
    (void)kill(pid, SIGTERM);
#endif
    break;
  }

  exit(0);
}

static int epcap_send(EPCAP_STATE *ep) {
  const int fd = STDIN_FILENO;
  int maxfd = 0;
  ssize_t n = 0;
  unsigned char buf[SNAPLEN] = {0};
  u_int16_t len = 0;

  int rv = 0;

  for (;;) {
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    FD_SET(ep->fdctl[PIPE_READ], &rfds);
    maxfd = ep->fdctl[PIPE_READ] + 1;

    rv = select(maxfd, &rfds, NULL, NULL, NULL);

    switch (rv) {
    case 0:
      continue;

    case -1:
      if (errno == EINTR)
        continue;

      return -1;

    default:
      break;
    }

    if (FD_ISSET(ep->fdctl[PIPE_READ], &rfds))
      return 0;

    if (!FD_ISSET(fd, &rfds))
      continue;

    n = read_exact(fd, &len, sizeof(len));

    if (n != sizeof(len)) {
      VERBOSE(1, "epcap_send: header len != %lu: %ld",
              (unsigned long)sizeof(len), (long)n);
      return -1;
    }

    len = ntohs(len);

    VERBOSE(2, "epcap_send: packet len = %u", len);

    if (len >= sizeof(buf)) {
      errno = EINVAL;
      return -1;
    }

    n = read_exact(fd, buf, len);

    if (n != len) {
      VERBOSE(1, "epcap_send: len = %u, read = %ld", len, (long)n);
      errno = EINVAL;
      return -1;
    }

    if (ep->opt & EPCAP_OPT_INJECT) {
      n = pcap_inject(ep->p, buf, len);

      if (n < 0) {
        VERBOSE(0, "epcap_send: %s", pcap_geterr(ep->p));
        return -1;
      } else if (n != len) {
        VERBOSE(1, "epcap_send: len = %u, sent = %ld", len, (long)n);
      }
    } else {
      VERBOSE(2, "epcap_send: ignoring: len = %u", len);
    }
  }

  return 0;
}

static int epcap_open(EPCAP_STATE *ep) {
  if (ep->file) {
    ep->p = pcap_open_offline(ep->file, ep->errbuf);

    if (ep->p == NULL) {
      VERBOSE(0, "%s, failed call to pcap_open_offline %s\n", __progname,
              ep->errbuf);
      return -1;
    }
  } else {
    if (ep->dev == NULL) {
      pcap_if_t *alldevs;

      if (pcap_findalldevs(&alldevs, ep->errbuf) < 0 || alldevs == NULL) {
        VERBOSE(0, "%s, failed call to pcap_findalldevs %s\n", __progname,
                ep->errbuf);
        return -1;
      }

      ep->dev = strdup(alldevs->name);

      if (ep->dev == NULL)
        return -1;

      pcap_freealldevs(alldevs);
    }

#ifdef HAVE_PCAP_CREATE
    ep->p = pcap_create(ep->dev, ep->errbuf);

    if (ep->p == NULL) {
      VERBOSE(0, "%s, failed call to pcap_create %s\n", __progname, ep->errbuf);
      return -1;
    }

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
      (void)strncpy(ep->errbuf, pcap_geterr(ep->p), sizeof(ep->errbuf) - 1);
      return -1;
    default:
      return -1;
    }
#else
    ep->p = pcap_open_live(ep->dev, ep->snaplen, ep->opt & EPCAP_OPT_PROMISC,
                           ep->timeout, ep->errbuf);

    if (ep->p == NULL) {
      VERBOSE(0, "%s, failed call to pcap_open_live %s\n", __progname,
              ep->errbuf);
      return -1;
    }
#endif

    /* monitor mode */
#ifdef PCAP_ERROR_RFMON_NOTSUP
    if (pcap_can_set_rfmon(ep->p) == 1)
      (void)pcap_set_rfmon(ep->p, ep->opt & EPCAP_OPT_RFMON);
#endif
  }

  ep->datalink = pcap_datalink(ep->p);

  if (ep->file == 0 && pcap_setdirection(ep->p, ep->direction) != 0) {
    VERBOSE(1, "pcap_setdirection: %s (%d)", pcap_geterr(ep->p), ep->direction);
    return -1;
  }

  return 0;
}

static int epcap_init(EPCAP_STATE *ep) {
  struct bpf_program fcode = {0};
  char errbuf[PCAP_ERRBUF_SIZE] = {0};

  u_int32_t ipaddr = 0;
  u_int32_t ipmask = 0;

  if (pcap_lookupnet(ep->dev, &ipaddr, &ipmask, errbuf) == -1) {
    VERBOSE(1, "%s", errbuf);
    ipmask = PCAP_NETMASK_UNKNOWN;
  }

  VERBOSE(2, "[%s] Using filter: %s\n", __progname, ep->filt);

  if (pcap_compile(ep->p, &fcode, ep->filt, 1 /* optimize == true */, ipmask) !=
      0) {
    VERBOSE(1, "pcap_compile: %s", pcap_geterr(ep->p));
    return -1;
  }

  if (pcap_setfilter(ep->p, &fcode) != 0) {
    VERBOSE(1, "pcap_setfilter: %s", pcap_geterr(ep->p));
    return -1;
  }

  pcap_freecode(&fcode);

  return 0;
}

static void epcap_loop(EPCAP_STATE *ep) {
  int rv = -1;

  rv = pcap_loop(ep->p, -1, epcap_response, (u_char *)ep);

  switch (rv) {
  case -2:
    break;
  case -1: /* error reading packet */
    VERBOSE(1, "%s", pcap_geterr(ep->p));
    break;
  default:
    if (ep->file)
      epcap_ctrl("eof");
    break;
  }
}

static void epcap_ctrl(const char *ctrl_evt) {
  ei_x_buff msg;

  EPCAP_ENCODE_ERR(ei_x_new_with_version(&msg));
  EPCAP_ENCODE_ERR(ei_x_encode_tuple_header(&msg, 2));
  EPCAP_ENCODE_ERR(ei_x_encode_atom(&msg, "epcap"));
  EPCAP_ENCODE_ERR(ei_x_encode_atom(&msg, ctrl_evt));

  epcap_send_free(&msg);
}

void epcap_response(u_char *user, const struct pcap_pkthdr *hdr,
                    const u_char *pkt) {
  EPCAP_STATE *ep = (EPCAP_STATE *)user;
  ei_x_buff msg = {0};

  EPCAP_ENCODE_ERR(ei_x_new_with_version(&msg));

  /* {packet, DatalinkType, Time, ActualLength, Packet} */
  EPCAP_ENCODE_ERR(ei_x_encode_tuple_header(&msg, 5));
  EPCAP_ENCODE_ERR(ei_x_encode_atom(&msg, "packet"));

  /* DataLinkType */
  EPCAP_ENCODE_ERR(ei_x_encode_long(&msg, ep->datalink));

  switch (ep->time_unit) {
  case EPCAP_TIME_UNIT_MICROSECOND:
    /* microseconds */
    EPCAP_ENCODE_ERR(ei_x_encode_ulonglong(
        &msg, (unsigned long long)hdr->ts.tv_sec * 1000000 +
                  (unsigned long long)hdr->ts.tv_usec));
    break;

  case EPCAP_TIME_UNIT_TIMESTAMP:
  default:
    /* {MegaSec, Sec, MicroSec} */
    EPCAP_ENCODE_ERR(ei_x_encode_tuple_header(&msg, 3));
    EPCAP_ENCODE_ERR(ei_x_encode_long(&msg, hdr->ts.tv_sec / 1000000L));
    EPCAP_ENCODE_ERR(ei_x_encode_long(&msg, hdr->ts.tv_sec % 1000000));
    EPCAP_ENCODE_ERR(ei_x_encode_long(&msg, hdr->ts.tv_usec));
    break;
  }

  /* ActualLength} */
  EPCAP_ENCODE_ERR(ei_x_encode_long(&msg, hdr->len));

  /* Packet */
  EPCAP_ENCODE_ERR(ei_x_encode_binary(&msg, pkt, hdr->caplen));

  /* } */

  epcap_send_free(&msg);
}

static void epcap_send_free(ei_x_buff *msg) {
  u_int16_t len = 0;
  struct iovec iov[2];

  len = htons(msg->index);

  iov[0].iov_base = &len;
  iov[0].iov_len = sizeof(len);
  iov[1].iov_base = msg->buff;
  iov[1].iov_len = msg->index;

  if (writev(STDOUT_FILENO, iov, sizeof(iov) / sizeof(iov[0])) !=
      sizeof(len) + msg->index)
    exit(errno);

  ei_x_free(msg);
}

static ssize_t read_exact(int fd, void *buf, ssize_t len) {
  ssize_t i = 0;
  ssize_t got = 0;

  do {
    if ((i = read(fd, buf + got, len - got)) <= 0)
      return i;
    got += i;
  } while (got < len);

  return len;
}

void signal_handler(int sig) {
  if (pid > 0)
#ifdef RESTRICT_PROCESS_capsicum
    (void)pdkill(pdfd, sig);
#else
    (void)kill(pid, sig);
#endif
}

int signal_init(void) {
  struct sigaction act = {0};
  int sig;

  act.sa_handler = signal_handler;
  (void)sigfillset(&act.sa_mask);

  for (sig = 1; sig < NSIG; sig++) {
    if (sig == SIGCHLD)
      continue;

    if (sigaction(sig, &act, NULL) < 0) {
      if (errno == EINVAL)
        continue;

      return -1;
    }
  }

  return 0;
}

static void usage(EPCAP_STATE *ep) {
  (void)fprintf(stderr, "%s, %s (using %s process restriction)\n", __progname,
                EPCAP_VERSION, RESTRICT_PROCESS);
  (void)fprintf(
      stderr,
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
      "              -X               enable sending packets\n"
      "              -Q               capture direction\n",
      __progname);

  exit(EXIT_FAILURE);
}
