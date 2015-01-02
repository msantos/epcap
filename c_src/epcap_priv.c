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
#include <pwd.h>
#include <grp.h>

#include "epcap.h"

    int
epcap_priv_drop(EPCAP_STATE *ep)
{
    struct passwd *pw = NULL;
    struct group *gr = NULL;

    if (geteuid() != 0)
        return 1;

    if (!ep->user)
        ep->user = EPCAP_USER;

    if (!ep->chroot)
        ep->chroot = EPCAP_CHROOT;

    if ( (pw = getpwnam(ep->user)) == NULL) {
        warnx("user does not exist: %s", ep->user);
        return -1;
    }

    if (ep->group && (gr = getgrnam(ep->group)) == NULL) {
        warnx("group does not exist: %s", ep->group);
        return -1;
    }

    if (chroot(ep->chroot) < 0) {
        warn("%s", ep->chroot);
        return -1;
    }

    IS_LTZERO(chdir("/"));
    IS_LTZERO(setgid(ep->group ? gr->gr_gid : pw->pw_gid));
    IS_LTZERO(setuid(pw->pw_uid));

    return 0;
}


    void
epcap_priv_issetuid(EPCAP_STATE *ep)
{
    if ((ep->opt & EPCAP_OPT_RUNASUSER) && (geteuid() == 0)) {
        IS_LTZERO(setgid(getgid()));
        IS_LTZERO(setuid(getuid()));
    }
}

    int
epcap_priv_rlimits(int nfd)
{
    struct rlimit rl = {0};

#ifdef RLIMIT_FSIZE
    if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
        return -1;
#endif

#ifdef RLIMIT_NPROC
    if (setrlimit(RLIMIT_NPROC, &rl) != 0)
        return -1;
#endif

#ifdef RLIMIT_NOFILE
    rl.rlim_cur = nfd;
    rl.rlim_max = nfd;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        return -1;
#endif

    return 0;
}
