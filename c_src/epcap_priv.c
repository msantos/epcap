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
#include "epcap.h"
#include <grp.h>
#include <pwd.h>

int epcap_priv_drop(EPCAP_STATE *ep) {
  struct passwd *pw = NULL;
  struct group *gr = NULL;
  gid_t gid;

  if (geteuid() != 0)
    return 1;

  if (!ep->user)
    ep->user = EPCAP_USER;

  if (!ep->chroot)
    ep->chroot = EPCAP_CHROOT;

  if ((pw = getpwnam(ep->user)) == NULL)
    return -1;

  if (ep->group && (gr = getgrnam(ep->group)) == NULL)
    return -1;

  if (chroot(ep->chroot) < 0)
    return -1;

  if (chdir("/") < 0)
    return -1;

  if (setgroups(0, NULL) < 0)
    return -1;

  gid = ep->group ? gr->gr_gid : pw->pw_gid;

#if defined(__sunos__) || defined(__APPLE__)
  if (setgid(gid) < 0)
    return -1;

  if (setuid(pw->pw_uid) < 0)
    return -1;
#else
  if (setresgid(gid, gid, gid) < 0)
    return -1;

  if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0)
    return -1;
#endif

  return 0;
}

int epcap_priv_runasuser(EPCAP_STATE *ep) {
  uid_t uid;
  gid_t gid;

  uid = getuid();
  gid = getgid();

  if (!(ep->opt & EPCAP_OPT_RUNASUSER) || (geteuid() != 0))
    return 0;

  if (setgroups(0, NULL) < 0)
    return -1;

#if defined(__sunos__) || defined(__APPLE__)
  if (setgid(getgid()) < 0)
    return -1;

  if (setuid(getuid()) < 0)
    return -1;
#else
  if (setresgid(gid, gid, gid) < 0)
    return -1;

  if (setresuid(uid, uid, uid) < 0)
    return -1;
#endif

  return 0;
}
