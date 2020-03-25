/* Copyright (c) 2017-2020 Michael Santos <michael.santos@gmail.com>. All
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
#ifdef RESTRICT_PROCESS_capsicum

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

#include "epcap.h"
#include <pcap/pcap.h>

int restrict_process_capture() {
  struct rlimit rl = {0};
  cap_rights_t policy_read;
  cap_rights_t policy_null;
  cap_rights_t policy_write;

  int fd = -1;

  (void)cap_rights_init(&policy_read, CAP_READ, CAP_EVENT);
  (void)cap_rights_init(&policy_null);
  (void)cap_rights_init(&policy_write, CAP_WRITE);

  if (cap_rights_limit(STDIN_FILENO, &policy_null) < 0)
    return -1;

  if (cap_rights_limit(STDOUT_FILENO, &policy_write) < 0)
    return -1;

  if (cap_rights_limit(STDERR_FILENO, &policy_write) < 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    return -1;

  for (fd = STDERR_FILENO + 1; fd < rl.rlim_cur; fd++) {
    if (fcntl(fd, F_GETFD, 0) < 0)
      continue;

    if (cap_rights_limit(fd, &policy_read) < 0)
      return -1;
  }

  return cap_enter();
}

int restrict_process_supervisor() {
  struct rlimit rl = {0};
  cap_rights_t policy_read;
  cap_rights_t policy_write;
  cap_rights_t policy_null;

  int fd = -1;

  (void)cap_rights_init(&policy_read, CAP_READ, CAP_EVENT);
  (void)cap_rights_init(&policy_write, CAP_WRITE, CAP_EVENT);
  (void)cap_rights_init(&policy_null);

  if (cap_rights_limit(STDIN_FILENO, &policy_read) < 0)
    return -1;

  if (cap_rights_limit(STDOUT_FILENO, &policy_null) < 0)
    return -1;

  if (cap_rights_limit(STDERR_FILENO, &policy_write) < 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    return -1;

  for (fd = STDERR_FILENO + 1; fd < rl.rlim_cur; fd++) {
    if (fcntl(fd, F_GETFD, 0) < 0)
      continue;

    if (cap_rights_limit(fd, &policy_write) < 0)
      return -1;
  }

  return cap_enter();
}
#endif
