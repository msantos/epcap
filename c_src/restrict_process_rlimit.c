/* Copyright (c) 2017-2025 Michael Santos <michael.santos@gmail.com>. All
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
#ifdef RESTRICT_PROCESS_rlimit

#include "epcap.h"

static int fdlimit(int lowfd);

int restrict_process_capture(void) {
  struct rlimit rl = {0};
  int maxfd;

  if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  maxfd = fdlimit(STDERR_FILENO);

  rl.rlim_cur = maxfd;
  rl.rlim_max = maxfd;

  if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    return -1;

  return 0;
}

int restrict_process_supervisor(void) {
  struct rlimit rl = {0};

  if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    return -1;

  return 0;
}

/* A previous call to chroot(2) prevents using /dev/fd to find the
 * max opened fd by the process. Fallback to testing each fd: with a high
 * RLIMIT_NOFILE, this check will be slow.
 */
static int fdlimit(int lowfd) {
  struct rlimit rl = {0};
  int fd;

  if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    return -1;

  for (fd = rl.rlim_cur; fd > lowfd; fd--) {
    if (fcntl(fd, F_GETFD, 0) == -1)
      continue;

    return fd;
  }

  return lowfd;
}
#endif
