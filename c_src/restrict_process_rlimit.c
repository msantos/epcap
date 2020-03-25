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
#ifdef RESTRICT_PROCESS_rlimit

#include "epcap.h"

/* On some platforms (Linux), poll() (used by pcap)
 *  * will return EINVAL if RLIMIT_NOFILES < numfd */
#ifndef EPCAP_RLIMIT_NOFILES
#define EPCAP_RLIMIT_NOFILES 0
#warning "Using default value of EPCAP_RLIMIT_NOFILES=0"
#endif

int restrict_process_capture() {
  struct rlimit rl = {0};

  if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  rl.rlim_cur = EPCAP_RLIMIT_NOFILES;
  rl.rlim_max = EPCAP_RLIMIT_NOFILES;

  if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    return -1;

  return 0;
}

int restrict_process_supervisor() {
  struct rlimit rl = {0};

  if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NPROC, &rl) != 0)
    return -1;

  if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    return -1;

  return 0;
}
#endif
