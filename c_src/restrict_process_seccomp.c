/* Copyright (c) 2018-2020 Michael Santos <michael.santos@gmail.com>. All
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
#ifdef RESTRICT_PROCESS_seccomp
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* macros from openssh-7.2/sandbox-seccomp-filter.c */

/* Linux seccomp_filter restrict_process */
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ifdef RESTRICT_PROCESS_SECCOMP_FILTER_DEBUG
#undef SECCOMP_FILTER_FAIL
#define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif /* RESTRICT_PROCESS_SECCOMP_FILTER_DEBUG */

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno)                                                   \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0, 1),                       \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (_errno))
#define SC_ALLOW(_nr)                                                          \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0, 1),                       \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val)                                   \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0,                           \
           4), /* load first syscall argument */                               \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS,                                       \
               offsetof(struct seccomp_data, args[(_arg_nr)])),                \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (_arg_val), 0, 1),                   \
      BPF_STMT(BPF_RET + BPF_K,                                                \
               SECCOMP_RET_ALLOW), /* reload syscall number; all rules expect  \
                                      it in accumulator */                     \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))

/*
 * http://outflux.net/teach-seccomp/
 * https://github.com/gebi/teach-seccomp
 *
 */
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#warning "seccomp: unsupported platform"
#define SECCOMP_AUDIT_ARCH 0
#endif

int restrict_process_capture() {
  struct sock_filter filter[] = {
      /* Ensure the syscall arch convention is as expected. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL),
      /* Load the syscall number for checking. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

  /* Syscalls to allow */

#ifdef __NR_brk
      SC_ALLOW(brk),
#endif
#ifdef __NR_recvfrom
      SC_ALLOW(recvfrom),
#endif
#ifdef __NR_recv
      SC_ALLOW(recv),
#endif
#ifdef __NR_recvmsg
      SC_ALLOW(recvmsg),
#endif

#ifdef __NR_writev
      SC_ALLOW(writev),
#endif

#ifdef __NR_fcntl
      SC_ALLOW(fcntl),
#endif
#ifdef __NR_fcntl64
      SC_ALLOW(fcntl64),
#endif

#ifdef __NR_setsockopt
      SC_ALLOW(setsockopt),
#endif

#ifdef __NR_poll
      SC_ALLOW(poll),
#endif

#ifdef __NR_restart_syscall
      SC_ALLOW(restart_syscall),
#endif

      /* Default deny */
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL)};

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    return -1;

  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int restrict_process_supervisor() {
  struct sock_filter filter[] = {
      /* Ensure the syscall arch convention is as expected. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL),
      /* Load the syscall number for checking. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

  /* Syscalls to allow */
#ifdef __NR_kill
      SC_ALLOW(kill),
#endif

#ifdef __NR_exit_group
      SC_ALLOW(exit_group),
#endif

#ifdef __NR_read
      SC_ALLOW(read),
#endif
#ifdef __NR_readv
      SC_ALLOW(readv),
#endif
#ifdef __NR_write
      SC_ALLOW(write),
#endif
#ifdef __NR_writev
      SC_ALLOW(writev),
#endif
#ifdef __NR_sendto
      SC_ALLOW(sendto),
#endif
#ifdef __NR__newselect
      SC_ALLOW(_newselect),
#endif
#ifdef __NR_select
      SC_ALLOW(select),
#endif

#ifdef __NR_poll
      SC_ALLOW(poll),
#endif

#ifdef __NR_restart_syscall
      SC_ALLOW(restart_syscall),
#endif

      /* Default deny */
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)};

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    return -1;

  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
#endif
